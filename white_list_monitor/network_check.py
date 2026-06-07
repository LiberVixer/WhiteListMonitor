import platform
import re
import subprocess
from dataclasses import dataclass

import requests

from .settings_store import (
    AppSettings,
    DEFAULT_OPEN_INTERNET_CHECK_URLS,
    DEFAULT_WHITELIST_CHECK_URLS,
)
from .status import NetworkStatus


@dataclass
class CheckResult:
    status: NetworkStatus
    whitelist_http_ok: bool
    open_internet_http_ok: bool
    primary_http_ok: bool
    secondary_http_ok: bool
    router_ping_ok: bool
    details: str
    whitelist_ok_urls: tuple[str, ...] = ()
    open_internet_ok_urls: tuple[str, ...] = ()


def normalize_http_urls(urls: object, fallback: list[str]) -> tuple[str, ...]:
    if isinstance(urls, str):
        values = re.split(r"[\s,;]+", urls)
    elif isinstance(urls, (list, tuple, set)):
        values = [str(value) for value in urls]
    else:
        values = []

    normalized: list[str] = []

    for value in values:
        url = value.strip()

        if not url:
            continue

        if "://" not in url:
            url = "http://" + url

        normalized.append(url)

    if normalized:
        return tuple(dict.fromkeys(normalized))

    return tuple(fallback)


def http_check(url: str, timeout: int) -> bool:
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        return 200 <= response.status_code < 500
    except requests.RequestException:
        return False


def check_http_group(urls: tuple[str, ...], timeout: int) -> tuple[str, ...]:
    ok_urls = []

    for url in urls:
        if http_check(url, timeout):
            ok_urls.append(url)

    return tuple(ok_urls)


def format_urls(urls: tuple[str, ...]) -> str:
    if not urls:
        return "нет"

    return ", ".join(urls)


def ping_check(host: str, timeout_seconds: int = 2) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_seconds * 1000), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_seconds), host]

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return completed.returncode == 0
    except OSError:
        return False


def detect_network_status(settings: AppSettings) -> CheckResult:
    router_ok = ping_check(settings.router_ip)
    if not router_ok:
        return CheckResult(
            status=NetworkStatus.ROUTER_DOWN,
            whitelist_http_ok=False,
            open_internet_http_ok=False,
            primary_http_ok=False,
            secondary_http_ok=False,
            router_ping_ok=False,
            details=f"Роутер {settings.router_ip} не пингуется",
        )

    whitelist_urls = normalize_http_urls(
        getattr(settings, "whitelist_check_urls", None),
        DEFAULT_WHITELIST_CHECK_URLS,
    )
    open_internet_urls = normalize_http_urls(
        getattr(settings, "open_internet_check_urls", None),
        DEFAULT_OPEN_INTERNET_CHECK_URLS,
    )

    whitelist_ok_urls = check_http_group(
        whitelist_urls,
        settings.http_timeout_seconds,
    )
    open_internet_ok_urls = check_http_group(
        open_internet_urls,
        settings.http_timeout_seconds,
    )

    whitelist_ok = bool(whitelist_ok_urls)
    open_internet_ok = bool(open_internet_ok_urls)

    if open_internet_ok:
        status = NetworkStatus.FREE_INTERNET
        details = (
            "Открытый интернет: OK "
            f"{format_urls(open_internet_ok_urls)}; "
            "белые HTTP: "
            f"{'OK ' + format_urls(whitelist_ok_urls) if whitelist_ok else 'FAIL'}"
        )
    elif whitelist_ok:
        status = NetworkStatus.WHITELIST_MODE
        details = (
            "Белые списки: OK "
            f"{format_urls(whitelist_ok_urls)}; "
            "открытый интернет: FAIL "
            f"{format_urls(open_internet_urls)}"
        )
    elif not whitelist_ok and not open_internet_ok:
        status = NetworkStatus.NO_INTERNET
        details = f"HTTP-проверки не проходят; роутер {settings.router_ip} пингуется"
    else:
        status = NetworkStatus.UNKNOWN
        details = "Нестандартный режим HTTP-проверок"

    return CheckResult(
        status=status,
        whitelist_http_ok=whitelist_ok,
        open_internet_http_ok=open_internet_ok,
        primary_http_ok=whitelist_ok,
        secondary_http_ok=open_internet_ok,
        router_ping_ok=router_ok,
        details=details,
        whitelist_ok_urls=whitelist_ok_urls,
        open_internet_ok_urls=open_internet_ok_urls,
    )
