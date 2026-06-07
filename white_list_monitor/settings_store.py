import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


def get_app_dir() -> Path:
    custom_dir = os.environ.get("WLM_DATA_DIR")

    if custom_dir:
        path = Path(custom_dir).expanduser()
    else:
        path = Path.home() / ".config" / "white-list-monitor"

    path.mkdir(parents=True, exist_ok=True)
    return path


SETTINGS_PATH = get_app_dir() / "settings.json"

DEFAULT_WHITELIST_CHECK_URLS = [
    "http://vk.com",
    "http://ya.ru",
    "http://mail.ru",
]

DEFAULT_OPEN_INTERNET_CHECK_URLS = [
    "http://kwork.ru",
    "http://tmsmm.ru",
    "http://rsload.net",
]


@dataclass
class AppSettings:
    router_ip: str = "192.168.8.1"
    url_primary: str = "http://ya.ru"
    url_secondary: str = "http://tmsmm.ru"
    whitelist_check_urls: list[str] = field(
        default_factory=lambda: DEFAULT_WHITELIST_CHECK_URLS.copy()
    )
    open_internet_check_urls: list[str] = field(
        default_factory=lambda: DEFAULT_OPEN_INTERNET_CHECK_URLS.copy()
    )

    http_timeout_seconds: int = 5
    check_interval_minutes: int = 5

    scheduler_hour: str = "*"
    scheduler_minute: str = "15"

    start_minimized: bool = False
    minimize_to_tray: bool = True

    sni_whitelist_url: str = ""

    extended_rating_max_workers: int = 50
    extended_rating_top_limit: int = 5000
    extended_rating_timeout_seconds: int = 10
    extended_rating_retries: int = 3
    extended_rating_submit_delay_ms: int = 100
    extended_rating_retry_delay_ms: int = 1000


def load_settings() -> AppSettings:
    if not SETTINGS_PATH.exists():
        settings = AppSettings()
        save_settings(settings)
        return settings

    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return AppSettings()

    allowed = AppSettings.__dataclass_fields__.keys()
    filtered = {key: value for key, value in data.items() if key in allowed}

    return AppSettings(**filtered)


def save_settings(settings: AppSettings) -> None:
    SETTINGS_PATH.write_text(
        json.dumps(asdict(settings), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
# Для совместимости с database.py
DB_PATH = get_app_dir() / "wl.db"

def ensure_app_dir():
    return get_app_dir()
