import base64
import ipaddress
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import requests
from PyQt6.QtCore import QObject, pyqtSignal

from .database import Database
from .settings_store import get_app_dir
from .sni_domains import sync_sni_domain_pool_from_servers


BLOCKED_PORTS = {80, 8080, 8880}

SUPPORTED_PROTOCOLS = {
    "vmess",
    "vless",
    "trojan",
    "ss",
    "ssr",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "wireguard",
    "wg",
    "naive",
    "brook",
    "mieru",
    "juicity",
    "anytls",
    "socks",
    "socks5",
    "http",
    "https",
}

LOCAL_DOMAIN_SUFFIXES = (
    ".local",
    ".lan",
    ".localhost",
)

COMMENT_PREFIXES = (
    "#",
    "//",
    ";",
    "---",
)

JUNK_PREFIXES = (
    "profile-title",
    "profile-update-interval",
    "profile-web-page-url",
    "subscription-userinfo",
    "content-disposition",
    "content-type",
    "mixed-port:",
    "allow-lan:",
    "mode:",
    "log-level:",
    "external-controller:",
    "dns:",
    "proxies:",
    "proxy-groups:",
    "rules:",
)

BAD_WHITELIST_PROTOCOLS = {
    "http",
    "https",
    "socks",
    "socks5",
    "wireguard",
    "wg",
}

TLS_REQUIRED_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "naive",
}

TLS_LIKE_PROTOCOLS = {
    "vless",
    "vmess",
    "trojan",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "anytls",
    "naive",
}

UDP_WHITELIST_PROTOCOLS = {
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
}

LEGACY_WHITELIST_PROTOCOLS = {
    "vmess",
    "ss",
    "ssr",
    "brook",
    "mieru",
    "juicity",
}

WHITELIST_TLS_PORTS = {
    443,
    8443,
    2053,
    2083,
    2087,
    2096,
}

MASKING_TRANSPORTS = {
    "ws",
    "websocket",
    "grpc",
    "xhttp",
    "splithttp",
    "httpupgrade",
}

BROWSER_FINGERPRINTS = {
    "chrome",
    "firefox",
    "safari",
    "edge",
}

S_RATING_MIN = 1
S_RATING_MAX = 99

S_RAW_MIN = -61.0
S_RAW_MAX = 126.0

S_PROTOCOL_SCORE = {
    "vless": 16.0,
    "trojan": 14.0,
    "anytls": 13.0,
    "naive": 12.0,
    "hysteria2": 10.0,
    "hy2": 10.0,
    "tuic": 8.0,
    "hysteria": 7.0,
    "vmess": 4.0,
    "juicity": 3.0,
    "ss": 0.0,
    "ssr": -4.0,
    "brook": -4.0,
    "mieru": -4.0,
}

S_DEFAULT_PROTOCOL_SCORE = -6.0
S_REALITY_SCORE = 20.0
S_TLS_SCORE = 12.0
S_NO_TLS_SCORE = -14.0
S_RAW_REALITY_TRANSPORT_SCORE = 15.0
S_TCP_REALITY_TRANSPORT_SCORE = 14.0
S_XHTTP_TRANSPORT_SCORE = 12.0
S_GRPC_TRANSPORT_SCORE = 9.0
S_WS_TRANSPORT_SCORE = 8.0
S_PLAIN_TCP_TRANSPORT_SCORE = -8.0
S_UDP_TRANSPORT_SCORE = -10.0
S_UNKNOWN_TRANSPORT_SCORE = -2.0
S_PORT_443_SCORE = 12.0
S_TLS_PORT_SCORE = 8.0
S_NON_TLS_PORT_SCORE = -10.0
S_WHITELISTED_SNI_SCORE = 18.0
S_SNI_SCORE = 12.0
S_NO_SNI_SCORE = -12.0
S_VISION_REALITY_SCORE = 10.0
S_VISION_SCORE = 5.0
S_NO_REALITY_VISION_SCORE = -2.0
S_BROWSER_FP_SCORE = 8.0
S_UNKNOWN_FP_SCORE = -4.0
S_MISSING_REALITY_FP_SCORE = -8.0
S_REALITY_PUBLIC_KEY_SCORE = 4.0
S_REALITY_SHORT_ID_SCORE = 3.0
S_REALITY_SPX_SCORE = 3.0
S_REALITY_MISSING_FIELDS_SCORE = -5.0
S_VLESS_REALITY_RAW_VISION_PROFILE_SCORE = 10.0
S_VLESS_REALITY_VISION_PROFILE_SCORE = 8.0
S_TROJAN_TLS_443_PROFILE_SCORE = 6.0
S_MASKED_TLS_443_PROFILE_SCORE = 6.0
S_PATH_EXTRA_SCORE = 3.0
S_UDP_ACTIVE_TEST_SCORE = -5.0

READY_EXPORT_DIR_NAME = "Ready"
READY_EXPORT_FILE_COUNT = 10
READY_EXPORT_ROWS_PER_FILE = 999
READY_EXPORT_FILE_PREFIX = "FB-White"
READY_EXPORT_ALL_FILE_NAME = "FB-White-All.txt"


@dataclass
class ParsedServer:
    protocol: str
    host: str
    port: int
    raw_uri: str
    source_subscribe_id: int | None

    sni: str = ""
    sni_base_domain: str = ""
    security: str = ""
    transport: str = ""
    flow: str = ""
    alpn: str = ""
    fp: str = ""

    black: int = 0
    black_reason: str = ""
    rating: int = 0
    rating_reason: str = ""


class VPNWorker(QObject):
    log = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, db: Database):
        super().__init__()
        self.db = db

    def run(self) -> None:
        try:
            self.run_scan()
        except Exception as exc:
            self.log.emit(f"Ошибка VPN-скрипта: {exc}")
        finally:
            self.finished.emit()

    def run_scan(self) -> None:
        self.ensure_schema()

        whitelist_base_domains = self.load_whitelist_base_domains()
        self.log.emit(f"SNI whitelist base-доменов: {len(whitelist_base_domains)}")
        self.log.emit("S-рейтинг: одноразовая статическая модель whitelist РФ")

        subscribes = [s for s in self.db.list_subscribes() if s.enabled]

        if not subscribes:
            self.log.emit("Нет включенных подписок")
            return

        self.log.emit(f"Активных подписок: {len(subscribes)}")

        raw_candidates: list[tuple[str, int | None]] = []

        downloaded_count = 0
        failed_count = 0
        total_raw_lines = 0

        for index, sub in enumerate(subscribes, start=1):
            text = self.download_subscription(sub.url)

            if text is None:
                failed_count += 1
                self.log.emit(
                    f"[{index}/{len(subscribes)}] Скачивание: {sub.url} Ошибка"
                )
                continue

            downloaded_count += 1

            lines = self.extract_subscription_lines(text)
            total_raw_lines += len(lines)

            self.log.emit(
                f"[{index}/{len(subscribes)}] Скачивание: {sub.url} Строк: {len(lines)}"
            )

            for line in lines:
                raw_candidates.append((line, sub.id))

        self.log.emit(f"Подписок скачано: {downloaded_count}")
        self.log.emit(f"Ошибок скачивания: {failed_count}")
        self.log.emit(f"Всего строк до очистки: {total_raw_lines}")

        cleaned = self.clean_and_dedupe(raw_candidates)

        self.log.emit(f"После очистки и удаления дублей: {len(cleaned)}")

        parsed_servers: list[ParsedServer] = []
        parse_failed = 0

        for raw_uri, source_subscribe_id in cleaned:
            parsed = self.parse_server(raw_uri, source_subscribe_id)

            if parsed is None:
                parse_failed += 1
                continue

            self.classify_and_rate(parsed, whitelist_base_domains)
            parsed_servers.append(parsed)

        black_count = sum(1 for item in parsed_servers if item.black)
        good_count = len(parsed_servers) - black_count

        self.log.emit(f"Разобрано строк серверов: {len(parsed_servers)}")
        self.log.emit(f"Не удалось разобрать: {parse_failed}")
        self.log.emit(f"BAD по статике whitelist РФ: {black_count}")
        self.log.emit(f"CANDIDATE с S-рейтингом: {good_count}")

        added, existing = self.save_servers(parsed_servers)

        self.log.emit(f"Добавлено новых строк серверов: {added}")
        self.log.emit(f"Уже были в базе, S-рейтинг не менялся: {existing}")

        try:
            sni_pool_result = self.sync_sni_domain_pool()
            self.log.emit(
                "SNI база подписок: "
                f"доменов={sni_pool_result['total']}, "
                f"новых={sni_pool_result['inserted']}, "
                f"обновлено={sni_pool_result['updated']}, "
                f"дублей удалено={sni_pool_result['removed']}"
            )
        except Exception as exc:
            self.log.emit(f"Ошибка обновления SNI базы подписок: {exc}")

        try:
            export_result = self.export_ready_top_servers()
            self.log.emit(
                "Экспорт Ready: "
                f"файлов={export_result['files']}, "
                f"строк={export_result['rows']}, "
                f"все кандидаты={export_result['all_rows']}, "
                f"папка={export_result['export_dir']}"
            )
        except Exception as exc:
            self.log.emit(f"Ошибка экспорта Ready: {exc}")

        self.log.emit("VPN-скрипт завершен")

    # ------------------------------------------------------------------
    # DB schema
    # ------------------------------------------------------------------

    def ensure_schema(self) -> None:
        with self.db.connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    protocol TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,

                    raw_uri TEXT NOT NULL UNIQUE,

                    source_subscribe_id INTEGER,

                    found_count INTEGER NOT NULL DEFAULT 1,

                    active INTEGER NOT NULL DEFAULT 1,

                    sni TEXT,
                    sni_base_domain TEXT,
                    security TEXT,
                    transport TEXT,
                    flow TEXT,
                    alpn TEXT,
                    fp TEXT,

                    black INTEGER NOT NULL DEFAULT 0,
                    black_reason TEXT,
                    rating INTEGER NOT NULL DEFAULT 0,
                    rating_reason TEXT,
                    s_rating INTEGER NOT NULL DEFAULT 0,
                    s_rating_reason TEXT,
                    whitelist_full_success INTEGER NOT NULL DEFAULT 0,
                    whitelist_full_success_count INTEGER NOT NULL DEFAULT 0,
                    whitelist_full_success_at DATETIME,
                    whitelist_full_success_note TEXT,

                    added_at DATETIME NOT NULL,
                    updated_at DATETIME NOT NULL
                )
                """
            )

            self.ensure_column(con, "servers", "found_count", "INTEGER NOT NULL DEFAULT 1")
            self.ensure_column(con, "servers", "active", "INTEGER NOT NULL DEFAULT 1")

            self.ensure_column(con, "servers", "sni", "TEXT")
            self.ensure_column(con, "servers", "sni_base_domain", "TEXT")
            self.ensure_column(con, "servers", "security", "TEXT")
            self.ensure_column(con, "servers", "transport", "TEXT")
            self.ensure_column(con, "servers", "flow", "TEXT")
            self.ensure_column(con, "servers", "alpn", "TEXT")
            self.ensure_column(con, "servers", "fp", "TEXT")

            self.ensure_column(con, "servers", "black", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "servers", "black_reason", "TEXT")
            self.ensure_column(con, "servers", "rating", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "servers", "rating_reason", "TEXT")
            self.ensure_column(con, "servers", "s_rating", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "servers", "s_rating_reason", "TEXT")
            self.ensure_column(con, "servers", "whitelist_full_success", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "servers", "whitelist_full_success_count", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "servers", "whitelist_full_success_at", "DATETIME")
            self.ensure_column(con, "servers", "whitelist_full_success_note", "TEXT")
            self.ensure_column(con, "servers", "e_rating", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "servers", "e_success_count", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "servers", "e_fail_count", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "servers", "e_last_latency_ms", "INTEGER")
            self.ensure_column(con, "servers", "e_best_latency_ms", "INTEGER")
            self.ensure_column(con, "servers", "e_last_test_at", "DATETIME")
            self.ensure_column(con, "servers", "e_last_mode", "TEXT")
            self.ensure_column(con, "servers", "e_last_error", "TEXT")

            self.ensure_column(con, "servers", "added_at", "DATETIME")
            self.ensure_column(con, "servers", "updated_at", "DATETIME")

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_sni (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    comment TEXT
                )
                """
            )

            con.execute(
                """
                CREATE TABLE IF NOT EXISTS sni_domain_pool (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    found_count INTEGER NOT NULL DEFAULT 0,
                    first_seen_at DATETIME NOT NULL,
                    last_seen_at DATETIME NOT NULL,
                    comment TEXT
                )
                """
            )

            self.ensure_column(con, "sni_domain_pool", "found_count", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "sni_domain_pool", "first_seen_at", "DATETIME")
            self.ensure_column(con, "sni_domain_pool", "last_seen_at", "DATETIME")
            self.ensure_column(con, "sni_domain_pool", "comment", "TEXT")

    def ensure_column(
        self,
        con: sqlite3.Connection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        rows = con.execute(f"PRAGMA table_info({table})").fetchall()
        existing_columns = {row[1] for row in rows}

        if column not in existing_columns:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    # ------------------------------------------------------------------
    # Download and line extraction
    # ------------------------------------------------------------------

    def download_subscription(self, url: str) -> str | None:
        try:
            response = requests.get(
                url,
                timeout=25,
                headers={
                    "User-Agent": "WhiteListMonitor/0.1",
                    "Accept": "*/*",
                },
            )
            response.raise_for_status()
            return response.text.strip()
        except Exception as exc:
            self.log.emit(f"  {exc}")
            return None

    def extract_subscription_lines(self, text: str) -> list[str]:
        variants = [text]

        decoded = self.try_decode_base64_text(text)

        if decoded and decoded != text:
            variants.append(decoded)

        result: list[str] = []

        for variant in variants:
            variant = variant.replace("\r\n", "\n").replace("\r", "\n")

            if "\n" in variant:
                for line in variant.splitlines():
                    line = line.strip()
                    if line:
                        result.append(line)
            else:
                line = variant.strip()
                if line:
                    result.append(line)

        return result

    def try_decode_base64_text(self, text: str) -> str | None:
        compact = "".join(text.strip().split())

        if not compact:
            return None

        if len(compact) < 16:
            return None

        if "://" in compact:
            return None

        if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
            return None

        decoded_bytes = self.b64decode_any(compact)

        if not decoded_bytes:
            return None

        try:
            decoded = decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None

        if "://" not in decoded:
            return None

        return decoded.strip()

    def b64decode_any(self, value: str) -> bytes | None:
        value = value.strip()

        if not value:
            return None

        value = value.replace("-", "+").replace("_", "/")
        padding = "=" * (-len(value) % 4)
        value += padding

        try:
            return base64.b64decode(value, validate=False)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Cleaning
    # ------------------------------------------------------------------

    def clean_and_dedupe(
        self,
        rows: list[tuple[str, int | None]],
    ) -> list[tuple[str, int | None]]:
        result: list[tuple[str, int | None]] = []
        seen: set[str] = set()

        for raw_uri, source_subscribe_id in rows:
            raw_uri = raw_uri.strip()

            if not raw_uri:
                continue

            if self.is_junk_line(raw_uri):
                continue

            if raw_uri in seen:
                continue

            seen.add(raw_uri)
            result.append((raw_uri, source_subscribe_id))

        return result

    def is_junk_line(self, line: str) -> bool:
        lower = line.strip().lower()

        if not lower:
            return True

        if lower.startswith(COMMENT_PREFIXES):
            return True

        if lower.startswith(JUNK_PREFIXES):
            return True

        if lower in {"proxies", "proxy-groups", "rules"}:
            return True

        protocol = self.get_protocol(line)

        if not protocol:
            return True

        if protocol not in SUPPORTED_PROTOCOLS:
            return True

        return False

    def get_protocol(self, raw_uri: str) -> str | None:
        match = re.match(r"^([a-zA-Z0-9+.-]+)://", raw_uri.strip())

        if not match:
            return None

        return match.group(1).lower()

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_server(
        self,
        raw_uri: str,
        source_subscribe_id: int | None,
    ) -> ParsedServer | None:
        protocol = self.get_protocol(raw_uri)

        if not protocol:
            return None

        if protocol not in SUPPORTED_PROTOCOLS:
            return None

        if protocol == "vmess":
            parsed = self.parse_vmess(raw_uri, source_subscribe_id)
        elif protocol == "ss":
            parsed = self.parse_ss(raw_uri, source_subscribe_id)
        elif protocol == "ssr":
            parsed = self.parse_ssr(raw_uri, source_subscribe_id)
        else:
            parsed = self.parse_standard_url(raw_uri, source_subscribe_id)

        if not parsed:
            return None

        parsed.host = self.clean_host(parsed.host)
        parsed.sni = self.clean_host(parsed.sni)

        if parsed.sni:
            parsed.sni_base_domain = self.get_base_domain(parsed.sni)

        if not parsed.host:
            return None

        if parsed.port <= 0 or parsed.port > 65535:
            return None

        return parsed

    def parse_vmess(
        self,
        raw_uri: str,
        source_subscribe_id: int | None,
    ) -> ParsedServer | None:
        payload = raw_uri.split("://", 1)[1].strip()

        decoded_bytes = self.b64decode_any(payload)

        if decoded_bytes:
            try:
                data = json.loads(decoded_bytes.decode("utf-8", errors="replace"))

                host = str(data.get("add") or data.get("host") or "").strip()
                port = int(str(data.get("port") or "0").strip())

                if host and port:
                    security = str(data.get("tls") or data.get("security") or "").strip().lower()
                    if security in {"1", "true", "tls"}:
                        security = "tls"

                    transport = str(data.get("net") or data.get("type") or "").strip().lower()
                    sni = str(
                        data.get("sni")
                        or data.get("servername")
                        or data.get("serverName")
                        or data.get("host")
                        or ""
                    ).strip()

                    alpn = str(data.get("alpn") or "").strip().lower()
                    fp = str(data.get("fp") or "").strip().lower()

                    return ParsedServer(
                        protocol="vmess",
                        host=host,
                        port=port,
                        raw_uri=raw_uri,
                        source_subscribe_id=source_subscribe_id,
                        sni=sni,
                        security=security,
                        transport=transport,
                        alpn=alpn,
                        fp=fp,
                    )
            except Exception:
                pass

        return self.parse_standard_url(raw_uri, source_subscribe_id)

    def parse_ss(
        self,
        raw_uri: str,
        source_subscribe_id: int | None,
    ) -> ParsedServer | None:
        body = raw_uri.split("://", 1)[1]

        if "#" in body:
            body = body.split("#", 1)[0]

        if "?" in body:
            body = body.split("?", 1)[0]

        body = unquote(body)

        if "@" in body:
            server_part = body.rsplit("@", 1)[1]
            host, port = self.extract_host_port(server_part)

            if host and port:
                return ParsedServer(
                    protocol="ss",
                    host=host,
                    port=port,
                    raw_uri=raw_uri,
                    source_subscribe_id=source_subscribe_id,
                    security="",
                    transport="tcp",
                )

            left_part = body.split("@", 1)[0]
            decoded = self.b64decode_any(left_part)

            if decoded:
                reconstructed = decoded.decode("utf-8", errors="replace") + "@" + body.rsplit("@", 1)[1]
                server_part = reconstructed.rsplit("@", 1)[1]
                host, port = self.extract_host_port(server_part)

                if host and port:
                    return ParsedServer(
                        protocol="ss",
                        host=host,
                        port=port,
                        raw_uri=raw_uri,
                        source_subscribe_id=source_subscribe_id,
                        security="",
                        transport="tcp",
                    )

        decoded = self.b64decode_any(body)

        if decoded:
            decoded_text = decoded.decode("utf-8", errors="replace")
            if "@" in decoded_text:
                server_part = decoded_text.rsplit("@", 1)[1]
            else:
                server_part = decoded_text

            host, port = self.extract_host_port(server_part)

            if host and port:
                return ParsedServer(
                    protocol="ss",
                    host=host,
                    port=port,
                    raw_uri=raw_uri,
                    source_subscribe_id=source_subscribe_id,
                    security="",
                    transport="tcp",
                )

        return self.parse_standard_url(raw_uri, source_subscribe_id)

    def parse_ssr(
        self,
        raw_uri: str,
        source_subscribe_id: int | None,
    ) -> ParsedServer | None:
        payload = raw_uri.split("://", 1)[1].strip()

        decoded = self.b64decode_any(payload)

        if not decoded:
            return None

        decoded_text = decoded.decode("utf-8", errors="replace")
        main_part = decoded_text.split("/?", 1)[0]
        parts = main_part.split(":")

        if len(parts) < 2:
            return None

        host = parts[0].strip()

        try:
            port = int(parts[1])
        except Exception:
            return None

        return ParsedServer(
            protocol="ssr",
            host=host,
            port=port,
            raw_uri=raw_uri,
            source_subscribe_id=source_subscribe_id,
            security="",
            transport="tcp",
        )

    def parse_standard_url(
        self,
        raw_uri: str,
        source_subscribe_id: int | None,
    ) -> ParsedServer | None:
        protocol = self.get_protocol(raw_uri)

        if not protocol:
            return None

        try:
            split = urlsplit(raw_uri)
            host = split.hostname
            port = split.port

            query = parse_qs(split.query, keep_blank_values=True)

            security = self.first_query_value(
                query,
                ["security", "tls", "allowinsecure"],
            ).lower()

            if security in {"1", "true"}:
                security = "tls"

            transport = self.first_query_value(
                query,
                ["type", "transport", "net"],
            ).lower()

            if not transport:
                transport = self.infer_transport(protocol, query)

            sni = self.first_query_value(
                query,
                [
                    "sni",
                    "servername",
                    "serverName",
                    "peer",
                    "host",
                    "authority",
                ],
            )

            flow = self.first_query_value(query, ["flow"]).lower()
            alpn = self.first_query_value(query, ["alpn"]).lower()
            fp = self.first_query_value(query, ["fp", "fingerprint"]).lower()

            if protocol in {"hysteria", "hysteria2", "hy2", "tuic", "anytls"}:
                if not security:
                    security = "tls"

            if host and port:
                return ParsedServer(
                    protocol=protocol,
                    host=host,
                    port=port,
                    raw_uri=raw_uri,
                    source_subscribe_id=source_subscribe_id,
                    sni=sni,
                    security=security,
                    transport=transport,
                    flow=flow,
                    alpn=alpn,
                    fp=fp,
                )
        except Exception:
            pass

        body = raw_uri.split("://", 1)[1]
        body = body.split("#", 1)[0]
        body = body.split("?", 1)[0]

        if "@" in body:
            body = body.rsplit("@", 1)[1]

        host, port = self.extract_host_port(body)

        if not host or not port:
            return None

        return ParsedServer(
            protocol=protocol,
            host=host,
            port=port,
            raw_uri=raw_uri,
            source_subscribe_id=source_subscribe_id,
            security="",
            transport="",
        )

    def first_query_value(self, query: dict[str, list[str]], names: list[str]) -> str:
        lower_map = {key.lower(): value for key, value in query.items()}

        for name in names:
            values = lower_map.get(name.lower())

            if not values:
                continue

            if values[0] is None:
                continue

            return unquote(str(values[0])).strip()

        return ""

    def infer_transport(self, protocol: str, query: dict[str, list[str]]) -> str:
        keys = {key.lower() for key in query.keys()}

        if "path" in keys:
            return "ws"

        if "serviceName".lower() in keys or "service_name" in keys:
            return "grpc"

        if protocol in {"hysteria", "hysteria2", "hy2", "tuic"}:
            return "udp"

        return ""

    def extract_host_port(self, text: str) -> tuple[str | None, int | None]:
        text = text.strip()

        if not text:
            return None, None

        if text.startswith("[") and "]:" in text:
            host = text[1:].split("]:", 1)[0]
            port_text = text.split("]:", 1)[1]
        elif ":" in text:
            host, port_text = text.rsplit(":", 1)
        else:
            return None, None

        host = host.strip()
        port_text = port_text.strip()

        try:
            port = int(port_text)
        except Exception:
            return None, None

        return host, port

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def clean_host(self, host: str) -> str:
        host = host or ""
        host = host.strip().strip("[]")
        host = host.strip().strip(".")
        return host.lower()

    def get_primary_bad_reason(self, host: str, port: int) -> str:
        if port in BLOCKED_PORTS:
            return f"Порт {port} не подходит для whitelist-кандидата"

        if self.is_local_domain(host):
            return "Локальный домен"

        if self.is_private_or_local_ip(host):
            return "Private/local/reserved IP"

        return ""

    def is_local_domain(self, host: str) -> bool:
        lower = host.lower().strip(".")

        if lower == "localhost":
            return True

        return lower.endswith(LOCAL_DOMAIN_SUFFIXES)

    def is_private_or_local_ip(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except Exception:
            return False

        if ip.is_private:
            return True

        if ip.is_loopback:
            return True

        if ip.is_link_local:
            return True

        if ip.is_multicast:
            return True

        if ip.is_reserved:
            return True

        if ip.is_unspecified:
            return True

        return False

    def is_ip_address(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # SNI whitelist and rating
    # ------------------------------------------------------------------

    def load_whitelist_base_domains(self) -> set[str]:
        result: set[str] = set()

        with self.db.connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_sni (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    comment TEXT
                )
                """
            )

            rows = con.execute(
                """
                SELECT domain
                FROM whitelist_sni
                WHERE enabled = 1
                """
            ).fetchall()

        for row in rows:
            domain = str(row[0] or "").strip().lower()
            base = self.get_base_domain(domain)

            if base:
                result.add(base)

        return result

    def get_base_domain(self, domain: str) -> str:
        domain = self.clean_host(domain)

        if not domain:
            return ""

        if self.is_ip_address(domain):
            return domain

        parts = [part for part in domain.split(".") if part]

        if len(parts) < 2:
            return domain

        return ".".join(parts[-2:])

    def classify_and_rate(
        self,
        server: ParsedServer,
        whitelist_base_domains: set[str],
    ) -> None:
        self.prepare_static_fields(server)

        bad_reason = self.get_bad_reason(server, whitelist_base_domains)

        if bad_reason:
            server.black = 1
            server.black_reason = bad_reason
            server.rating = 0
            server.rating_reason = "BAD: " + bad_reason
            return

        server.black = 0
        server.black_reason = ""

        rating, reasons = self.calculate_s_rating(server, whitelist_base_domains)
        server.rating = max(S_RATING_MIN, min(S_RATING_MAX, rating))
        server.rating_reason = "CANDIDATE: " + "; ".join(reasons)

    def prepare_static_fields(self, server: ParsedServer) -> None:
        if server.protocol in TLS_LIKE_PROTOCOLS:
            if not server.sni and server.host and not self.is_ip_address(server.host):
                server.sni = server.host

        if server.sni:
            server.sni_base_domain = self.get_base_domain(server.sni)

    def get_bad_reason(
        self,
        server: ParsedServer,
        whitelist_base_domains: set[str],
    ) -> str:
        primary_reason = self.get_primary_bad_reason(server.host, server.port)

        if primary_reason:
            return primary_reason

        protocol = server.protocol.lower()

        if protocol in BAD_WHITELIST_PROTOCOLS:
            return "Протокол не подходит для whitelist-режима"

        if protocol in TLS_REQUIRED_PROTOCOLS and not self.is_tls_or_reality(server):
            return "Нет TLS/Reality"

        if protocol in TLS_LIKE_PROTOCOLS:
            if not server.sni and self.is_ip_address(server.host):
                return "Нет SNI и host является IP"

        return ""

    def is_tls_or_reality(self, server: ParsedServer) -> bool:
        security = (server.security or "").lower()
        protocol = server.protocol.lower()

        if security in {"tls", "reality"}:
            return True

        if protocol in {"trojan", "naive", "anytls"}:
            return True

        if protocol in {"hysteria", "hysteria2", "hy2", "tuic"}:
            return True

        if "reality" in server.raw_uri.lower():
            return True

        return False

    def calculate_s_rating(
        self,
        server: ParsedServer,
        whitelist_base_domains: set[str],
    ) -> tuple[int, list[str]]:
        raw_score = 0.0
        reasons: list[str] = ["model=normalized_v2"]

        def add(label: str, value: float) -> None:
            nonlocal raw_score
            raw_score += value
            reasons.append(f"{label}{value:+g}")

        protocol = server.protocol.lower()
        security = (server.security or "").lower()
        transport = (server.transport or "").lower()
        flow = (server.flow or "").lower()
        fp = (server.fp or "").lower()
        is_reality = self.is_reality(server)

        protocol_score = S_PROTOCOL_SCORE.get(protocol, S_DEFAULT_PROTOCOL_SCORE)
        add(f"protocol={protocol}", protocol_score)

        if is_reality:
            add("security=reality", S_REALITY_SCORE)
        elif security == "tls" or self.is_tls_or_reality(server):
            add("security=tls_like", S_TLS_SCORE)
        else:
            add("security=no_tls", S_NO_TLS_SCORE)

        if transport == "raw":
            if is_reality:
                add("transport=raw_reality", S_RAW_REALITY_TRANSPORT_SCORE)
            else:
                add("transport=raw", S_UNKNOWN_TRANSPORT_SCORE)
        elif transport in {"xhttp", "splithttp"}:
            add(f"transport={transport}", S_XHTTP_TRANSPORT_SCORE)
        elif transport == "grpc":
            add("transport=grpc", S_GRPC_TRANSPORT_SCORE)
        elif transport in {"ws", "websocket", "httpupgrade"}:
            add(f"transport={transport}", S_WS_TRANSPORT_SCORE)
        elif transport == "tcp":
            if is_reality:
                add("transport=tcp_reality", S_TCP_REALITY_TRANSPORT_SCORE)
            else:
                add("transport=plain_tcp", S_PLAIN_TCP_TRANSPORT_SCORE)
        elif transport == "udp":
            add("transport=udp_uncertain", S_UDP_TRANSPORT_SCORE)
        else:
            add("transport=unknown", S_UNKNOWN_TRANSPORT_SCORE)

        if server.port == 443:
            add("port=443", S_PORT_443_SCORE)
        elif server.port in WHITELIST_TLS_PORTS:
            add(f"port=tls_{server.port}", S_TLS_PORT_SCORE)
        else:
            add(f"port=non_tls_{server.port}", S_NON_TLS_PORT_SCORE)

        if server.sni_base_domain:
            if server.sni_base_domain in whitelist_base_domains:
                add(
                    f"sni_whitelisted={server.sni_base_domain}",
                    S_WHITELISTED_SNI_SCORE,
                )
            else:
                add(f"sni={server.sni_base_domain}", S_SNI_SCORE)
        else:
            if protocol in TLS_LIKE_PROTOCOLS:
                add("sni=missing", S_NO_SNI_SCORE)

        if "vision" in flow:
            if is_reality:
                add("flow=vision_reality", S_VISION_REALITY_SCORE)
            else:
                add("flow=vision", S_VISION_SCORE)
        elif is_reality:
            add("flow=no_reality_vision", S_NO_REALITY_VISION_SCORE)

        if fp in BROWSER_FINGERPRINTS:
            add(f"browser_fp={fp}", S_BROWSER_FP_SCORE)
        elif is_reality:
            add("browser_fp=missing_for_reality", S_MISSING_REALITY_FP_SCORE)
        else:
            add("browser_fp=unknown", S_UNKNOWN_FP_SCORE)

        if server.alpn:
            add(f"alpn={server.alpn}", S_PATH_EXTRA_SCORE)

        has_reality_key = False
        if is_reality and self.raw_has_query_name(server.raw_uri, "pbk"):
            has_reality_key = True
            add("reality_public_key", S_REALITY_PUBLIC_KEY_SCORE)

        has_reality_sid = self.raw_has_query_name(
            server.raw_uri,
            "sid",
        ) or self.raw_has_query_name(
            server.raw_uri,
            "shortid",
        )
        if is_reality and has_reality_sid:
            add("reality_short_id", S_REALITY_SHORT_ID_SCORE)

        if is_reality and self.raw_has_query_name(server.raw_uri, "spx"):
            add("reality_spx", S_REALITY_SPX_SCORE)

        if is_reality and not has_reality_key and not has_reality_sid:
            add("reality_missing_key_sid", S_REALITY_MISSING_FIELDS_SCORE)

        if (
            protocol == "vless"
            and is_reality
            and "vision" in flow
            and fp in BROWSER_FINGERPRINTS
            and server.port == 443
            and server.sni_base_domain
        ):
            if transport in {"raw", "tcp"}:
                add(
                    f"profile=vless_reality_{transport}_vision",
                    S_VLESS_REALITY_RAW_VISION_PROFILE_SCORE,
                )
            else:
                add(
                    "profile=vless_reality_vision",
                    S_VLESS_REALITY_VISION_PROFILE_SCORE,
                )

        if (
            protocol == "trojan"
            and not is_reality
            and server.sni_base_domain
            and server.port == 443
        ):
            add("profile=trojan_tls_443", S_TROJAN_TLS_443_PROFILE_SCORE)

        if transport in MASKING_TRANSPORTS and server.sni_base_domain and server.port == 443:
            add("profile=masked_tls_443", S_MASKED_TLS_443_PROFILE_SCORE)

        if self.raw_has_query_name(server.raw_uri, "path") or self.raw_has_query_name(
            server.raw_uri,
            "extra",
        ):
            add("http_path_or_extra", S_PATH_EXTRA_SCORE)

        if protocol in UDP_WHITELIST_PROTOCOLS:
            add("udp_needs_active_test", S_UDP_ACTIVE_TEST_SCORE)

        rating = self.normalize_s_rating(raw_score)
        reasons.append(f"raw_score={raw_score:g}")
        reasons.append(f"normalized={rating}")

        return rating, reasons

    def normalize_s_rating(self, raw_score: float) -> int:
        if raw_score <= S_RAW_MIN:
            return S_RATING_MIN

        if raw_score >= S_RAW_MAX:
            return S_RATING_MAX

        ratio = (raw_score - S_RAW_MIN) / (S_RAW_MAX - S_RAW_MIN)
        rating = round(S_RATING_MIN + ratio * (S_RATING_MAX - S_RATING_MIN))

        return max(S_RATING_MIN, min(S_RATING_MAX, rating))

    def is_reality(self, server: ParsedServer) -> bool:
        return (server.security or "").lower() == "reality" or "reality" in server.raw_uri.lower()

    def raw_has_query_name(self, raw_uri: str, name: str) -> bool:
        name = name.lower()

        try:
            query = parse_qs(urlsplit(raw_uri).query, keep_blank_values=True)
        except Exception:
            return f"{name}=" in raw_uri.lower()

        return any(key.lower() == name for key in query.keys())

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def sync_sni_domain_pool(self) -> dict[str, int]:
        self.ensure_schema()
        return sync_sni_domain_pool_from_servers(self.db)

    def save_servers(self, servers: list[ParsedServer]) -> tuple[int, int]:
        added = 0
        updated = 0

        now = datetime.now().isoformat(timespec="seconds")

        with self.db.connect() as con:
            for server in servers:
                row = con.execute(
                    "SELECT id FROM servers WHERE raw_uri = ?",
                    (server.raw_uri,),
                ).fetchone()

                if row:
                    con.execute(
                        """
                        UPDATE servers
                        SET
                            protocol = ?,
                            host = ?,
                            port = ?,
                            source_subscribe_id = ?,
                            sni = ?,
                            sni_base_domain = ?,
                            security = ?,
                            transport = ?,
                            flow = ?,
                            alpn = ?,
                            fp = ?,
                            active = 1,
                            found_count = found_count + 1,
                            updated_at = ?
                        WHERE raw_uri = ?
                        """,
                        (
                            server.protocol,
                            server.host,
                            server.port,
                            server.source_subscribe_id,
                            server.sni,
                            server.sni_base_domain,
                            server.security,
                            server.transport,
                            server.flow,
                            server.alpn,
                            server.fp,
                            now,
                            server.raw_uri,
                        ),
                    )
                    updated += 1
                else:
                    con.execute(
                        """
                        INSERT INTO servers (
                            protocol,
                            host,
                            port,
                            raw_uri,
                            source_subscribe_id,
                            found_count,
                            active,
                            sni,
                            sni_base_domain,
                            security,
                            transport,
                            flow,
                            alpn,
                            fp,
                            black,
                            black_reason,
                            rating,
                            rating_reason,
                            s_rating,
                            s_rating_reason,
                            added_at,
                            updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            server.protocol,
                            server.host,
                            server.port,
                            server.raw_uri,
                            server.source_subscribe_id,
                            server.sni,
                            server.sni_base_domain,
                            server.security,
                            server.transport,
                            server.flow,
                            server.alpn,
                            server.fp,
                            server.black,
                            server.black_reason,
                            server.rating,
                            server.rating_reason,
                            server.rating,
                            server.rating_reason,
                            now,
                            now,
                        ),
                    )
                    added += 1

        return added, updated

    def mark_whitelist_full_success(
        self,
        raw_uri: str,
        note: str = "",
    ) -> bool:
        self.ensure_schema()

        now = datetime.now().isoformat(timespec="seconds")

        with self.db.connect() as con:
            cursor = con.execute(
                """
                UPDATE servers
                SET
                    whitelist_full_success = 1,
                    whitelist_full_success_count = COALESCE(whitelist_full_success_count, 0) + 1,
                    whitelist_full_success_at = ?,
                    whitelist_full_success_note = ?,
                    updated_at = ?
                WHERE raw_uri = ?
                """,
                (
                    now,
                    note[:500],
                    now,
                    raw_uri,
                ),
            )

        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Ready export
    # ------------------------------------------------------------------

    def export_ready_top_servers(
        self,
        export_dir: Path | None = None,
        file_count: int = READY_EXPORT_FILE_COUNT,
        rows_per_file: int = READY_EXPORT_ROWS_PER_FILE,
    ) -> dict[str, int | str]:
        self.ensure_schema()

        file_count = max(1, int(file_count))
        rows_per_file = max(1, int(rows_per_file))
        limit = file_count * rows_per_file

        target_dir = export_dir or (get_app_dir() / READY_EXPORT_DIR_NAME)
        target_dir.mkdir(parents=True, exist_ok=True)

        all_rows = self.fetch_ready_export_rows()
        top_rows = all_rows[:limit]

        all_path = target_dir / READY_EXPORT_ALL_FILE_NAME
        self.write_ready_export_file(all_path, all_rows)

        for file_index in range(file_count):
            start = file_index * rows_per_file
            end = start + rows_per_file
            chunk = top_rows[start:end]

            path = target_dir / f"{READY_EXPORT_FILE_PREFIX}-{file_index + 1:02d}.txt"
            self.write_ready_export_file(path, chunk)

        return {
            "files": file_count,
            "rows": len(top_rows),
            "all_rows": len(all_rows),
            "export_dir": str(target_dir),
        }

    def fetch_ready_export_rows(self, limit: int | None = None) -> list[dict[str, object]]:
        limit_clause = ""
        params: tuple[int, ...] = ()

        if limit is not None:
            limit_clause = "LIMIT ?"
            params = (max(0, int(limit)),)

        with self.db.connect() as con:
            rows = con.execute(
                f"""
                SELECT
                    raw_uri,
                    COALESCE(NULLIF(s_rating, 0), rating, 0) AS static_rating,
                    COALESCE(e_rating, 0) AS extended_rating,
                    e_last_latency_ms
                FROM servers
                WHERE COALESCE(black, 0) = 0
                  AND COALESCE(active, 1) = 1
                ORDER BY static_rating DESC, extended_rating DESC, found_count DESC, id ASC
                {limit_clause}
                """,
                params,
            ).fetchall()

        result: list[dict[str, object]] = []

        for row in rows:
            result.append(
                {
                    "raw_uri": str(row[0] or ""),
                    "s_rating": self.safe_export_int(row[1]),
                    "e_rating": self.safe_export_int(row[2]),
                    "e_last_latency_ms": row[3],
                }
            )

        return result

    def write_ready_export_file(self, path: Path, rows: list[dict[str, object]]) -> None:
        lines = []

        for row in rows:
            display_name = self.format_ready_export_name(
                row["s_rating"],
                row["e_rating"],
                row["e_last_latency_ms"],
            )
            lines.append(
                self.replace_server_name_for_export(str(row["raw_uri"]), display_name)
            )

        text = "\n".join(lines)
        if text:
            text += "\n"

        path.write_text(text, encoding="utf-8")

    def format_ready_export_name(
        self,
        s_rating: object,
        e_rating: object,
        latency_ms: object,
    ) -> str:
        s_value = self.safe_export_int(s_rating)
        e_value = self.safe_export_int(e_rating)
        latency_value = self.format_export_latency(latency_ms)

        return f"FB-s{s_value:02d}e{e_value:02d}-[{latency_value}ms]"

    def safe_export_int(self, value: object, default: int = 0) -> int:
        try:
            number = int(value)
        except Exception:
            return default

        return max(0, number)

    def format_export_latency(self, value: object) -> str:
        if value is None:
            return "???"

        try:
            number = int(value)
        except Exception:
            return "???"

        if number < 0:
            return "???"

        return str(number)

    def replace_server_name_for_export(self, raw_uri: str, display_name: str) -> str:
        protocol = self.get_protocol(raw_uri)

        if protocol == "vmess":
            replaced = self.replace_vmess_name_for_export(raw_uri, display_name)
            if replaced:
                return replaced

        if protocol == "ssr":
            replaced = self.replace_ssr_name_for_export(raw_uri, display_name)
            if replaced:
                return replaced

        return self.replace_url_fragment_for_export(raw_uri, display_name)

    def replace_url_fragment_for_export(self, raw_uri: str, display_name: str) -> str:
        body = raw_uri.split("#", 1)[0]
        return f"{body}#{display_name}"

    def replace_vmess_name_for_export(
        self,
        raw_uri: str,
        display_name: str,
    ) -> str | None:
        try:
            payload = raw_uri.split("://", 1)[1].split("#", 1)[0].strip()
        except Exception:
            return None

        decoded = self.b64decode_any(payload)
        if not decoded:
            return None

        try:
            data = json.loads(decoded.decode("utf-8", errors="replace"))
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        data["ps"] = display_name
        encoded = self.b64encode_text(
            json.dumps(data, ensure_ascii=False, separators=(",", ":")),
        )

        return f"vmess://{encoded}"

    def replace_ssr_name_for_export(
        self,
        raw_uri: str,
        display_name: str,
    ) -> str | None:
        try:
            payload = raw_uri.split("://", 1)[1].split("#", 1)[0].strip()
        except Exception:
            return None

        decoded = self.b64decode_any(payload)
        if not decoded:
            return None

        decoded_text = decoded.decode("utf-8", errors="replace")

        if "/?" in decoded_text:
            main_part, query_text = decoded_text.split("/?", 1)
        else:
            main_part = decoded_text
            query_text = ""

        encoded_name = self.b64encode_text(display_name, urlsafe=True)
        query_parts = [part for part in query_text.split("&") if part]
        replaced = False

        for index, part in enumerate(query_parts):
            key = part.split("=", 1)[0].lower()
            if key == "remarks":
                query_parts[index] = f"remarks={encoded_name}"
                replaced = True
                break

        if not replaced:
            query_parts.append(f"remarks={encoded_name}")

        new_text = f"{main_part}/?{'&'.join(query_parts)}"
        encoded = self.b64encode_text(new_text, urlsafe=True)

        return f"ssr://{encoded}"

    def b64encode_text(self, value: str, urlsafe: bool = False) -> str:
        raw = value.encode("utf-8")

        if urlsafe:
            encoded = base64.urlsafe_b64encode(raw)
        else:
            encoded = base64.b64encode(raw)

        return encoded.decode("ascii").rstrip("=")

    def recalculate_static_ratings_in_db(self) -> dict[str, int]:
        self.ensure_schema()

        whitelist_base_domains = self.load_whitelist_base_domains()
        now = datetime.now().isoformat(timespec="seconds")

        with self.db.connect() as con:
            rows = con.execute(
                """
                SELECT id, raw_uri, source_subscribe_id
                FROM servers
                ORDER BY id
                """
            ).fetchall()

            total = len(rows)
            bad = 0
            candidate = 0
            parse_failed = 0
            low_rating = 0
            medium_rating = 0
            high_rating = 0
            top_rating = 0

            for row in rows:
                server_id = int(row[0])
                raw_uri = str(row[1] or "")
                source_subscribe_id = row[2]

                parsed = self.parse_server(raw_uri, source_subscribe_id)

                if parsed is None:
                    parse_failed += 1
                    bad += 1
                    bad_reason = "Не удалось разобрать raw_uri"

                    con.execute(
                        """
                        UPDATE servers
                        SET
                            black = 1,
                            black_reason = ?,
                            rating = 0,
                            rating_reason = ?,
                            s_rating = 0,
                            s_rating_reason = ?,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            bad_reason,
                            "BAD: " + bad_reason,
                            "BAD: " + bad_reason,
                            now,
                            server_id,
                        ),
                    )
                    continue

                self.classify_and_rate(parsed, whitelist_base_domains)

                if parsed.black:
                    bad += 1
                else:
                    candidate += 1

                    if parsed.rating <= 30:
                        low_rating += 1
                    elif parsed.rating <= 60:
                        medium_rating += 1
                    elif parsed.rating <= 80:
                        high_rating += 1
                    else:
                        top_rating += 1

                con.execute(
                    """
                    UPDATE servers
                    SET
                        protocol = ?,
                        host = ?,
                        port = ?,
                        source_subscribe_id = ?,
                        sni = ?,
                        sni_base_domain = ?,
                        security = ?,
                        transport = ?,
                        flow = ?,
                        alpn = ?,
                        fp = ?,
                        black = ?,
                        black_reason = ?,
                        rating = ?,
                        rating_reason = ?,
                        s_rating = ?,
                        s_rating_reason = ?,
                        active = 1,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        parsed.protocol,
                        parsed.host,
                        parsed.port,
                        parsed.source_subscribe_id,
                        parsed.sni,
                        parsed.sni_base_domain,
                        parsed.security,
                        parsed.transport,
                        parsed.flow,
                        parsed.alpn,
                        parsed.fp,
                        parsed.black,
                        parsed.black_reason,
                        parsed.rating,
                        parsed.rating_reason,
                        parsed.rating,
                        parsed.rating_reason,
                        now,
                        server_id,
                    ),
                )

        return {
            "total": total,
            "candidate": candidate,
            "bad": bad,
            "low_rating": low_rating,
            "medium_rating": medium_rating,
            "high_rating": high_rating,
            "top_rating": top_rating,
            "parse_failed": parse_failed,
            "whitelist_domains": len(whitelist_base_domains),
        }
