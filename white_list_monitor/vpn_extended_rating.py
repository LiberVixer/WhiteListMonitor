import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime

from PyQt6.QtCore import QObject, pyqtSignal

from .database import Database
from .status import NetworkStatus


@dataclass
class PortTestResult:
    server_id: int
    host: str
    port: int
    success: bool
    latency_ms: int | None
    attempts_used: int
    e_delta: int
    error: str = ""


class ExtendedRatingWorker(QObject):
    log = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(
        self,
        db: Database,
        mode: NetworkStatus,
        max_workers: int = 50,
        top_limit: int = 5000,
        timeout_seconds: int = 10,
        retries: int = 3,
        submit_delay_ms: int = 100,
        retry_delay_ms: int = 1000,
    ):
        super().__init__()
        self.db = db
        self.mode = mode
        self.max_workers = max(1, min(int(max_workers), 50))
        self.top_limit = max(1, int(top_limit))
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.retries = max(1, int(retries))
        self.submit_delay_ms = max(0, int(submit_delay_ms))
        self.retry_delay_ms = max(0, int(retry_delay_ms))

    def run(self) -> None:
        try:
            self.run_test()
        except Exception as exc:
            self.log.emit(f"Ошибка e-рейтинга: {exc}")
        finally:
            self.finished.emit()

    def run_test(self) -> None:
        self.ensure_schema()

        mode_name = self.mode_name()
        servers = self.fetch_servers()

        if not servers:
            self.log.emit("Нет серверов для e-теста. Сначала запусти VPN-скрипт и получи s-рейтинг.")
            return

        total = len(servers)
        self.log.emit(
            f"Запуск e-теста: режим={mode_name}, потоков={self.max_workers}, "
            f"top={total}, timeout={self.timeout_seconds}s, попыток={self.retries}"
        )
        self.log.emit(
            "Тест проверяет только TCP-доступность host:port. Он не поднимает VPN-туннель."
        )
        self.log.emit(
            "Прогресс будет выводиться по каждому серверу: номер/всего, адрес, результат, задержка."
        )

        success_count = 0
        fail_count = 0
        processed = 0
        started_at = datetime.now().isoformat(timespec="seconds")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []

            for index, server in enumerate(servers, start=1):
                futures.append(executor.submit(self.test_one_server, server))

                if index == 1 or index % 100 == 0 or index == total:
                    self.log.emit(
                        f"e-тест: поставлено в очередь {index}/{total}"
                    )

                if self.submit_delay_ms > 0:
                    time.sleep(self.submit_delay_ms / 1000)

            for future in as_completed(futures):
                result = future.result()
                processed += 1

                if result.success:
                    success_count += 1
                else:
                    fail_count += 1

                self.save_result(result, started_at)

                if result.success:
                    self.log.emit(
                        f"e-тест {processed}/{total}: OK {result.host}:{result.port} "
                        f"{result.latency_ms} ms, попытка {result.attempts_used}/{self.retries}, "
                        f"e+{result.e_delta}, OK={success_count}, FAIL={fail_count}"
                    )
                else:
                    error = result.error or "порт не открылся"
                    self.log.emit(
                        f"e-тест {processed}/{total}: FAIL {result.host}:{result.port} "
                        f"после {result.attempts_used}/{self.retries} попыток, "
                        f"OK={success_count}, FAIL={fail_count}, ошибка: {error[:120]}"
                    )

                if processed == 1 or processed % 25 == 0 or processed == total:
                    percent = int(processed * 100 / total)
                    self.log.emit(
                        f"e-тест прогресс: {processed}/{total} ({percent}%), "
                        f"OK={success_count}, FAIL={fail_count}"
                    )

        self.log.emit(
            f"e-тест завершён: проверено={processed}, OK={success_count}, FAIL={fail_count}"
        )

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
                    rating INTEGER NOT NULL DEFAULT 0,
                    rating_reason TEXT,
                    added_at DATETIME,
                    updated_at DATETIME
                )
                """
            )

            self.ensure_column(con, "servers", "s_rating", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "servers", "s_rating_reason", "TEXT")
            self.ensure_column(con, "servers", "black", "INTEGER NOT NULL DEFAULT 0")
            self.ensure_column(con, "servers", "black_reason", "TEXT")
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

            # Перенос старого статичного rating в новый s_rating, если s_rating ещё пустой.
            con.execute(
                """
                UPDATE servers
                SET
                    s_rating = COALESCE(NULLIF(s_rating, 0), rating, 0),
                    s_rating_reason = COALESCE(s_rating_reason, rating_reason)
                WHERE COALESCE(s_rating, 0) = 0
                """
            )

    def ensure_column(self, con, table: str, column: str, definition: str) -> None:
        rows = con.execute(f"PRAGMA table_info({table})").fetchall()
        existing = {row[1] for row in rows}

        if column not in existing:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def fetch_servers(self) -> list[dict]:
        with self.db.connect() as con:
            rows = con.execute(
                """
                SELECT
                    id,
                    host,
                    port,
                    protocol,
                    COALESCE(NULLIF(s_rating, 0), rating, 0) AS static_rating,
                    COALESCE(e_rating, 0) AS extended_rating
                FROM servers
                WHERE COALESCE(black, 0) = 0
                  AND COALESCE(active, 1) = 1
                ORDER BY static_rating DESC, found_count DESC, id ASC
                LIMIT ?
                """,
                (self.top_limit,),
            ).fetchall()

        result = []
        for row in rows:
            result.append(
                {
                    "id": int(row[0]),
                    "host": str(row[1]),
                    "port": int(row[2]),
                    "protocol": str(row[3]),
                    "s_rating": int(row[4] or 0),
                    "e_rating": int(row[5] or 0),
                }
            )

        return result

    def test_one_server(self, server: dict) -> PortTestResult:
        host = server["host"]
        port = server["port"]
        last_error = ""

        for attempt in range(1, self.retries + 1):
            start = time.monotonic()

            try:
                with socket.create_connection(
                    (host, port),
                    timeout=self.timeout_seconds,
                ):
                    latency_ms = int((time.monotonic() - start) * 1000)
                    e_delta = self.calculate_e_delta(latency_ms)

                    return PortTestResult(
                        server_id=server["id"],
                        host=host,
                        port=port,
                        success=True,
                        latency_ms=latency_ms,
                        attempts_used=attempt,
                        e_delta=e_delta,
                    )

            except Exception as exc:
                last_error = str(exc)

            if attempt < self.retries and self.retry_delay_ms > 0:
                time.sleep(self.retry_delay_ms / 1000)

        return PortTestResult(
            server_id=server["id"],
            host=host,
            port=port,
            success=False,
            latency_ms=None,
            attempts_used=self.retries,
            e_delta=0,
            error=last_error,
        )

    def calculate_e_delta(self, latency_ms: int) -> int:
        if self.mode == NetworkStatus.WHITELIST_MODE:
            if latency_ms <= 80:
                return 20
            if latency_ms <= 150:
                return 16
            if latency_ms <= 300:
                return 12
            if latency_ms <= 700:
                return 8
            if latency_ms <= 1500:
                return 5
            return 3

        if self.mode == NetworkStatus.FREE_INTERNET:
            if latency_ms <= 80:
                return 5
            if latency_ms <= 150:
                return 4
            if latency_ms <= 300:
                return 3
            if latency_ms <= 700:
                return 2
            return 1

        # Неизвестный режим: порт открыт, но ценность результата ниже.
        return 1

    def save_result(self, result: PortTestResult, tested_at: str) -> None:
        mode_name = self.mode_name()

        with self.db.connect() as con:
            if result.success:
                con.execute(
                    """
                    UPDATE servers
                    SET
                        e_rating = COALESCE(e_rating, 0) + ?,
                        e_success_count = COALESCE(e_success_count, 0) + 1,
                        e_last_latency_ms = ?,
                        e_best_latency_ms = CASE
                            WHEN e_best_latency_ms IS NULL THEN ?
                            WHEN ? < e_best_latency_ms THEN ?
                            ELSE e_best_latency_ms
                        END,
                        e_last_test_at = ?,
                        e_last_mode = ?,
                        e_last_error = '',
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        result.e_delta,
                        result.latency_ms,
                        result.latency_ms,
                        result.latency_ms,
                        result.latency_ms,
                        tested_at,
                        mode_name,
                        tested_at,
                        result.server_id,
                    ),
                )
            else:
                con.execute(
                    """
                    UPDATE servers
                    SET
                        e_fail_count = COALESCE(e_fail_count, 0) + 1,
                        e_last_latency_ms = NULL,
                        e_last_test_at = ?,
                        e_last_mode = ?,
                        e_last_error = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        tested_at,
                        mode_name,
                        result.error[:500],
                        tested_at,
                        result.server_id,
                    ),
                )

    def mode_name(self) -> str:
        if self.mode == NetworkStatus.WHITELIST_MODE:
            return "whitelist"
        if self.mode == NetworkStatus.FREE_INTERNET:
            return "open"
        if self.mode == NetworkStatus.NO_INTERNET:
            return "no_internet"
        if self.mode == NetworkStatus.ROUTER_DOWN:
            return "router_down"
        return "unknown"
