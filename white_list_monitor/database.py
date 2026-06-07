import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .settings_store import DB_PATH, ensure_app_dir


@dataclass
class Subscribe:
    id: int | None
    url: str
    enabled: bool = True
    comment: str = ""


class Database:
    def __init__(self, path: Path = DB_PATH):
        ensure_app_dir()
        self.path = path
        self.init_schema()

    def connect(self):
        return sqlite3.connect(self.path)

    def init_schema(self) -> None:
        with self.connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS subscribes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    comment TEXT DEFAULT ''
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS vpn_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subscribe_id INTEGER,
                    server_name TEXT,
                    protocol TEXT,
                    result TEXT,
                    latency INTEGER,
                    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(subscribe_id) REFERENCES subscribes(id)
                )
                """
            )

    def list_subscribes(self) -> list[Subscribe]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT id, url, enabled, comment FROM subscribes ORDER BY id"
            ).fetchall()
        return [Subscribe(id=row[0], url=row[1], enabled=bool(row[2]), comment=row[3] or "") for row in rows]

    def replace_subscribes(self, subscribes: Iterable[Subscribe]) -> None:
        with self.connect() as con:
            con.execute("DELETE FROM subscribes")
            con.executemany(
                "INSERT INTO subscribes(url, enabled, comment) VALUES (?, ?, ?)",
                [(s.url, int(s.enabled), s.comment) for s in subscribes if s.url.strip()],
            )
