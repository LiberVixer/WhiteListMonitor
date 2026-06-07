import ipaddress
import re
from collections import Counter
from datetime import datetime
from typing import Callable

from .database import Database


WHITELIST_SNI_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS whitelist_sni (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    comment TEXT
)
"""

SNI_DOMAIN_POOL_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS sni_domain_pool (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    found_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    comment TEXT
)
"""

def normalize_sni_domain(value: str) -> str | None:
    value = value.strip().lower()

    value = value.replace("http://", "")
    value = value.replace("https://", "")

    value = value.split("/", 1)[0]
    value = value.split(":", 1)[0]
    value = value.strip().strip(".")

    if value.startswith("*."):
        value = value[2:]

    if not value:
        return None

    if len(value) > 253:
        return None

    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    if not re.fullmatch(r"[a-z0-9а-яё.-]+", value):
        return None

    parts = [part for part in value.split(".") if part]

    if len(parts) < 2:
        return None

    if parts[-1].isdigit():
        return None

    return ".".join(parts[-2:])


def merge_sni_domain_rows(
    rows: list[tuple[str, int | bool, str]],
) -> list[tuple[str, int, str]]:
    merged: dict[str, list[int | str]] = {}
    order: list[str] = []

    for raw_domain, enabled, comment in rows:
        domain = normalize_sni_domain(str(raw_domain or ""))

        if not domain:
            continue

        enabled_value = 1 if enabled else 0
        comment_value = str(comment or "").strip()

        if domain not in merged:
            merged[domain] = [enabled_value, comment_value]
            order.append(domain)
            continue

        if enabled_value:
            merged[domain][0] = 1

        if not merged[domain][1] and comment_value:
            merged[domain][1] = comment_value

    return [
        (domain, int(merged[domain][0]), str(merged[domain][1]))
        for domain in order
    ]


def ensure_column(con, table: str, column: str, definition: str) -> None:
    rows = con.execute(f"PRAGMA table_info({table})").fetchall()
    existing_columns = {row[1] for row in rows}

    if column not in existing_columns:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def ensure_whitelist_sni_table(db: Database) -> None:
    with db.connect() as con:
        con.execute(WHITELIST_SNI_TABLE_SQL)


def ensure_sni_domain_pool_table(db: Database) -> None:
    with db.connect() as con:
        con.execute(SNI_DOMAIN_POOL_TABLE_SQL)
        ensure_column(con, "sni_domain_pool", "found_count", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(con, "sni_domain_pool", "first_seen_at", "DATETIME")
        ensure_column(con, "sni_domain_pool", "last_seen_at", "DATETIME")
        ensure_column(con, "sni_domain_pool", "comment", "TEXT")


def compact_sni_whitelist(db: Database) -> dict[str, int]:
    ensure_whitelist_sni_table(db)

    with db.connect() as con:
        rows = con.execute(
            """
            SELECT domain, enabled, comment
            FROM whitelist_sni
            ORDER BY id ASC
            """
        ).fetchall()

        source_rows = [
            (str(domain or ""), int(enabled or 0), str(comment or ""))
            for domain, enabled, comment in rows
        ]
        merged_rows = merge_sni_domain_rows(source_rows)

        con.execute("DELETE FROM whitelist_sni")
        con.executemany(
            """
            INSERT INTO whitelist_sni (domain, enabled, comment)
            VALUES (?, ?, ?)
            """,
            merged_rows,
        )

    return {
        "before": len(source_rows),
        "after": len(merged_rows),
        "removed": len(source_rows) - len(merged_rows),
    }


def compact_sni_domain_pool(db: Database) -> dict[str, int]:
    ensure_sni_domain_pool_table(db)

    with db.connect() as con:
        rows = con.execute(
            """
            SELECT domain, found_count, first_seen_at, last_seen_at, comment
            FROM sni_domain_pool
            ORDER BY id ASC
            """
        ).fetchall()

        merged: dict[str, dict[str, object]] = {}
        order: list[str] = []

        for domain, found_count, first_seen_at, last_seen_at, comment in rows:
            normalized = normalize_sni_domain(str(domain or ""))

            if not normalized:
                continue

            if normalized not in merged:
                merged[normalized] = {
                    "found_count": int(found_count or 0),
                    "first_seen_at": first_seen_at,
                    "last_seen_at": last_seen_at,
                    "comment": str(comment or ""),
                }
                order.append(normalized)
                continue

            current = merged[normalized]
            current["found_count"] = int(current["found_count"]) + int(found_count or 0)

            if first_seen_at and (
                not current["first_seen_at"] or first_seen_at < current["first_seen_at"]
            ):
                current["first_seen_at"] = first_seen_at

            if last_seen_at and (
                not current["last_seen_at"] or last_seen_at > current["last_seen_at"]
            ):
                current["last_seen_at"] = last_seen_at

            if not current["comment"] and comment:
                current["comment"] = str(comment)

        merged_rows = [
            (
                domain,
                int(merged[domain]["found_count"]),
                str(merged[domain]["first_seen_at"] or ""),
                str(merged[domain]["last_seen_at"] or ""),
                str(merged[domain]["comment"] or ""),
            )
            for domain in order
        ]

        con.execute("DELETE FROM sni_domain_pool")
        con.executemany(
            """
            INSERT INTO sni_domain_pool (
                domain,
                found_count,
                first_seen_at,
                last_seen_at,
                comment
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            merged_rows,
        )

    return {
        "before": len(rows),
        "after": len(merged_rows),
        "removed": len(rows) - len(merged_rows),
    }


def sync_sni_domain_pool_from_servers(
    db: Database,
    progress_callback: Callable[[int], None] | None = None,
) -> dict[str, int]:
    ensure_sni_domain_pool_table(db)

    counts: Counter[str] = Counter()
    progress = progress_callback or (lambda value: None)
    progress(0)

    with db.connect() as con:
        servers_table = con.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'servers'
            """
        ).fetchone()

        if not servers_table:
            progress(100)
            return {
                "seen": 0,
                "domains": 0,
                "inserted": 0,
                "updated": 0,
                "removed": 0,
                "total": 0,
            }

        total_rows = int(
            con.execute(
                """
                SELECT COUNT(*)
                FROM servers
                WHERE COALESCE(sni_base_domain, '') <> ''
                   OR COALESCE(sni, '') <> ''
                """
            ).fetchone()[0]
            or 0
        )

        cursor = con.execute(
            """
            SELECT sni_base_domain, sni
            FROM servers
            WHERE COALESCE(sni_base_domain, '') <> ''
               OR COALESCE(sni, '') <> ''
            """
        )

        seen_rows = 0

        while True:
            rows = cursor.fetchmany(5000)

            if not rows:
                break

            for sni_base_domain, sni in rows:
                domain = normalize_sni_domain(str(sni_base_domain or ""))

                if not domain:
                    domain = normalize_sni_domain(str(sni or ""))

                if domain:
                    counts[domain] += 1

            seen_rows += len(rows)

            if total_rows:
                progress(min(70, int(seen_rows / total_rows * 70)))

    progress(72)

    now = datetime.now().isoformat(timespec="seconds")
    inserted = 0
    updated = 0
    domains = sorted(counts.items())
    total_domains = len(domains)

    with db.connect() as con:
        for index, (domain, found_count) in enumerate(domains, start=1):
            existing = con.execute(
                """
                SELECT id
                FROM sni_domain_pool
                WHERE domain = ?
                """,
                (domain,),
            ).fetchone()

            if existing:
                con.execute(
                    """
                    UPDATE sni_domain_pool
                    SET
                        found_count = ?,
                        last_seen_at = ?
                    WHERE domain = ?
                    """,
                    (found_count, now, domain),
                )
                updated += 1
            else:
                con.execute(
                    """
                    INSERT INTO sni_domain_pool (
                        domain,
                        found_count,
                        first_seen_at,
                        last_seen_at,
                        comment
                    )
                    VALUES (?, ?, ?, ?, '')
                    """,
                    (domain, found_count, now, now),
                )
                inserted += 1

            if total_domains and index % 100 == 0:
                progress(72 + min(18, int(index / total_domains * 18)))

    progress(92)
    compacted = compact_sni_domain_pool(db)
    progress(96)

    with db.connect() as con:
        total = con.execute("SELECT COUNT(*) FROM sni_domain_pool").fetchone()[0]

    progress(100)

    return {
        "seen": total_rows,
        "domains": len(counts),
        "inserted": inserted,
        "updated": updated,
        "removed": compacted["removed"],
        "total": int(total),
    }


def list_sni_domain_pool(db: Database) -> list[dict[str, object]]:
    ensure_sni_domain_pool_table(db)
    ensure_whitelist_sni_table(db)

    with db.connect() as con:
        rows = con.execute(
            """
            SELECT
                p.domain,
                p.found_count,
                p.comment,
                COALESCE(w.enabled, 0) AS whitelist_enabled
            FROM sni_domain_pool p
            LEFT JOIN whitelist_sni w
                ON w.domain = p.domain
            ORDER BY whitelist_enabled DESC, p.found_count DESC, p.domain ASC
            """
        ).fetchall()

    return [
        {
            "domain": str(domain or ""),
            "found_count": int(found_count or 0),
            "comment": str(comment or ""),
            "whitelist_enabled": bool(whitelist_enabled),
        }
        for domain, found_count, comment, whitelist_enabled in rows
    ]


def set_whitelist_sni_enabled(
    db: Database,
    domain: str,
    enabled: bool,
    comment: str = "added from SNI domain pool",
) -> bool:
    normalized = normalize_sni_domain(domain)

    if not normalized:
        return False

    ensure_whitelist_sni_table(db)

    with db.connect() as con:
        row = con.execute(
            """
            SELECT id
            FROM whitelist_sni
            WHERE domain = ?
            """,
            (normalized,),
        ).fetchone()

        if row:
            con.execute(
                """
                UPDATE whitelist_sni
                SET enabled = ?
                WHERE domain = ?
                """,
                (1 if enabled else 0, normalized),
            )
        elif enabled:
            con.execute(
                """
                INSERT INTO whitelist_sni (domain, enabled, comment)
                VALUES (?, 1, ?)
                """,
                (normalized, comment),
            )
        else:
            return True

    return True
