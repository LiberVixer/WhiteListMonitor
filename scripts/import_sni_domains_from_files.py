import json
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from white_list_monitor.database import Database
from white_list_monitor.sni_domains import (
    compact_sni_whitelist,
    normalize_sni_domain,
)
from white_list_monitor.settings_store import DB_PATH
from white_list_monitor.vpn_worker import VPNWorker


DEFAULT_FILES = [
    Path("/media/sf_Data/новый 1.txt"),
    Path("/media/sf_Data/новый 2.txt"),
]

DOMAIN_KEYS = {
    "server",
    "server_name",
    "sni",
    "host",
    "Host",
}


def iter_json_objects(text: str) -> list[Any]:
    decoder = json.JSONDecoder()
    position = 0
    result = []

    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1

        if position >= len(text):
            break

        value, position = decoder.raw_decode(text, position)
        result.append(value)

    return result


def add_domain(
    domains: dict[str, set[str]],
    value: str,
    source: str,
) -> None:
    domain = normalize_sni_domain(value)

    if not domain:
        return

    domains.setdefault(domain, set()).add(source)


def collect_json_domains(
    value: Any,
    domains: dict[str, set[str]],
    source: str,
    key: str = "",
) -> None:
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            collect_json_domains(child_value, domains, source, str(child_key))
        return

    if isinstance(value, list):
        for item in value:
            collect_json_domains(item, domains, source, key)
        return

    if isinstance(value, str) and key in DOMAIN_KEYS:
        add_domain(domains, value, source)


def collect_file_domains(path: Path, domains: dict[str, set[str]]) -> None:
    text = path.read_text(encoding="utf-8-sig")
    worker = VPNWorker(db=None)

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if "://" not in line:
            continue

        parsed = worker.parse_server(line, source_subscribe_id=None)

        if not parsed:
            continue

        add_domain(domains, parsed.sni, path.name)
        add_domain(domains, parsed.host, path.name)

    try:
        objects = iter_json_objects(text)
    except json.JSONDecodeError:
        objects = []

    for item in objects:
        collect_json_domains(item, domains, path.name)


def import_domains(paths: list[Path]) -> dict[str, Any]:
    domains: dict[str, set[str]] = {}

    for path in paths:
        collect_file_domains(path, domains)

    compact_sni_whitelist(Database(Path(DB_PATH)))

    inserted = 0
    existing = 0
    enabled = 0
    comment = "imported from working samples"

    db = Database(Path(DB_PATH))

    with db.connect() as con:
        for domain in sorted(domains):
            row = con.execute(
                """
                SELECT enabled
                FROM whitelist_sni
                WHERE domain = ?
                """,
                (domain,),
            ).fetchone()

            if row is None:
                con.execute(
                    """
                    INSERT INTO whitelist_sni (domain, enabled, comment)
                    VALUES (?, 1, ?)
                    """,
                    (domain, comment),
                )
                inserted += 1
                continue

            existing += 1

            if not row[0]:
                con.execute(
                    """
                    UPDATE whitelist_sni
                    SET enabled = 1
                    WHERE domain = ?
                    """,
                    (domain,),
                )
                enabled += 1

    compacted = compact_sni_whitelist(db)

    with db.connect() as con:
        total = con.execute("SELECT COUNT(*) FROM whitelist_sni").fetchone()[0]

    return {
        "domains": domains,
        "inserted": inserted,
        "existing": existing,
        "enabled": enabled,
        "compacted": compacted,
        "total": total,
    }


def main() -> None:
    paths = [Path(arg) for arg in sys.argv[1:]] or DEFAULT_FILES
    result = import_domains(paths)
    domains: dict[str, set[str]] = result["domains"]

    print(f"Files: {', '.join(str(path) for path in paths)}")
    print(f"Found domains: {len(domains)}")

    for domain in sorted(domains):
        sources = ", ".join(sorted(domains[domain]))
        print(f"  {domain} <- {sources}")

    print(f"Inserted: {result['inserted']}")
    print(f"Already existed: {result['existing']}")
    print(f"Enabled existing: {result['enabled']}")
    print(f"Compacted removed: {result['compacted']['removed']}")
    print(f"Total whitelist_sni: {result['total']}")


if __name__ == "__main__":
    main()
