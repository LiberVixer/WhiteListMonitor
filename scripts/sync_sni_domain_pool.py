from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from white_list_monitor.database import Database
from white_list_monitor.settings_store import DB_PATH
from white_list_monitor.sni_domains import sync_sni_domain_pool_from_servers


def main() -> None:
    db_path = Path(DB_PATH)
    result = sync_sni_domain_pool_from_servers(Database(db_path))

    print(f"DB: {db_path}")
    print(f"Server SNI rows scanned: {result['seen']}")
    print(f"Domains found: {result['domains']}")
    print(f"Inserted: {result['inserted']}")
    print(f"Updated: {result['updated']}")
    print(f"Duplicates removed: {result['removed']}")
    print(f"Total sni_domain_pool: {result['total']}")


if __name__ == "__main__":
    main()
