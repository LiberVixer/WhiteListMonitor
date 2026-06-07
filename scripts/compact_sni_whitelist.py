from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from white_list_monitor.database import Database
from white_list_monitor.sni_domains import compact_sni_whitelist
from white_list_monitor.settings_store import DB_PATH


def main() -> None:
    db_path = Path(DB_PATH)
    db = Database(db_path)
    result = compact_sni_whitelist(db)

    print(f"DB: {db_path}")
    print(f"Before: {result['before']}")
    print(f"After: {result['after']}")
    print(f"Removed: {result['removed']}")


if __name__ == "__main__":
    main()
