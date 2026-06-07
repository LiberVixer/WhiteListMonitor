import tempfile
import unittest
from pathlib import Path

from white_list_monitor.database import Database
from white_list_monitor.sni_domains import (
    compact_sni_whitelist,
    ensure_sni_domain_pool_table,
    ensure_whitelist_sni_table,
    list_sni_domain_pool,
    merge_sni_domain_rows,
    normalize_sni_domain,
    set_whitelist_sni_enabled,
    sync_sni_domain_pool_from_servers,
)
from white_list_monitor.vpn_worker import VPNWorker


class SniDomainNormalizeTest(unittest.TestCase):
    def test_normalizes_urls_wildcards_and_ports(self):
        self.assertEqual(
            normalize_sni_domain("https://*.Example.COM:443/path"),
            "example.com",
        )

    def test_cuts_sni_to_second_level_domain(self):
        self.assertEqual(normalize_sni_domain("find.ya.ru"), "ya.ru")
        self.assertEqual(normalize_sni_domain("money.avito.com"), "avito.com")

    def test_rejects_values_without_base_domain(self):
        self.assertIsNone(normalize_sni_domain("localhost"))
        self.assertIsNone(normalize_sni_domain("bad domain.example"))
        self.assertIsNone(normalize_sni_domain("5.188.114.12"))
        self.assertIsNone(normalize_sni_domain("114.12"))

    def test_merges_duplicates_after_second_level_cut(self):
        self.assertEqual(
            merge_sni_domain_rows(
                [
                    ("find.ya.ru", 1, "first"),
                    ("ya.ru", 0, "second"),
                    ("money.avito.com", 0, ""),
                    ("avito.com", 1, "enabled duplicate"),
                ]
            ),
            [
                ("ya.ru", 1, "first"),
                ("avito.com", 1, "enabled duplicate"),
            ],
        )

    def test_compacts_sni_whitelist_table(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "wl.db")

            with db.connect() as con:
                con.execute(
                    """
                    CREATE TABLE whitelist_sni (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL UNIQUE,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        comment TEXT
                    )
                    """
                )
                con.executemany(
                    """
                    INSERT INTO whitelist_sni (domain, enabled, comment)
                    VALUES (?, ?, ?)
                    """,
                    [
                        ("find.ya.ru", 1, "subdomain"),
                        ("ya.ru", 0, "base"),
                        ("money.avito.com", 0, ""),
                    ],
                )

            result = compact_sni_whitelist(db)

            with db.connect() as con:
                rows = con.execute(
                    """
                    SELECT domain, enabled, comment
                    FROM whitelist_sni
                    ORDER BY domain
                    """
                ).fetchall()

        self.assertEqual(result["before"], 3)
        self.assertEqual(result["after"], 2)
        self.assertEqual(result["removed"], 1)
        self.assertEqual(
            rows,
            [
                ("avito.com", 0, ""),
                ("ya.ru", 1, "subdomain"),
            ],
        )

    def test_sni_domain_pool_syncs_from_servers_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "wl.db")
            worker = VPNWorker(db)
            worker.ensure_schema()

            raw_uris = [
                "vless://uuid1@example.com:443?security=reality&sni=find.ya.ru",
                "vless://uuid2@example.net:443?security=reality&sni=ya.ru",
                "vless://uuid3@example.org:443?security=reality&sni=money.avito.com",
            ]
            servers = []

            for raw_uri in raw_uris:
                server = worker.parse_server(raw_uri, source_subscribe_id=None)
                self.assertIsNotNone(server)
                worker.classify_and_rate(server, set())
                servers.append(server)

            worker.save_servers(servers)
            result = sync_sni_domain_pool_from_servers(db)

            rows = list_sni_domain_pool(db)

        self.assertEqual(result["domains"], 2)
        self.assertEqual(
            [(row["domain"], row["found_count"]) for row in rows],
            [("ya.ru", 2), ("avito.com", 1)],
        )

    def test_sni_domain_pool_adds_and_removes_whitelist_status(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "wl.db")
            ensure_sni_domain_pool_table(db)
            ensure_whitelist_sni_table(db)

            with db.connect() as con:
                con.execute(
                    """
                    INSERT INTO sni_domain_pool (
                        domain,
                        found_count,
                        first_seen_at,
                        last_seen_at,
                        comment
                    )
                    VALUES ('ya.ru', 2, '2026-06-07T10:00:00', '2026-06-07T10:00:00', '')
                    """
                )

            self.assertTrue(set_whitelist_sni_enabled(db, "find.ya.ru", True))
            rows = list_sni_domain_pool(db)
            self.assertTrue(rows[0]["whitelist_enabled"])

            self.assertTrue(set_whitelist_sni_enabled(db, "ya.ru", False))
            rows = list_sni_domain_pool(db)
            self.assertFalse(rows[0]["whitelist_enabled"])


if __name__ == "__main__":
    unittest.main()
