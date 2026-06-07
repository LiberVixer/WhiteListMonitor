import json
import tempfile
import unittest
from pathlib import Path

from white_list_monitor.database import Database
from white_list_monitor.status import NetworkStatus
from white_list_monitor.vpn_extended_rating import ExtendedRatingWorker
from white_list_monitor.vpn_worker import S_RAW_MAX, S_RAW_MIN, VPNWorker


class VPNWorkerStaticRatingTest(unittest.TestCase):
    def parse_and_rate(
        self,
        raw_uri: str,
        whitelist_base_domains: set[str] | None = None,
    ):
        worker = VPNWorker(db=None)
        server = worker.parse_server(raw_uri, source_subscribe_id=None)
        self.assertIsNotNone(server)

        worker.classify_and_rate(server, whitelist_base_domains or set())
        return server

    def test_normalized_rating_bounds_are_fixed(self):
        worker = VPNWorker(db=None)

        self.assertEqual(worker.normalize_s_rating(S_RAW_MIN), 1)
        self.assertEqual(worker.normalize_s_rating(S_RAW_MAX), 99)
        self.assertEqual(worker.normalize_s_rating(S_RAW_MIN - 100), 1)
        self.assertEqual(worker.normalize_s_rating(S_RAW_MAX + 100), 99)

    def test_vless_reality_vision_is_strong_candidate(self):
        server = self.parse_and_rate(
            "vless://uuid@example.com:443?"
            "security=reality&type=xhttp&sni=example.com&"
            "flow=xtls-rprx-vision&fp=chrome&pbk=key&sid=abcd&alpn=h2",
            {"example.com"},
        )

        self.assertEqual(server.black, 0)
        self.assertGreaterEqual(server.rating, 90)
        self.assertTrue(server.rating_reason.startswith("CANDIDATE:"))
        self.assertIn("model=normalized_v2", server.rating_reason)
        self.assertIn("profile=vless_reality_vision+8", server.rating_reason)
        self.assertIn("sni_whitelisted=example.com+18", server.rating_reason)

    def test_best_supported_profile_gets_max_rating(self):
        server = self.parse_and_rate(
            "vless://uuid@example.com:443?"
            "security=reality&type=xhttp&sni=example.com&"
            "flow=xtls-rprx-vision&fp=chrome&pbk=key&sid=abcd&"
            "spx=/&path=/api&extra=%7B%7D&alpn=h2",
            {"example.com"},
        )

        self.assertEqual(server.black, 0)
        self.assertEqual(server.rating, 99)
        self.assertIn("normalized=99", server.rating_reason)

    def test_minimal_candidate_stays_low(self):
        server = self.parse_and_rate(
            "ssr://"
            "ZXhhbXBsZS5jb206MTIzNDU6b3JpZ2luOmFlcy0yNTYtY2ZiOnBsYWluOnBhc3N3b3JkLz8"
        )

        self.assertEqual(server.black, 0)
        self.assertLessEqual(server.rating, 30)
        self.assertIn("protocol=ssr-4", server.rating_reason)
        self.assertIn("port=non_tls_12345-10", server.rating_reason)

    def test_wireguard_is_bad_for_static_whitelist_filter(self):
        server = self.parse_and_rate("wireguard://example.com:51820")

        self.assertEqual(server.black, 1)
        self.assertEqual(server.rating, 0)
        self.assertTrue(server.rating_reason.startswith("BAD:"))
        self.assertIn("Протокол не подходит", server.black_reason)

    def test_unknown_sni_is_candidate_but_scores_below_whitelisted_sni(self):
        unknown = self.parse_and_rate(
            "vless://uuid@example.com:443?"
            "security=reality&type=tcp&sni=blocked.example&fp=chrome",
            {"allowed.example"},
        )
        whitelisted = self.parse_and_rate(
            "vless://uuid@example.com:443?"
            "security=reality&type=tcp&sni=blocked.example&fp=chrome",
            {"blocked.example"},
        )

        self.assertEqual(unknown.black, 0)
        self.assertEqual(whitelisted.black, 0)
        self.assertLess(unknown.rating, whitelisted.rating)
        self.assertIn("sni=blocked.example+12", unknown.rating_reason)
        self.assertIn(
            "sni_whitelisted=blocked.example+18",
            whitelisted.rating_reason,
        )

    def test_legacy_protocol_can_remain_weak_candidate(self):
        server = self.parse_and_rate("ss://YWVzLTI1Ni1nY206cGFzcw@example.com:443")

        self.assertEqual(server.black, 0)
        self.assertLessEqual(server.rating, 30)
        self.assertIn("protocol=ss+0", server.rating_reason)

    def test_reference_raw_reality_profile_is_high_without_sni_whitelist(self):
        server = self.parse_and_rate(
            "vless://831f0f42-e5f0-48b5-b8e5-95a3fd7b0ee7@"
            "cdn0.s3-rus.ru:443?"
            "encryption=none&flow=xtls-rprx-vision&type=raw&"
            "security=reality&sni=de-s3.ru&fp=edge&"
            "pbk=CmKaRa0TecpFSyn7OK6UTPPuWJ7ji2OwsaOBuUtSKGM&"
            "sid=7a3f9e2b1c8d4f6a&spx=/",
            set(),
        )

        self.assertEqual(server.black, 0)
        self.assertGreaterEqual(server.rating, 90)
        self.assertIn("transport=raw_reality+15", server.rating_reason)
        self.assertIn("browser_fp=edge+8", server.rating_reason)
        self.assertIn("profile=vless_reality_raw_vision+10", server.rating_reason)

    def test_existing_raw_uri_keeps_first_static_rating(self):
        raw_uri = (
            "vless://uuid@example.com:443?"
            "security=reality&type=tcp&sni=example.com&"
            "flow=xtls-rprx-vision&fp=chrome"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "wl.db")
            worker = VPNWorker(db)
            worker.ensure_schema()

            first = worker.parse_server(raw_uri, source_subscribe_id=None)
            self.assertIsNotNone(first)
            worker.classify_and_rate(first, {"example.com"})
            self.assertEqual(first.black, 0)

            worker.save_servers([first])

            second = worker.parse_server(raw_uri, source_subscribe_id=None)
            self.assertIsNotNone(second)
            worker.classify_and_rate(second, {"other.example"})
            self.assertEqual(second.black, 0)
            self.assertLess(second.rating, first.rating)

            worker.save_servers([second])

            with db.connect() as con:
                row = con.execute(
                    """
                    SELECT black, black_reason, s_rating, s_rating_reason, found_count
                    FROM servers
                    WHERE raw_uri = ?
                    """,
                    (raw_uri,),
                ).fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], 0)
        self.assertEqual(row[1] or "", "")
        self.assertGreaterEqual(row[2], 70)
        self.assertIn("CANDIDATE:", row[3])
        self.assertEqual(row[4], 2)

    def test_initial_static_rating_matches_manual_recalculate_when_context_matches(self):
        raw_uri = (
            "vless://uuid@example.com:443?"
            "security=reality&type=raw&sni=example.com&"
            "flow=xtls-rprx-vision&fp=edge&pbk=key&sid=abcd&spx=/"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "wl.db")
            worker = VPNWorker(db)
            worker.ensure_schema()

            with db.connect() as con:
                con.execute(
                    """
                    INSERT INTO whitelist_sni (domain, enabled, comment)
                    VALUES ('example.com', 1, '')
                    """
                )

            server = worker.parse_server(raw_uri, source_subscribe_id=None)
            self.assertIsNotNone(server)
            worker.classify_and_rate(server, {"example.com"})
            worker.save_servers([server])
            initial_rating = server.rating
            initial_reason = server.rating_reason

            result = worker.recalculate_static_ratings_in_db()

            with db.connect() as con:
                row = con.execute(
                    """
                    SELECT black, s_rating, s_rating_reason
                    FROM servers
                    WHERE raw_uri = ?
                    """,
                    (raw_uri,),
                ).fetchone()

        self.assertEqual(result["total"], 1)
        self.assertEqual(row[0], 0)
        self.assertEqual(row[1], initial_rating)
        self.assertEqual(row[2], initial_reason)

    def test_manual_recalculate_updates_static_rating_and_keeps_e_rating(self):
        raw_uri = (
            "vless://uuid@example.com:443?"
            "security=reality&type=tcp&sni=example.com&"
            "flow=xtls-rprx-vision&fp=chrome"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "wl.db")
            worker = VPNWorker(db)
            worker.ensure_schema()

            server = worker.parse_server(raw_uri, source_subscribe_id=None)
            self.assertIsNotNone(server)
            worker.classify_and_rate(server, {"example.com"})
            worker.save_servers([server])

            with db.connect() as con:
                con.execute(
                    """
                    UPDATE servers
                    SET e_rating = 123
                    WHERE raw_uri = ?
                    """,
                    (raw_uri,),
                )
                con.execute(
                    """
                    INSERT INTO whitelist_sni (domain, enabled, comment)
                    VALUES ('other.example', 1, '')
                    """
                )

            result = worker.recalculate_static_ratings_in_db()

            with db.connect() as con:
                row = con.execute(
                    """
                    SELECT black, black_reason, s_rating, s_rating_reason, e_rating
                    FROM servers
                    WHERE raw_uri = ?
                    """,
                    (raw_uri,),
                ).fetchone()

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["bad"], 0)
        self.assertEqual(result["candidate"], 1)
        self.assertEqual(result["low_rating"], 0)
        self.assertEqual(result["medium_rating"], 0)
        self.assertEqual(result["high_rating"], 0)
        self.assertEqual(result["top_rating"], 1)
        self.assertEqual(row[0], 0)
        self.assertGreater(row[2], 80)
        self.assertEqual(row[1] or "", "")
        self.assertIn("CANDIDATE:", row[3])
        self.assertEqual(row[4], 123)

    def test_whitelist_full_success_columns_are_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "wl.db")
            worker = VPNWorker(db)
            worker.ensure_schema()

            with db.connect() as con:
                columns = {
                    row[1]
                    for row in con.execute("PRAGMA table_info(servers)").fetchall()
                }

        self.assertIn("whitelist_full_success", columns)
        self.assertIn("whitelist_full_success_count", columns)
        self.assertIn("whitelist_full_success_at", columns)
        self.assertIn("whitelist_full_success_note", columns)

    def test_mark_whitelist_full_success_updates_existing_server_only(self):
        raw_uri = (
            "vless://uuid@example.com:443?"
            "security=reality&type=raw&sni=example.com&"
            "flow=xtls-rprx-vision&fp=edge&pbk=key&sid=abcd&spx=/"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "wl.db")
            worker = VPNWorker(db)
            worker.ensure_schema()

            self.assertFalse(
                worker.mark_whitelist_full_success(
                    "vless://paid.example.com:443?security=reality",
                    "paid sample must not be inserted",
                )
            )

            server = worker.parse_server(raw_uri, source_subscribe_id=None)
            self.assertIsNotNone(server)
            worker.classify_and_rate(server, {"example.com"})
            worker.save_servers([server])

            self.assertTrue(worker.mark_whitelist_full_success(raw_uri, "manual test"))
            self.assertTrue(worker.mark_whitelist_full_success(raw_uri, "second pass"))

            with db.connect() as con:
                total = con.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
                row = con.execute(
                    """
                    SELECT
                        whitelist_full_success,
                        whitelist_full_success_count,
                        whitelist_full_success_at,
                        whitelist_full_success_note
                    FROM servers
                    WHERE raw_uri = ?
                    """,
                    (raw_uri,),
                ).fetchone()

        self.assertEqual(total, 1)
        self.assertEqual(row[0], 1)
        self.assertEqual(row[1], 2)
        self.assertTrue(row[2])
        self.assertEqual(row[3], "second pass")

    def test_ready_export_writes_ten_files_with_999_rows_and_names(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "wl.db")
            worker = VPNWorker(db)
            worker.ensure_schema()

            now = "2026-06-06T12:00:00"
            rows = [
                (
                    "vless",
                    "best.example.com",
                    443,
                    "vless://uuid@best.example.com:443?security=reality&sni=example.com#old",
                    10,
                    1,
                    0,
                    99,
                    "CANDIDATE: test",
                    7,
                    123,
                    now,
                    now,
                )
            ]

            for index in range(999):
                rows.append(
                    (
                        "vless",
                        f"server{index}.example.com",
                        443,
                        f"vless://uuid{index}@server{index}.example.com:443?security=tls&sni=example.com#old",
                        1,
                        1,
                        0,
                        1,
                        "CANDIDATE: test",
                        0,
                        None,
                        now,
                        now,
                    )
                )

            with db.connect() as con:
                con.executemany(
                    """
                    INSERT INTO servers (
                        protocol,
                        host,
                        port,
                        raw_uri,
                        found_count,
                        active,
                        black,
                        s_rating,
                        s_rating_reason,
                        e_rating,
                        e_last_latency_ms,
                        added_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

            export_dir = Path(tmpdir) / "Ready"
            result = worker.export_ready_top_servers(export_dir)

            self.assertEqual(result["files"], 10)
            self.assertEqual(result["rows"], 1000)
            self.assertEqual(result["all_rows"], 1000)

            paths = [
                export_dir / f"FB-White-{index:02d}.txt"
                for index in range(1, 11)
            ]
            self.assertTrue(all(path.exists() for path in paths))

            all_lines = (export_dir / "FB-White-All.txt").read_text(
                encoding="utf-8"
            ).splitlines()
            first_lines = paths[0].read_text(encoding="utf-8").splitlines()
            second_lines = paths[1].read_text(encoding="utf-8").splitlines()

            self.assertEqual(len(all_lines), 1000)
            self.assertEqual(len(first_lines), 999)
            self.assertEqual(len(second_lines), 1)
            self.assertEqual(all_lines[0], first_lines[0])
            self.assertTrue(first_lines[0].endswith("#FB-s99e07-[123ms]"))
            self.assertIn("#FB-s01e00-[???ms]", first_lines[1])

            for path in paths[2:]:
                self.assertEqual(path.read_text(encoding="utf-8"), "")

    def test_ready_export_rewrites_vmess_ps(self):
        worker = VPNWorker(db=None)
        payload = worker.b64encode_text(
            json.dumps(
                {
                    "v": "2",
                    "ps": "old-name",
                    "add": "example.com",
                    "port": "443",
                },
                separators=(",", ":"),
            )
        )

        renamed = worker.replace_server_name_for_export(
            f"vmess://{payload}",
            "FB-s99e00-[???ms]",
        )
        decoded = worker.b64decode_any(renamed.split("://", 1)[1])
        self.assertIsNotNone(decoded)

        data = json.loads(decoded.decode("utf-8"))
        self.assertEqual(data["ps"], "FB-s99e00-[???ms]")

    def test_extended_rating_schema_has_static_filter_columns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Database(Path(tmpdir) / "wl.db")
            worker = ExtendedRatingWorker(db, NetworkStatus.FREE_INTERNET)
            worker.ensure_schema()

            self.assertEqual(worker.fetch_servers(), [])


if __name__ == "__main__":
    unittest.main()
