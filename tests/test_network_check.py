import unittest
from unittest.mock import patch

from white_list_monitor.network_check import detect_network_status
from white_list_monitor.settings_store import AppSettings
from white_list_monitor.status import NetworkStatus


class NetworkCheckTest(unittest.TestCase):
    def detect_with_http(self, ok_urls: set[str], router_ok: bool = True):
        settings = AppSettings()

        with patch(
            "white_list_monitor.network_check.ping_check",
            return_value=router_ok,
        ), patch(
            "white_list_monitor.network_check.http_check",
            side_effect=lambda url, timeout: url in ok_urls,
        ) as http_mock:
            result = detect_network_status(settings)

        return result, http_mock

    def test_whitelist_mode_when_allowed_domain_responds_and_open_domains_do_not(self):
        result, _ = self.detect_with_http({"http://vk.com"})

        self.assertEqual(result.status, NetworkStatus.WHITELIST_MODE)
        self.assertTrue(result.whitelist_http_ok)
        self.assertFalse(result.open_internet_http_ok)
        self.assertEqual(result.whitelist_ok_urls, ("http://vk.com",))
        self.assertEqual(result.open_internet_ok_urls, ())

    def test_free_internet_when_any_open_domain_responds(self):
        result, _ = self.detect_with_http({"http://ya.ru", "http://rsload.net"})

        self.assertEqual(result.status, NetworkStatus.FREE_INTERNET)
        self.assertTrue(result.whitelist_http_ok)
        self.assertTrue(result.open_internet_http_ok)
        self.assertEqual(result.open_internet_ok_urls, ("http://rsload.net",))

    def test_no_internet_when_router_responds_but_http_groups_do_not(self):
        result, _ = self.detect_with_http(set())

        self.assertEqual(result.status, NetworkStatus.NO_INTERNET)
        self.assertFalse(result.whitelist_http_ok)
        self.assertFalse(result.open_internet_http_ok)
        self.assertTrue(result.router_ping_ok)

    def test_router_down_keeps_existing_behavior(self):
        result, http_mock = self.detect_with_http({"http://vk.com"}, router_ok=False)

        self.assertEqual(result.status, NetworkStatus.ROUTER_DOWN)
        self.assertFalse(result.router_ping_ok)
        http_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
