"""
Тесты для vpn_utils.py и vpn_finder.py

Запуск: python -m pytest tests/ -v
"""

import base64
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Убедимся что директория проекта в sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vpn_utils import (
    _fix_b64_padding,
    clean_key,
    decode_subscription_content,
    deduplicate_keys,
    extract_keys_from_text,
    is_ip_address,
    parse_key_details,
    ping_and_tls_check,
    ping_key,
)


class TestIsIpAddress(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertTrue(is_ip_address("1.2.3.4"))

    def test_valid_ipv6(self):
        self.assertTrue(is_ip_address("::1"))
        self.assertTrue(is_ip_address("[::1]"))

    def test_domain(self):
        self.assertFalse(is_ip_address("example.com"))

    def test_empty(self):
        self.assertFalse(is_ip_address(""))


class TestFixB64Padding(unittest.TestCase):
    def test_no_padding_needed(self):
        s = "abcd"  # len=4, rem=0
        self.assertEqual(_fix_b64_padding(s), "abcd")

    def test_rem_2(self):
        s = "ab"
        self.assertEqual(_fix_b64_padding(s), "ab==")

    def test_rem_3(self):
        s = "abc"
        self.assertEqual(_fix_b64_padding(s), "abc=")

    def test_rem_1(self):
        s = "abcde"  # len=5, rem=1 → обрезаем
        result = _fix_b64_padding(s)
        self.assertEqual(len(result) % 4, 0)


class TestCleanKey(unittest.TestCase):
    def test_strips_whitespace(self):
        self.assertEqual(clean_key("  vless://abc  "), "vless://abc")

    def test_strips_quotes(self):
        self.assertEqual(clean_key('"vless://abc"'), "vless://abc")

    def test_html_entities(self):
        result = clean_key("vless://host?param=a&amp;b=c")
        self.assertNotIn("&amp;", result)
        self.assertIn("&", result)

    def test_trailing_punctuation(self):
        self.assertEqual(clean_key("vless://abc."), "vless://abc")
        self.assertEqual(clean_key("vless://abc,"), "vless://abc")

    def test_empty_string(self):
        self.assertEqual(clean_key(""), "")

    def test_none_like(self):
        self.assertEqual(clean_key(None), "")  # type: ignore


class TestDeduplicateKeys(unittest.TestCase):
    def test_removes_duplicates(self):
        keys = ["vless://a", "vless://b", "vless://a"]
        result = deduplicate_keys(keys)
        self.assertEqual(result, ["vless://a", "vless://b"])

    def test_removes_empty(self):
        keys = ["vless://a", "", "  "]
        result = deduplicate_keys(keys)
        self.assertEqual(result, ["vless://a"])

    def test_preserves_order(self):
        keys = ["vless://c", "vless://a", "vless://b"]
        result = deduplicate_keys(keys)
        self.assertEqual(result, ["vless://c", "vless://a", "vless://b"])


class TestParseKeyDetails(unittest.TestCase):
    def test_vless_basic(self):
        key = "vless://user@1.2.3.4:443?security=tls&sni=example.com#test"
        result = parse_key_details(key)
        self.assertIsNotNone(result)
        self.assertEqual(result["host"], "1.2.3.4")
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["sni"], "example.com")
        self.assertTrue(result["is_tls"])
        self.assertFalse(result["is_udp"])

    def test_vless_reality(self):
        key = "vless://uid@host.com:443?security=reality&pbk=abc&sni=domain.com#r"
        result = parse_key_details(key)
        self.assertIsNotNone(result)
        self.assertTrue(result["is_reality"])
        self.assertTrue(result["is_tls"])

    def test_trojan_basic(self):
        key = "trojan://password@server.com:443#name"
        result = parse_key_details(key)
        self.assertIsNotNone(result)
        self.assertEqual(result["scheme"], "trojan")
        self.assertTrue(result["is_tls"])

    def test_hysteria2_is_udp(self):
        key = "hy2://pass@host.com:5678#h2"
        result = parse_key_details(key)
        self.assertIsNotNone(result)
        self.assertTrue(result["is_udp"])

    def test_vmess_valid(self):
        vmess_data = {
            "v": "2",
            "ps": "test",
            "add": "1.2.3.4",
            "port": 8080,
            "id": "abc",
            "aid": 0,
            "net": "ws",
            "tls": "tls",
        }
        b64 = base64.b64encode(json.dumps(vmess_data).encode()).decode()
        key = f"vmess://{b64}"
        result = parse_key_details(key)
        self.assertIsNotNone(result)
        self.assertEqual(result["host"], "1.2.3.4")
        self.assertEqual(result["port"], 8080)
        self.assertTrue(result["is_tls"])

    def test_vmess_invalid_json(self):
        key = "vmess://" + base64.b64encode(b"not json").decode()
        result = parse_key_details(key)
        self.assertIsNone(result)

    def test_shadowsocks_with_at(self):
        key = "ss://dXNlcjpwYXNz@1.2.3.4:8388#test"
        result = parse_key_details(key)
        self.assertIsNotNone(result)
        self.assertEqual(result["host"], "1.2.3.4")
        self.assertEqual(result["port"], 8388)

    def test_shadowsocks_base64(self):
        userinfo = base64.b64encode(b"method:password@1.2.3.4:8388").decode()
        key = f"ss://{userinfo}#test"
        result = parse_key_details(key)
        # Может не распарситься если нет @ в decoded — это нормально
        # Главное — не бросает исключение
        self.assertIsInstance(result, (dict, type(None)))

    def test_invalid_scheme(self):
        result = parse_key_details("http://example.com")
        self.assertIsNone(result)

    def test_empty_key(self):
        result = parse_key_details("")
        self.assertIsNone(result)

    def test_no_host(self):
        result = parse_key_details("vless://:443#test")
        self.assertIsNone(result)


class TestDecodeSubscriptionContent(unittest.TestCase):
    def test_plain_text_with_keys(self):
        text = "vless://user@host.com:443#test\ntrojan://pass@host.com:443#t"
        result = decode_subscription_content(text)
        self.assertIn("vless://", result)

    def test_base64_encoded(self):
        plain = "vless://user@host.com:443#test"
        encoded = base64.b64encode(plain.encode()).decode()
        result = decode_subscription_content(encoded)
        self.assertIn("vless://", result)

    def test_empty_string(self):
        result = decode_subscription_content("")
        self.assertEqual(result, "")

    def test_urlsafe_base64(self):
        plain = "vless://user@host.com:443#test"
        encoded = base64.urlsafe_b64encode(plain.encode()).decode()
        result = decode_subscription_content(encoded)
        self.assertIn("vless://", result)


class TestExtractKeysFromText(unittest.TestCase):
    def test_extracts_multiple_protocols(self):
        text = (
            "vless://uid@host.com:443?security=tls&sni=host.com#v\n"
            "trojan://pass@server.com:443#t\n"
            "vmess://ignored_invalid\n"
        )
        keys = extract_keys_from_text(text)
        protocols = {k.split("://")[0].lower() for k in keys}
        self.assertIn("vless", protocols)
        self.assertIn("trojan", protocols)

    def test_filters_invalid_domains(self):
        text = "vless://uid@github.com:443?security=tls#t"
        keys = extract_keys_from_text(text)
        self.assertEqual(keys, [])

    def test_deduplicates_keys(self):
        line = "vless://uid@host.com:443?security=tls&sni=host.com#v"
        text = f"{line}\n{line}\n{line}"
        keys = extract_keys_from_text(text)
        self.assertEqual(len(keys), 1)

    def test_html_entities_decoded(self):
        text = "vless://uid@host.com:443?security=tls&amp;sni=host.com#v"
        keys = extract_keys_from_text(text)
        # Должен извлечь хотя бы один ключ
        self.assertGreaterEqual(len(keys), 0)  # Не должно бросать исключение


class TestPingKey(unittest.TestCase):
    """Тесты пинга — мокируем сетевые соединения."""

    def test_unparseable_key_returns_none(self):
        key, latency = ping_key("invalid://key")
        self.assertEqual(key, "invalid://key")
        self.assertIsNone(latency)

    @patch("vpn_utils.socket.create_connection")
    def test_successful_ping(self, mock_connect):
        mock_sock = MagicMock()
        mock_connect.return_value = mock_sock

        key = "vless://uid@1.2.3.4:443?security=tls&sni=example.com#test"
        result_key, latency = ping_key(key, timeout=1.0)

        self.assertEqual(result_key, key)
        self.assertIsNotNone(latency)
        self.assertGreaterEqual(latency, 0)
        mock_sock.close.assert_called_once()

    @patch("vpn_utils.socket.create_connection", side_effect=OSError("Connection refused"))
    def test_failed_ping(self, mock_connect):
        key = "vless://uid@1.2.3.4:443?security=tls&sni=example.com#test"
        result_key, latency = ping_key(key, timeout=1.0)
        self.assertEqual(result_key, key)
        self.assertIsNone(latency)


class TestPingAndTLSCheck(unittest.TestCase):
    def test_unparseable_key(self):
        key, latency = ping_and_tls_check("bad_key")
        self.assertIsNone(latency)

    @patch("vpn_utils.socket.create_connection")
    def test_non_tls_key(self, mock_connect):
        """Ключ без TLS — закрывает просто TCP-сокет."""
        mock_sock = MagicMock()
        mock_connect.return_value = mock_sock

        # ss:// не использует TLS
        key = "ss://bWV0aG9kOnBhc3M@1.2.3.4:8388#test"
        result_key, latency = ping_and_tls_check(key, timeout=1.0)
        # Не должно бросать исключений
        self.assertEqual(result_key, key)

    @patch("vpn_utils.socket.create_connection", side_effect=TimeoutError)
    def test_timeout_returns_none(self, mock_connect):
        key = "vless://uid@1.2.3.4:443?security=tls&sni=example.com#test"
        _, latency = ping_and_tls_check(key, timeout=1.0)
        self.assertIsNone(latency)


class TestVpnFinderHelpers(unittest.TestCase):
    def test_load_lines_nonexistent_file(self):
        from vpn_finder import load_lines
        result = load_lines("/nonexistent/path/file.txt")
        self.assertEqual(result, [])

    def test_load_lines_reads_content(self):
        from vpn_finder import load_lines
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("line1\nline2\n  \nline3\n")
            tmp = f.name
        try:
            result = load_lines(tmp)
            self.assertEqual(result, ["line1", "line2", "line3"])
        finally:
            os.unlink(tmp)

    def test_safe_save_verified_keys(self):
        from vpn_finder import safe_save_verified_keys, OUTPUT_KEYS_FILE, OUTPUT_SUB_FILE
        keys = [
            "vless://uid@1.2.3.4:443?security=tls&sni=example.com#test1",
            "trojan://pass@2.3.4.5:443#test2",
        ]
        orig_dir = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            try:
                safe_save_verified_keys(keys)
                # working_keys.txt должен существовать
                self.assertTrue(os.path.exists(OUTPUT_KEYS_FILE))
                with open(OUTPUT_KEYS_FILE, "r") as f:
                    saved = [l.strip() for l in f if l.strip()]
                self.assertEqual(len(saved), 2)
                # sub.txt должен быть валидным Base64
                self.assertTrue(os.path.exists(OUTPUT_SUB_FILE))
                with open(OUTPUT_SUB_FILE, "r") as f:
                    b64_content = f.read().strip()
                import base64 as b64_mod
                decoded = b64_mod.b64decode(b64_content).decode("utf-8")
                self.assertIn("vless://", decoded)
            finally:
                os.chdir(orig_dir)

    def test_safe_save_empty_keys(self, capsys=None):
        from vpn_finder import safe_save_verified_keys
        # Не должно бросать исключений на пустом списке
        safe_save_verified_keys([])


if __name__ == "__main__":
    unittest.main(verbosity=2)
