import base64
import html
import io
import json
import re
import socket
import ssl
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import requests

DEFAULT_HEADERS = {
    "User-Agent": "v2rayN/6.23 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Accept": "*/*",
}

VPN_PROTOCOLS_REGEX = re.compile(
    r"(?<![a-zA-Z0-9])(vless|vmess|trojan|ss|ssr|tuic|hy2|hysteria2)://[^\s<>\"\'\\]+",
    re.IGNORECASE,
)

INVALID_DOMAINS = {
    "discord.gg",
    "apple.com",
    "apps.apple.com",
    "google.com",
    "play.google.com",
    "github.com",
    "raw.githubusercontent.com",
    "t.me",
    "telegram.org",
}


def is_ip_address(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except socket.error:
        pass
    return False


def clean_key(key: str) -> str:
    """Очищает VPN-ключ от мусора, кавычек, HTML-кодирования (&amp;) и пробелов."""
    if not key:
        return ""
    # Декодируем HTML-сущности (&amp; -> &, &quot; -> ", и т.д.)
    key = html.unescape(key)
    key = key.replace("&amp;", "&").replace("\\/", "/").strip().strip("'\"`<>")
    # Убираем возможные скобки в конце
    key = re.sub(r"[\)\]\>]+$", "", key)
    return key


def decode_subscription_content(raw_text: str) -> str:
    """Безопасно декодирует тело подписки (Base64 или чистый текст)."""
    text = raw_text.strip()
    if not text:
        return ""

    if re.search(VPN_PROTOCOLS_REGEX, text):
        return text

    clean_b64 = re.sub(r"[\s\r\n\t]+", "", text)
    if len(clean_b64) >= 8:
        missing_padding = len(clean_b64) % 4
        if missing_padding:
            clean_b64 += "=" * (4 - missing_padding)

        for decoder in [base64.b64decode, base64.urlsafe_b64decode]:
            try:
                decoded = decoder(clean_b64.encode("ascii")).decode("utf-8", errors="ignore")
                if re.search(VPN_PROTOCOLS_REGEX, decoded):
                    return decoded
            except Exception:
                continue

    return raw_text


def extract_keys_from_text(text: str) -> list[str]:
    """Извлекает и очищает все VPN-ключи из переданного текста."""
    text = html.unescape(text)
    decoded_text = decode_subscription_content(text)
    raw_keys = VPN_PROTOCOLS_REGEX.findall(decoded_text)

    full_matches = []
    for match in VPN_PROTOCOLS_REGEX.finditer(decoded_text):
        full_matches.append(match.group(0))

    valid_keys = []
    seen = set()

    for rk in full_matches:
        ck = clean_key(rk)
        if not ck or ck in seen:
            continue

        details = parse_key_details(ck)
        if not details or not details.get("host") or not details.get("port"):
            continue

        host_lower = details["host"].lower()
        if host_lower in INVALID_DOMAINS or host_lower.endswith(".json"):
            continue

        seen.add(ck)
        valid_keys.append(ck)

    return valid_keys


def parse_key_details(key: str) -> dict | None:
    """
    Разбирает VPN-ключ (VLESS, VMess, Trojan, Shadowsocks, Hysteria2)
    и извлекает host, port, sni, protocol.
    """
    try:
        key = clean_key(key)
        parsed = urllib.parse.urlparse(key)
        scheme = parsed.scheme.lower()

        if scheme in ("vless", "trojan", "hy2", "hysteria2", "tuic"):
            host = parsed.hostname
            port = parsed.port
            if not host or not port:
                return None

            query_params = urllib.parse.parse_qs(parsed.query)
            sni = None
            for sni_field in ["sni", "peer", "host", "serverName"]:
                if sni_field in query_params:
                    sni = query_params[sni_field][0]
                    break

            # Проверяем reality public key
            is_reality = "reality" in parsed.query.lower() or "pbk" in query_params

            return {
                "scheme": scheme,
                "host": host,
                "port": port,
                "sni": sni or host,
                "is_udp": scheme in ("hy2", "hysteria2", "tuic"),
                "is_reality": is_reality,
            }

        elif scheme == "vmess":
            b64_payload = parsed.netloc
            missing_padding = len(b64_payload) % 4
            if missing_padding:
                b64_payload += "=" * (4 - missing_padding)
            decoded_json = base64.b64decode(b64_payload.encode("utf-8")).decode("utf-8", errors="ignore")
            data = json.loads(decoded_json)

            host = data.get("add")
            port = int(data.get("port", 0))
            sni = data.get("sni") or data.get("host") or host
            if not host or not port:
                return None

            return {
                "scheme": scheme,
                "host": host,
                "port": port,
                "sni": sni,
                "is_udp": False,
                "is_reality": False,
            }

        elif scheme == "ss":
            netloc = parsed.netloc
            if "@" in netloc:
                user_info, host_port = netloc.split("@", 1)
            else:
                missing_padding = len(netloc) % 4
                if missing_padding:
                    netloc += "=" * (4 - missing_padding)
                try:
                    decoded = base64.b64decode(netloc.encode("utf-8")).decode("utf-8", errors="ignore")
                    if "@" in decoded:
                        user_info, host_port = decoded.split("@", 1)
                    else:
                        return None
                except Exception:
                    return None

            if host_port.startswith("[") and "]" in host_port:
                host = host_port[1 : host_port.index("]")]
                port_str = host_port[host_port.index("]") + 1 :].lstrip(":")
            else:
                parts = host_port.split(":")
                host = parts[0]
                port_str = parts[1] if len(parts) > 1 else ""

            port_str = port_str.split("?")[0].split("#")[0]
            if not host or not port_str or not port_str.isdigit():
                return None

            return {
                "scheme": scheme,
                "host": host,
                "port": int(port_str),
                "sni": host,
                "is_udp": False,
                "is_reality": False,
            }

    except Exception:
        return None

    return None


def fetch_keys_from_sub(url: str, timeout: float = 8.0) -> list[str]:
    try:
        resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout)
        if resp.status_code == 200 and resp.text:
            return extract_keys_from_text(resp.text)
    except Exception:
        pass
    return []


def fetch_all_subs_parallel(urls: list[str], max_workers: int = 30, timeout: float = 8.0) -> dict[str, list[str]]:
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(fetch_keys_from_sub, u, timeout): u for u in urls}
        for future in as_completed(future_to_url):
            u = future_to_url[future]
            try:
                keys = future.result()
                if keys:
                    results[u] = keys
            except Exception:
                pass
    return results


def ping_key(key: str, timeout: float = 2.0) -> tuple[str, float | None]:
    details = parse_key_details(key)
    if not details:
        return key, None

    host = details["host"]
    port = details["port"]
    is_udp = details["is_udp"]

    start = time.perf_counter()
    if is_udp:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00" * 16, (host, port))
            sock.close()
            latency = round((time.perf_counter() - start) * 1000, 1)
            return key, latency
        except Exception:
            return key, None

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        latency = round((time.perf_counter() - start) * 1000, 1)
        return key, latency
    except Exception:
        return key, None


def ping_and_tls_check(key: str, timeout: float = 2.0) -> tuple[str, float | None]:
    details = parse_key_details(key)
    if not details:
        return key, None

    host = details["host"]
    port = details["port"]
    sni = details.get("sni")
    is_udp = details["is_udp"]

    if is_udp:
        return ping_key(key, timeout=timeout)

    start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)

        # TLS проверка
        if port == 443 or (sni and sni != host):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            target_sni = sni if (sni and not is_ip_address(sni)) else None
            try:
                ssl_sock = context.wrap_socket(sock, server_hostname=target_sni)
                ssl_sock.close()
            except Exception:
                return key, None
        else:
            sock.close()

        latency = round((time.perf_counter() - start) * 1000, 1)
        return key, latency
    except Exception:
        return key, None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
