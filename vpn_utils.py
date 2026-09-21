import base64
import html
import io
import json
import os
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

# Регулярное выражение поиска ссылок (non-capturing group для схемы)
VPN_PROTOCOLS_REGEX = re.compile(
    r"(?<![a-zA-Z0-9])(?:vless|vmess|trojan|ss|ssr|tuic|hy2|hysteria2)://[^\s<>\"\'`\\]+",
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
    if not host:
        return False
    host = host.strip("[]")
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (socket.error, AttributeError):
        pass
    return False


def clean_key(key: str) -> str:
    """
    Очищает VPN-ключ от мусора, кавычек, HTML-сущностей (&amp; -> &, &quot; -> ", и т.д.)
    и знаков пунктуации на конце.
    """
    if not key:
        return ""

    key = key.strip().strip("'\"`<>")

    # Многократная очистка HTML-сущностей (&amp;amp; -> &)
    for _ in range(3):
        unescaped = html.unescape(key)
        unescaped = unescaped.replace("&amp;", "&").replace("\\/", "/")
        if unescaped == key:
            break
        key = unescaped

    # Удаляем мусорные знаки препинания и закрывающие скобки на концах URL
    key = re.sub(r"[\.,;:!\)\]\>\}\'\"]+$", "", key.strip())
    return key


def decode_subscription_content(raw_text: str) -> str:
    """Безопасно декодирует тело подписки (Base64 или чистый текст)."""
    text = raw_text.strip()
    if not text:
        return ""

    if re.search(VPN_PROTOCOLS_REGEX, text):
        return text

    # Очищаем от пробельных символов и BOM
    clean_b64 = re.sub(r"[\s\r\n\t\ufeff]+", "", text)
    if len(clean_b64) >= 8:
        rem = len(clean_b64) % 4
        if rem == 1:
            clean_b64 = clean_b64[:-1]
        elif rem == 2:
            clean_b64 += "=="
        elif rem == 3:
            clean_b64 += "="

        for decoder in [base64.b64decode, base64.urlsafe_b64decode]:
            try:
                decoded = decoder(clean_b64.encode("utf-8", errors="ignore")).decode("utf-8", errors="ignore")
                if re.search(VPN_PROTOCOLS_REGEX, decoded):
                    return decoded
            except Exception:
                continue

    return raw_text


def extract_keys_from_text(text: str) -> list[str]:
    """Извлекает и очищает все VPN-ключи из переданного текста."""
    text = html.unescape(text)
    decoded_text = decode_subscription_content(text)

    valid_keys = []
    seen = set()

    for match in VPN_PROTOCOLS_REGEX.finditer(decoded_text):
        ck = clean_key(match.group(0))
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
    и извлекает host, port, sni, protocol, is_tls, is_udp.
    """
    try:
        key = clean_key(key)
        if "://" not in key:
            return None

        scheme, rest = key.split("://", 1)
        scheme = scheme.lower()

        if scheme in ("vless", "trojan", "hy2", "hysteria2", "tuic"):
            parsed = urllib.parse.urlparse(key)
            host = parsed.hostname
            if not host:
                return None

            port = parsed.port or (443 if scheme in ("vless", "trojan", "hy2", "hysteria2", "tuic") else 80)

            query_params = urllib.parse.parse_qs(parsed.query)
            sni = None
            for sni_field in ["sni", "peer", "host", "serverName"]:
                if sni_field in query_params:
                    sni = query_params[sni_field][0]
                    break

            security = query_params.get("security", [""])[0].lower()
            is_reality = security == "reality" or "reality" in parsed.query.lower() or "pbk" in query_params
            is_udp = scheme in ("hy2", "hysteria2", "tuic")
            is_tls = scheme == "trojan" or is_reality or security == "tls" or query_params.get("tls", [""])[0] in ("1", "true") or port == 443

            return {
                "scheme": scheme,
                "host": host,
                "port": port,
                "sni": sni or host,
                "is_udp": is_udp,
                "is_reality": is_reality,
                "is_tls": is_tls,
            }

        elif scheme == "vmess":
            # VMess URL: vmess://BASE64_JSON[#remark]
            # Не используем urlparse, чтобы слэши в base64 не обрезали payload!
            b64_payload = rest.split("#")[0].split("?")[0].strip()
            rem = len(b64_payload) % 4
            if rem == 2:
                b64_payload += "=="
            elif rem == 3:
                b64_payload += "="
            elif rem == 1:
                b64_payload = b64_payload[:-1]

            decoded_json = None
            for decoder in [base64.b64decode, base64.urlsafe_b64decode]:
                try:
                    decoded_json = decoder(b64_payload.encode("utf-8", errors="ignore")).decode("utf-8", errors="ignore")
                    break
                except Exception:
                    continue

            if not decoded_json:
                return None

            data = json.loads(decoded_json)
            if not isinstance(data, dict):
                return None

            host = str(data.get("add") or data.get("host") or "").strip("[]")
            try:
                port = int(data.get("port", 0))
            except (ValueError, TypeError):
                port = 0

            if not host or not port:
                return None

            sni = str(data.get("sni") or data.get("host") or host).strip("[]")
            tls_val = str(data.get("tls", "")).lower()
            is_tls = tls_val in ("tls", "1", "true") or port == 443

            return {
                "scheme": scheme,
                "host": host,
                "port": port,
                "sni": sni,
                "is_udp": False,
                "is_reality": False,
                "is_tls": is_tls,
            }

        elif scheme == "ss":
            body = rest.split("#")[0]
            if "@" in body:
                user_info, host_port = body.split("@", 1)
            else:
                b64_part = body.split("?")[0].split("/")[0].strip()
                rem = len(b64_part) % 4
                if rem == 2:
                    b64_part += "=="
                elif rem == 3:
                    b64_part += "="
                elif rem == 1:
                    b64_part = b64_part[:-1]

                decoded = None
                for decoder in [base64.b64decode, base64.urlsafe_b64decode]:
                    try:
                        decoded = decoder(b64_part.encode("utf-8", errors="ignore")).decode("utf-8", errors="ignore")
                        break
                    except Exception:
                        continue

                if not decoded or "@" not in decoded:
                    return None
                user_info, host_port = decoded.split("@", 1)

            hp = host_port.split("?")[0].split("/")[0]
            if hp.startswith("[") and "]" in hp:
                host = hp[1 : hp.index("]")]
                port_str = hp[hp.index("]") + 1 :].lstrip(":")
            else:
                parts = hp.split(":")
                host = parts[0]
                port_str = parts[1] if len(parts) > 1 else ""

            if not host or not port_str or not port_str.isdigit():
                return None

            return {
                "scheme": scheme,
                "host": host,
                "port": int(port_str),
                "sni": host,
                "is_udp": False,
                "is_reality": False,
                "is_tls": False,
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
    is_udp = details.get("is_udp", False)

    start = time.perf_counter()
    if is_udp:
        # Для UDP протоколов (Hysteria2/TUIC) пингуем хост через TCP connect на порт хоста или 443,
        # чтобы измерить РЕАЛЬНЫЙ RTT сети, а не получать ложные 0.1 мс от sendto
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            latency = round((time.perf_counter() - start) * 1000, 1)
            return key, latency
        except ConnectionRefusedError:
            # Хост доступен в сети и ответил RST
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
    is_udp = details.get("is_udp", False)
    is_tls = details.get("is_tls", False)

    if is_udp:
        return ping_key(key, timeout=timeout)

    start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)

        # Проводим TLS Handshake если протокол TLS/Reality/Trojan или указан SNI
        if is_tls or (sni and sni != host):
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
