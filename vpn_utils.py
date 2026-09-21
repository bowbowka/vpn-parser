import base64
import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlparse

import requests

VPN_PROTOCOLS_REGEX = re.compile(
    r'(?<![a-zA-Z0-9])(?:vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic)://[^\s<"\'`]+',
    re.IGNORECASE
)

SUPPORTED_SCHEMES = {'vless', 'vmess', 'trojan', 'ss', 'ssr', 'hy2', 'hysteria2', 'tuic'}

BLOCKED_HOSTS = {
    'discord.gg', 'discord.com', 'discordapp.com', 'discord.snapshot.org',
    'twitter.com', 'x.com', 'apple.com', 'apps.apple.com', 'play.google.com',
    't.me', 'telegram.org', 'github.com', 'raw.githubusercontent.com', 'localhost', '127.0.0.1'
}

DEFAULT_HEADERS = {
    "User-Agent": "v2rayTun/1.0.0 (Android; v2rayN)",
    "Accept": "*/*"
}


def clean_key(raw_key: str) -> str:
    """Очищает ключ от мусорных знаков препинания на концах."""
    if not raw_key:
        return ""
    return raw_key.strip().rstrip('.,;:)]}\'"`>')


def decode_subscription_content(raw_text: str) -> str:
    """
    Интеллектуальное декодирование подписки:
    Поддерживает plain-text, стандартный Base64, URL-Safe Base64,
    а также многострочный Base64 с переносами строк (\r, \n).
    """
    if not raw_text:
        return ""

    text = raw_text.strip()
    # Если уже содержит протоколы в открытом виде
    if any(p in text.lower() for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hy2://', 'tuic://']):
        return text

    cleaned = re.sub(r'[\s\r\n\t]+', '', text)
    missing_padding = (-len(cleaned)) % 4
    padded = cleaned + ('=' * missing_padding)

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded.encode('ascii', errors='ignore')).decode('utf-8', errors='ignore')
            if any(p in decoded.lower() for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hy2://', 'tuic://']):
                return decoded
        except Exception:
            continue

    return text


def extract_keys_from_text(text: str) -> list[str]:
    """Извлекает и фильтрует сырые VPN-ключи из текста."""
    decoded = decode_subscription_content(text)
    raw_matches = VPN_PROTOCOLS_REGEX.findall(decoded)
    valid_keys = []
    seen = set()

    for k in raw_matches:
        ck = clean_key(k)
        if len(ck) < 15 or ck in seen:
            continue
        # Быстрая валидация схемы
        scheme = ck.split("://", 1)[0].lower()
        if scheme not in SUPPORTED_SCHEMES:
            continue
        seen.add(ck)
        valid_keys.append(ck)

    return valid_keys


def parse_key_details(key: str) -> dict | None:
    """
    Универсальный парсер параметров VPN-ключа:
    Возвращает словарь {scheme, host, port, sni, is_tls, is_udp} или None при ошибке.
    """
    try:
        ck = clean_key(key)
        if "://" not in ck:
            return None
        scheme, rest = ck.split("://", 1)
        scheme = scheme.lower()
        if scheme not in SUPPORTED_SCHEMES:
            return None

        # 1. VMess (Base64 JSON)
        if scheme == "vmess":
            b64_str = rest.split('#')[0].split('?')[0]
            b64_str = re.sub(r'\s+', '', b64_str)
            b64_str += '=' * ((-len(b64_str)) % 4)
            data = json.loads(base64.b64decode(b64_str).decode('utf-8', errors='ignore'))
            host = data.get('add') or data.get('host')
            if not host:
                return None
            host = str(host).strip('[]')
            if host.lower() in BLOCKED_HOSTS:
                return None
            port = int(data.get('port', 443))
            sni = data.get('sni') or data.get('host') or host
            tls_val = str(data.get('tls', '')).lower()
            is_tls = tls_val in ['tls', 'reality'] or port == 443
            return {
                'scheme': 'vmess',
                'host': host,
                'port': port,
                'sni': str(sni).strip('[]') if sni else host,
                'is_tls': is_tls,
                'is_udp': False
            }

        # 2. Shadowsocks
        elif scheme == "ss":
            body = rest.split('#')[0]
            if "@" in body:
                # SIP002 формат
                user_info, host_port_params = body.split("@", 1)
                hp = host_port_params.split("/")[0].split("?")[0]
                if ":" in hp:
                    if hp.startswith("["):
                        host = hp.split("]")[0].lstrip("[")
                        port = int(hp.split("]")[-1].lstrip(":"))
                    else:
                        host, port_str = hp.rsplit(":", 1)
                        port = int(port_str)
                else:
                    return None
            else:
                # Полный base64
                b64_part = body.split("?")[0].split("/")[0]
                b64_part = re.sub(r'\s+', '', b64_part)
                b64_part += '=' * ((-len(b64_part)) % 4)
                decoded = base64.b64decode(b64_part).decode('utf-8', errors='ignore')
                hp = decoded.split("@")[-1] if "@" in decoded else decoded
                hp = hp.split("/")[0].split("?")[0]
                if ":" in hp:
                    host, port_str = hp.rsplit(":", 1)
                    port = int(port_str)
                else:
                    return None

            host = host.strip('[]')
            if host.lower() in BLOCKED_HOSTS:
                return None
            return {
                'scheme': 'ss',
                'host': host,
                'port': port,
                'sni': host,
                'is_tls': False,
                'is_udp': False
            }

        # 3. VLESS, Trojan, Hysteria2, Hy2, TUIC, SSR
        else:
            parsed = urlparse(ck)
            query = parse_qs(parsed.query)
            host = parsed.hostname
            if not host or host.lower() in BLOCKED_HOSTS:
                return None

            is_udp = scheme in ['hy2', 'hysteria2', 'tuic']
            default_port = 443 if scheme in ['vless', 'trojan', 'hy2', 'hysteria2', 'tuic'] else 8388
            port = parsed.port or default_port

            sni_list = query.get('sni') or query.get('host')
            sni = sni_list[0] if sni_list else host

            security = query.get('security', [''])[0].lower()
            is_tls = security in ['tls', 'reality'] or scheme in ['hy2', 'hysteria2', 'trojan'] or port == 443

            return {
                'scheme': scheme,
                'host': host,
                'port': port,
                'sni': sni,
                'is_tls': is_tls,
                'is_udp': is_udp
            }

    except Exception:
        pass

    return None


def fetch_keys_from_sub(url: str, timeout: float = 8.0) -> list[str]:
    """Загружает URL подписки и извлекает VPN-ключи."""
    try:
        res = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        if res.status_code != 200 or not res.text.strip():
            return []
        return extract_keys_from_text(res.text)
    except Exception:
        return []


def fetch_all_subs_parallel(urls: list[str], max_workers: int = 30, timeout: float = 8.0) -> dict[str, list[str]]:
    """
    Параллельно загружает все подписки из списка URL.
    Возвращает словарь {url: [ключи...]}.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(fetch_keys_from_sub, u, timeout): u for u in urls}
        for future in as_completed(future_to_url):
            u = future_to_url[future]
            try:
                keys = future.result()
                results[u] = keys
            except Exception:
                results[u] = []
    return results


def is_ip_address(addr: str) -> bool:
    """Проверяет, является ли строка IPv4 или IPv6 адресом."""
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except (socket.error, AttributeError):
        pass
    return False


def ping_key(key: str, timeout: float = 2.5) -> tuple[str, float | None]:
    """
    Проверяет доступность сервера ключа:
    - TCP соединение для VLESS, VMess, Trojan, SS
    - Проверка сокета/DNS для UDP протоколов (Hysteria2, TUIC)
    """
    details = parse_key_details(key)
    if not details:
        return key, None

    host = details['host']
    port = details['port']
    is_udp = details['is_udp']

    start_time = time.perf_counter()
    try:
        if is_udp:
            # Для UDP протоколов (Hysteria2/TUIC)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.connect((host, port))
                latency = (time.perf_counter() - start_time) * 1000
                return key, round(latency, 1)
            finally:
                sock.close()
        else:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            latency = (time.perf_counter() - start_time) * 1000
            return key, round(latency, 1)
    except Exception:
        return key, None


def ping_and_tls_check(key: str, timeout: float = 3.0) -> tuple[str, float | None]:
    """
    Проверяет TCP соединение и TLS рукопожатие с SNI.
    Отсеивает Cloudflare-заглушки и мертвые ноды.
    """
    details = parse_key_details(key)
    if not details:
        return key, None

    host = details['host']
    port = details['port']
    sni = details['sni']
    is_tls = details['is_tls']
    is_udp = details['is_udp']

    start_time = time.perf_counter()

    if is_udp:
        # Hysteria2 / TUIC работают по UDP, TLS handshake проверяется через UDP connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            latency = (time.perf_counter() - start_time) * 1000
            return key, round(latency, 1)
        except Exception:
            return key, None
        finally:
            sock.close()

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)

        if is_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # RFC 6066: SNI server_hostname не должен быть IP-адресом
            server_hostname = None
            candidate = sni if sni else host
            if candidate and not is_ip_address(candidate):
                server_hostname = candidate

            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                latency = (time.perf_counter() - start_time) * 1000
                return key, round(latency, 1)
        else:
            latency = (time.perf_counter() - start_time) * 1000
            return key, round(latency, 1)

    except Exception:
        return key, None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
