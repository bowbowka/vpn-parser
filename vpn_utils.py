import base64
import html
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

# Регулярное выражение поиска ссылок (предотвращает склеивание соседних ссылок)
VPN_PROTOCOLS_REGEX = re.compile(
    r"(?<![a-zA-Z0-9])(?:vless|vmess|trojan|ss|ssr|tuic|hy2|hysteria2)://(?:(?!(?:vless|vmess|trojan|ss|ssr|tuic|hy2|hysteria2)://)[^\s<>\"'`\\])+",
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
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
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
    key = re.sub(r"[\.,;:!\)\]>\'\"]+$", "", key.strip())
    # Заменяем пустой fp= на безопасный firefox
    key = key.replace("fp=&", "fp=firefox&").replace("fp=#", "fp=firefox#")
    return key


BLOCKED_SNI_KEYWORDS = [
    "rkn", "fuck", ".ir", "navalny",
    "cloudflare.com", ".cf", "cf-",
]

BLOCKED_HOST_PREFIXES = ["169.40.", "169.41."]
ALLOWED_PORTS = {443, 8443, 2053, 2083, 2087, 2096}


def is_sni_allowed(sni: str) -> bool:
    """Проверяет, не заблокирован ли SNI в РФ цензурными стоп-словами или TSPU."""
    if not sni:
        return True
    sl = sni.lower()
    return not any(kw in sl for kw in BLOCKED_SNI_KEYWORDS)


def is_host_allowed(host: str) -> bool:
    """Проверяет хост на принадлежность к заблокированным датацентрам и стоп-словам."""
    if not host:
        return False
    hl = host.lower()
    if any(hl.startswith(p) for p in BLOCKED_HOST_PREFIXES):
        return False
    if "cloudflare" in hl:
        return False
    return is_sni_allowed(hl)


def get_host_subnet(host: str) -> str:
    """Возвращает /24 подсеть для IPv4 или домен."""
    if is_ip_address(host):
        parts = host.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3])
    return host.lower()


def deduplicate_keys(keys: list[str]) -> list[str]:
    """Дедупликация: очищает ключи и убирает дубликаты, сохраняя порядок."""
    seen: set[str] = set()
    result: list[str] = []
    for k in keys:
        ck = clean_key(k)
        if ck and ck not in seen:
            seen.add(ck)
            result.append(ck)
    return result


def filter_and_diversify_keys(keys: list[str], max_per_subnet: int = 2) -> list[str]:
    """
    Фильтрует заблокированные в РФ SNI, нестандартные порты и ограничивает дубликаты подсетей,
    чтобы один хостер или спам-сервер не забивал всю подписку одинаковыми узлами.
    """
    subnet_count: dict[str, int] = {}
    seen_identities: set[tuple[str, int, str]] = set()
    result: list[str] = []

    for k in keys:
        d = parse_key_details(k)
        if not d:
            continue
        sni = (d.get("sni") or "").lower()
        host = (d.get("host") or "").lower()
        port = d.get("port")

        # Разрешаем только стандартные HTTPS порты (нестандартные порты часто режутся ТСПУ)
        if port not in ALLOWED_PORTS:
            continue

        if not is_sni_allowed(sni) or not is_host_allowed(host):
            continue

        # Убираем дублирование одного и того же физического сервера с разными хештегами
        uuid = ""
        if "://" in k and "@" in k:
            uuid = k.split("://", 1)[1].split("@", 1)[0]
        ident = (host, port, uuid)
        if ident in seen_identities:
            continue

        sub = get_host_subnet(host)
        if subnet_count.get(sub, 0) >= max_per_subnet:
            continue

        seen_identities.add(ident)
        subnet_count[sub] = subnet_count.get(sub, 0) + 1
        result.append(k)

    return result


def _fix_b64_padding(s: str) -> str:
    """Добавляет правильный padding к Base64-строке."""
    rem = len(s) % 4
    if rem == 2:
        return s + "=="
    if rem == 3:
        return s + "="
    if rem == 1:
        # Невалидный Base64 — обрезаем лишний символ
        return s[:-1]
    return s


def decode_subscription_content(raw_text: str) -> str:
    """Безопасно декодирует тело подписки (Base64 или чистый текст)."""
    text = raw_text.strip()
    if not text:
        return ""

    # Если уже содержит VPN-ссылки — возвращаем as-is
    if re.search(VPN_PROTOCOLS_REGEX, text):
        return text

    # Очищаем от пробельных символов и BOM
    clean_b64 = re.sub(r"[\s\r\n\t\ufeff]+", "", text)
    if len(clean_b64) >= 8:
        clean_b64 = _fix_b64_padding(clean_b64)

        for decoder in [base64.b64decode, base64.urlsafe_b64decode]:
            try:
                decoded = decoder(clean_b64.encode("utf-8", errors="ignore")).decode(
                    "utf-8", errors="ignore"
                )
                if re.search(VPN_PROTOCOLS_REGEX, decoded):
                    return decoded
            except Exception:
                continue

    return raw_text


def extract_keys_from_text(text: str) -> list[str]:
    """Извлекает и очищает все VPN-ключи из переданного текста."""
    text = html.unescape(text)
    decoded_text = decode_subscription_content(text)

    valid_keys: list[str] = []
    seen: set[str] = set()

    for match in VPN_PROTOCOLS_REGEX.finditer(decoded_text):
        ck = clean_key(match.group(0))
        if not ck or ck in seen:
            continue

        # Защита от склеенных ссылок (если внутри тела ссылки снова встретилось ://)
        if "://" in ck.split("://", 1)[1]:
            continue

        details = parse_key_details(ck)
        if not details or not details.get("host") or not details.get("port"):
            continue

        host_lower = details["host"].lower()
        if host_lower in INVALID_DOMAINS or host_lower.endswith(".json"):
            continue

        # Защита от фейковых и тестовых ключей
        if details["scheme"] == "vless":
            parsed = urllib.parse.urlparse(ck)
            user = (parsed.username or "").lower()
            if user in ("uuid", "<uuid>", "user", "username"):
                continue

        # Shadowsocks не может иметь параметров Reality
        if details["scheme"] in ("ss", "ssr"):
            if "security=reality" in ck.lower() or "xtls-rprx-vision" in ck.lower():
                continue

        seen.add(ck)
        valid_keys.append(ck)

    return valid_keys


def parse_key_details(key: str) -> dict | None:
    """
    Разбирает VPN-ключ (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC)
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

            port = parsed.port or (
                443 if scheme in ("vless", "trojan", "hy2", "hysteria2", "tuic") else 80
            )

            query_params = urllib.parse.parse_qs(parsed.query)
            sni = None
            for sni_field in ["sni", "peer", "host", "serverName"]:
                if sni_field in query_params:
                    sni = query_params[sni_field][0]
                    break

            security = query_params.get("security", [""])[0].lower()
            is_reality = (
                security == "reality"
                or "reality" in parsed.query.lower()
                or "pbk" in query_params
            )
            is_udp = scheme in ("hy2", "hysteria2", "tuic")
            is_tls = (
                scheme == "trojan"
                or is_reality
                or security == "tls"
                or query_params.get("tls", [""])[0] in ("1", "true")
                or port == 443
            )

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
            b64_payload = _fix_b64_padding(b64_payload)

            decoded_json: str | None = None
            for decoder in [base64.b64decode, base64.urlsafe_b64decode]:
                try:
                    decoded_json = decoder(
                        b64_payload.encode("utf-8", errors="ignore")
                    ).decode("utf-8", errors="ignore")
                    break
                except Exception:
                    continue

            if not decoded_json:
                return None

            try:
                data = json.loads(decoded_json)
            except (json.JSONDecodeError, ValueError):
                return None

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

        elif scheme in ("ss", "ssr"):
            body = rest.split("#")[0]
            if "@" in body:
                user_info, host_port = body.split("@", 1)
            else:
                b64_part = body.split("?")[0].split("/")[0].strip()
                b64_part = _fix_b64_padding(b64_part)

                decoded: str | None = None
                for decoder in [base64.b64decode, base64.urlsafe_b64decode]:
                    try:
                        decoded = decoder(
                            b64_part.encode("utf-8", errors="ignore")
                        ).decode("utf-8", errors="ignore")
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
                parts = hp.rsplit(":", 1)
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


def fetch_keys_from_sub(url: str, timeout: float = 8.0, retries: int = 1) -> list[str]:
    """Загружает ключи из URL подписки с поддержкой retry."""
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout)
            if resp.status_code == 200 and resp.text:
                return extract_keys_from_text(resp.text)
            break  # 4xx/5xx — не повторяем
        except requests.exceptions.Timeout:
            if attempt < retries:
                time.sleep(0.5)
        except Exception:
            break
    return []


def fetch_all_subs_parallel(
    urls: list[str], max_workers: int = 30, timeout: float = 8.0
) -> dict[str, list[str]]:
    """Параллельно загружает ключи из списка URL подписок."""
    results: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(fetch_keys_from_sub, u, timeout): u for u in urls
        }
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
    """TCP пинг VPN-ключа. Для UDP-протоколов (Hysteria2/TUIC) использует TCP на тот же порт."""
    details = parse_key_details(key)
    if not details:
        return key, None

    host = details["host"]
    port = details["port"]

    start = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        latency = round((time.perf_counter() - start) * 1000, 1)
        return key, latency
    except ConnectionRefusedError:
        # Хост доступен в сети и ответил RST — считаем как живой (для UDP-протоколов)
        if details.get("is_udp"):
            latency = round((time.perf_counter() - start) * 1000, 1)
            return key, latency
        return key, None
    except Exception:
        return key, None


def ping_and_tls_check(key: str, timeout: float = 2.0) -> tuple[str, float | None]:
    """
    TCP + TLS Handshake проверка VPN-ключа.
    Для UDP-протоколов (Hysteria2/TUIC) выполняет только TCP пинг.
    """
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
    ssl_sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)

        # Проводим TLS Handshake если протокол TLS/Reality/Trojan или указан SNI
        if is_tls or (sni and sni != host):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            target_sni = sni if (sni and not is_ip_address(sni)) else None
            ssl_sock = context.wrap_socket(sock, server_hostname=target_sni)
            # ssl_sock владеет sock, закрываем только ssl_sock
            sock = None
            ssl_sock.close()
            ssl_sock = None
        else:
            sock.close()
            sock = None

        latency = round((time.perf_counter() - start) * 1000, 1)
        return key, latency
    except Exception:
        return key, None
    finally:
        # Закрываем только если ещё не закрыты
        if ssl_sock is not None:
            try:
                ssl_sock.close()
            except Exception:
                pass
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
