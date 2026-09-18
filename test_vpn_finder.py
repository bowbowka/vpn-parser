import os
import re
import json
import time
import ssl
import socket
import requests
import base64
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "valid_subscriptions.txt"
OUTPUT_KEYS_FILE = "working_keys.txt"

MAX_PING_MS = 150       # Максимально допустимый пинг TLS (мс)
MAX_THREADS = 25        # Потоки для проверки
VPN_PROTOCOLS_REGEX = r'(?:vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic)://[^\s<"\']+'


def fetch_keys_from_sub(url: str) -> list[str]:
    """Загружает подписку и извлекает сырые VPN-ключи."""
    headers = {"User-Agent": "v2rayTun/1.0.0 (Android; v2rayN)", "Accept": "*/*"}
    try:
        res = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
        if res.status_code != 200 or not res.text.strip():
            return []

        content = res.text.strip()
        try:
            missing_padding = len(content) % 4
            content_padded = content + '=' * (4 - missing_padding) if missing_padding else content
            decoded = base64.b64decode(content_padded).decode('utf-8', errors='ignore')
            if any(p in decoded for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hy2://']):
                content = decoded
        except Exception:
            pass

        return re.findall(VPN_PROTOCOLS_REGEX, content, re.IGNORECASE)
    except Exception:
        return []


def parse_key_details(key: str) -> tuple[str, int, str | None, bool] | None:
    """
    Извлекает (host, port, sni, is_tls) из конфигурации ключа.
    """
    try:
        # VMess (Base64 JSON)
        if key.startswith("vmess://"):
            b64_str = key[8:].split('#')[0]
            b64_str += '=' * (-len(b64_str) % 4)
            data = json.loads(base64.b64decode(b64_str).decode('utf-8', errors='ignore'))
            host = data.get('add') or data.get('host')
            port = int(data.get('port', 443))
            sni = data.get('sni') or data.get('host') or host
            is_tls = str(data.get('tls', '')).lower() == 'tls' or port == 443
            if host:
                return str(host), port, str(sni) if sni else None, is_tls

        # Shadowsocks
        elif key.startswith("ss://") and "@" not in key.split('#')[0]:
            raw = key[5:].split('#')[0]
            raw += '=' * (-len(raw) % 4)
            decoded = base64.b64decode(raw).decode('utf-8', errors='ignore')
            hp = decoded.split("@")[1] if "@" in decoded else decoded
            host, port = hp.split(":")
            return host, int(port), None, False

        # VLESS, Trojan, Hysteria2, SS-URI
        else:
            parsed = urlparse(key)
            query = parse_qs(parsed.query)
            host = parsed.hostname
            if not host:
                return None

            port = parsed.port or (443 if parsed.scheme in ['vless', 'trojan', 'hy2', 'hysteria2'] else 8388)
            sni_list = query.get('sni') or query.get('host')
            sni = sni_list[0] if sni_list else host

            security = query.get('security', [''])[0].lower()
            is_tls = security in ['tls', 'reality'] or parsed.scheme in ['hy2', 'hysteria2', 'trojan'] or port == 443

            return host, port, sni, is_tls
    except Exception:
        pass
    return None


def ping_and_tls_check(key: str, timeout: float = 3.0) -> tuple[str, float | None]:
    """
    Выполняет TCP + TLS Handshake с проверкой SNI.
    Откидывает заглушки Cloudflare, у которых сокет открыт, но TLS сбоит.
    """
    details = parse_key_details(key)
    if not details:
        return key, None

    host, port, sni, is_tls = details
    start_time = time.perf_counter()

    try:
        # 1. Устанавливаем базовое TCP-соединение
        sock = socket.create_connection((host, port), timeout=timeout)

        # 2. Если используется TLS/Reality — проводим рукопожатие
        if is_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            server_hostname = sni if sni else host
            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                # Рукопожатие успешно пройден
                latency = (time.perf_counter() - start_time) * 1000
                return key, round(latency, 1)
        else:
            sock.close()
            latency = (time.perf_counter() - start_time) * 1000
            return key, round(latency, 1)

    except Exception:
        # Если рукопожатие сорвалось (ошибка TLS/SNI) — ключ отсеивается
        return key, None


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Файл {INPUT_FILE} не найден!")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        urls = [line.split("|")[0].strip() for line in f if line.strip()]

    urls = [u for u in dict.fromkeys(urls) if u.startswith("http")]
    print(f"📖 Загружено {len(urls)} подписок...")

    all_keys = []
    for u in urls:
        all_keys.extend(fetch_keys_from_sub(u))

    unique_keys = list(set(all_keys))
    print(f"🔑 Найдено уникальных ключей: {len(unique_keys)}")
    print(f"🔒 Запуск TLS Handshake + SNI проверки (порог: < {MAX_PING_MS} мс)...")
    print(f"💾 Валидные ключи сразу записываются в: {OUTPUT_KEYS_FILE}\n" + "=" * 65)

    valid_count = 0

    with open(OUTPUT_KEYS_FILE, "w", encoding="utf-8") as out_file:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(ping_and_tls_check, key): key for key in unique_keys}

            for i, future in enumerate(as_completed(futures), 1):
                key, latency = future.result()
                if latency is not None and latency < MAX_PING_MS:
                    valid_count += 1
                    out_file.write(f"{key}\n")
                    out_file.flush()
                    print(f"[{i}/{len(unique_keys)}] ✅ TLS OK ({latency} мс) | {key[:55]}...")
                elif latency is not None:
                    print(f"[{i}/{len(unique_keys)}] ⚠️ Медленный TLS ({latency} мс)")
                else:
                    print(f"[{i}/{len(unique_keys)}] ❌ Ошибка TLS / Недоступен")

    print("=" * 65)
    print("📊 ИТОГИ:")
    print(f"Всего ключей: {len(unique_keys)}")
    print(f"Прошли TLS Handshake и записаны: {valid_count}")


if __name__ == "__main__":
    main()
