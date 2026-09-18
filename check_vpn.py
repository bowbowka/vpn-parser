import os
import re
import json
import time
import socket
import requests
import base64
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "valid_subscriptions.txt"
OUTPUT_KEYS_FILE = "working_keys.txt"

MAX_PING_MS = 100       # Максимально допустимый пинг в мс
MAX_THREADS = 30        # Количество параллельных потоков для проверки
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


def parse_host_port(key: str) -> tuple[str, int] | None:
    """Извлекает хост и порт из конфигурации ключа."""
    try:
        # Разбор VMess (Base64 JSON)
        if key.startswith("vmess://"):
            b64_str = key[8:].split('#')[0]
            b64_str += '=' * (-len(b64_str) % 4)
            data = json.loads(base64.b64decode(b64_str).decode('utf-8', errors='ignore'))
            host = data.get('add') or data.get('host')
            port = int(data.get('port', 443))
            if host:
                return str(host), port

        # Разбор Shadowsocks с Base64 кодированием до знака #
        elif key.startswith("ss://") and "@" not in key.split('#')[0]:
            raw = key[5:].split('#')[0]
            raw += '=' * (-len(raw) % 4)
            decoded = base64.b64decode(raw).decode('utf-8', errors='ignore')
            hp = decoded.split("@")[1] if "@" in decoded else decoded
            host, port = hp.split(":")
            return host, int(port)

        # Разбор VLESS, Trojan, Hysteria2, SS (стандартные URI)
        else:
            parsed = urlparse(key)
            if parsed.hostname and parsed.port:
                return parsed.hostname, parsed.port
            elif parsed.hostname:
                default_port = 443 if parsed.scheme in ['vless', 'trojan', 'hy2', 'hysteria2'] else 8388
                return parsed.hostname, default_port
    except Exception:
        pass
    return None


def ping_key(key: str, timeout: float = 2.5) -> tuple[str, float | None]:
    """Проверяет TCP-соединение с сервером ключа и возвращает пинг в мс."""
    target = parse_host_port(key)
    if not target:
        return key, None

    host, port = target
    start_time = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        latency = (time.perf_counter() - start_time) * 1000  # Перевод в мс
        return key, round(latency, 1)
    except Exception:
        return key, None


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Файл {INPUT_FILE} не найден!")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        urls = [line.split("|")[0].strip() for line in f if line.strip()]

    urls = [u for u in dict.fromkeys(urls) if u.startswith("http")]
    print(f"📖 Загружено {len(urls)} подписок для анализа...")

    all_keys = []
    for u in urls:
        all_keys.extend(fetch_keys_from_sub(u))

    unique_keys = list(set(all_keys))
    print(f"🔑 Собрано уникальных ключей: {len(unique_keys)}")
    print(f"⚡ Начинаем параллельный пинг (порог: < {MAX_PING_MS} мс)...")
    print(f"💾 Результаты сразу записываются в: {OUTPUT_KEYS_FILE}\n" + "=" * 65)

    fast_count = 0

    # Открываем выходной файл перед началом проверки
    with open(OUTPUT_KEYS_FILE, "w", encoding="utf-8") as out_file:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(ping_key, key): key for key in unique_keys}

            for i, future in enumerate(as_completed(futures), 1):
                key, latency = future.result()
                if latency is not None and latency < MAX_PING_MS:
                    fast_count += 1
                    # Запись и немедленное сохранение на диск
                    out_file.write(f"{key}\n")
                    out_file.flush()
                    print(f"[{i}/{len(unique_keys)}] ✅ {latency} мс | {key[:60]}...")
                elif latency is not None:
                    print(f"[{i}/{len(unique_keys)}] ⚠️ {latency} мс (Медленный > {MAX_PING_MS}мс)")
                else:
                    print(f"[{i}/{len(unique_keys)}] ❌ Недоступен")

    print("=" * 65)
    print("📊 ИТОГИ ПРОВЕРКИ:")
    print(f"Всего ключей проверено: {len(unique_keys)}")
    print(f"Сохранено рабочих с пингом < {MAX_PING_MS} мс: {fast_count}")


if __name__ == "__main__":
    main()
