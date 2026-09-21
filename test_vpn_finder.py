import io
import os
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from vpn_utils import (
    fetch_all_subs_parallel,
    fetch_keys_from_sub,
    parse_key_details,
    ping_and_tls_check,
)

INPUT_FILE = "valid_subscriptions.txt"
OUTPUT_KEYS_FILE = "working_keys.txt"

MAX_PING_MS = 150
MAX_THREADS = 25


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[!] Файл {INPUT_FILE} не найден!")
        return

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        urls = [line.split("|")[0].strip() for line in f if line.strip()]

    urls = [u for u in dict.fromkeys(urls) if u.startswith("http")]
    print(f"[*] Загружено {len(urls)} подписок...")

    print(f"[*] Быстрая параллельная загрузка ключей ({MAX_THREADS} потоков)...")
    start_fetch = time.perf_counter()
    sub_results = fetch_all_subs_parallel(urls, max_workers=MAX_THREADS, timeout=8.0)

    all_keys = []
    for u, keys in sub_results.items():
        all_keys.extend(keys)

    fetch_time = round(time.perf_counter() - start_fetch, 1)
    unique_keys = list(set(all_keys))
    print(f"[*] Найдено уникальных ключей: {len(unique_keys)} (за {fetch_time} сек)")
    print(f"[*] Запуск TLS Handshake + SNI проверки (порог: < {MAX_PING_MS} мс)...")
    print(f"[*] Результаты будут сохранены в: {OUTPUT_KEYS_FILE}\n" + "=" * 65)

    if os.path.exists(OUTPUT_KEYS_FILE) and os.path.getsize(OUTPUT_KEYS_FILE) > 0:
        try:
            shutil.copyfile(OUTPUT_KEYS_FILE, f"{OUTPUT_KEYS_FILE}.bak")
        except Exception:
            pass

    valid_count = 0
    tmp_output = f"{OUTPUT_KEYS_FILE}.tmp"

    with open(tmp_output, "w", encoding="utf-8") as out_file:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(ping_and_tls_check, key): key for key in unique_keys}

            for i, future in enumerate(as_completed(futures), 1):
                key, latency = future.result()
                if latency is not None and latency < MAX_PING_MS:
                    valid_count += 1
                    out_file.write(f"{key}\n")
                    out_file.flush()
                    print(f"[{i}/{len(unique_keys)}] [TLS OK] {latency} мс | {key[:55]}...")
                elif latency is not None:
                    if i % 50 == 0:
                        print(f"[{i}/{len(unique_keys)}] [SLOW] Медленный TLS ({latency} мс)")
                else:
                    if i % 100 == 0:
                        print(f"[{i}/{len(unique_keys)}] ...")

    if os.path.exists(OUTPUT_KEYS_FILE):
        os.remove(OUTPUT_KEYS_FILE)
    os.rename(tmp_output, OUTPUT_KEYS_FILE)

    print("=" * 65)
    print("[*] ИТОГИ:")
    print(f"Всего ключей: {len(unique_keys)}")
    print(f"Прошли TLS Handshake и записаны: {valid_count}")


if __name__ == "__main__":
    main()
