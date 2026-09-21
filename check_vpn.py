import io
import os
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Безопасная настройка UTF-8 для консоли Windows / CI
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
    ping_key,
)

INPUT_FILE = "valid_subscriptions.txt"
OUTPUT_KEYS_FILE = "working_keys.txt"

MAX_PING_MS = 100
MAX_THREADS = 30


def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[!] Файл {INPUT_FILE} не найден!")
        return

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        urls = [line.split("|")[0].strip() for line in f if line.strip()]

    urls = [u for u in dict.fromkeys(urls) if u.startswith("http")]
    print(f"[*] Загружено {len(urls)} подписок для анализа...")

    print(f"[*] Параллельная загрузка ключей ({MAX_THREADS} потоков)...")
    start_fetch = time.perf_counter()
    sub_results = fetch_all_subs_parallel(urls, max_workers=MAX_THREADS, timeout=8.0)

    all_keys = []
    for u, keys in sub_results.items():
        all_keys.extend(keys)

    fetch_time = round(time.perf_counter() - start_fetch, 1)
    unique_keys = list(set(all_keys))
    print(f"[*] Собрано уникальных ключей: {len(unique_keys)} (за {fetch_time} сек)")
    print(f"[*] Начинаем пинг (порог: < {MAX_PING_MS} мс, потоков: {MAX_THREADS})...")
    print(f"[*] Результаты сохраняются в: {OUTPUT_KEYS_FILE}\n" + "=" * 65)

    if os.path.exists(OUTPUT_KEYS_FILE) and os.path.getsize(OUTPUT_KEYS_FILE) > 0:
        try:
            shutil.copyfile(OUTPUT_KEYS_FILE, f"{OUTPUT_KEYS_FILE}.bak")
        except Exception:
            pass

    fast_count = 0
    tmp_output = f"{OUTPUT_KEYS_FILE}.tmp"

    with open(tmp_output, "w", encoding="utf-8") as out_file:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(ping_key, key): key for key in unique_keys}

            for i, future in enumerate(as_completed(futures), 1):
                key, latency = future.result()
                if latency is not None and latency < MAX_PING_MS:
                    fast_count += 1
                    out_file.write(f"{key}\n")
                    out_file.flush()
                    print(f"[{i}/{len(unique_keys)}] [OK] {latency} мс | {key[:60]}...")
                elif latency is not None:
                    if i % 50 == 0:
                        print(f"[{i}/{len(unique_keys)}] [SLOW] {latency} мс")
                else:
                    if i % 100 == 0:
                        print(f"[{i}/{len(unique_keys)}] ...")

    if os.path.exists(OUTPUT_KEYS_FILE):
        os.remove(OUTPUT_KEYS_FILE)
    os.rename(tmp_output, OUTPUT_KEYS_FILE)

    print("=" * 65)
    print("[*] ИТОГИ ПРОВЕРКИ:")
    print(f"Всего ключей проверено: {len(unique_keys)}")
    print(f"Сохранено рабочих: {fast_count}")


if __name__ == "__main__":
    main()
