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

from vpn_finder import safe_save_verified_keys
from vpn_utils import (
    clean_key,
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

    unique_keys = []
    seen = set()
    for k in all_keys:
        ck = clean_key(k)
        if ck and ck not in seen:
            seen.add(ck)
            unique_keys.append(ck)

    print(f"[*] Собрано уникальных ключей: {len(unique_keys)} (за {fetch_time} сек)")
    if not unique_keys:
        print("[!] Нет ключей для проверки.")
        return

    print(f"[*] Начинаем пинг (порог: < {MAX_PING_MS} мс, потоков: {MAX_THREADS})...")
    print(f"[*] Результаты сохраняются в: {OUTPUT_KEYS_FILE}\n" + "=" * 65)

    working_keys = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(ping_key, key): key for key in unique_keys}

        for i, future in enumerate(as_completed(futures), 1):
            key, latency = future.result()
            if latency is not None and latency < MAX_PING_MS:
                working_keys.append((latency, key))
                print(f"[{i}/{len(unique_keys)}] [OK] {latency} мс | {key[:60]}...")
            elif latency is not None:
                if i % 50 == 0:
                    print(f"[{i}/{len(unique_keys)}] [SLOW] {latency} мс")
            else:
                if i % 100 == 0:
                    print(f"[{i}/{len(unique_keys)}] ...")

    working_keys.sort(key=lambda x: x[0])
    verified_keys = [k for _, k in working_keys]

    print("=" * 65)
    print("[*] ИТОГИ ПРОВЕРКИ:")
    print(f"Всего ключей проверено: {len(unique_keys)}")
    print(f"Сохранено рабочих: {len(verified_keys)}")

    if verified_keys:
        safe_save_verified_keys(verified_keys)
    else:
        print("[!] Внимание: ни один ключ не ответил быстрее порога, файлы не были затерты.")


if __name__ == "__main__":
    main()
