"""
tls_checker.py — Глубокая проверка VPN-ключей через TLS Handshake + SNI.

Загружает ключи из valid_subscriptions.txt, выполняет полное TLS-рукопожатие
и сохраняет только те ключи, которые реально отвечают — отсеивая
Cloudflare-фронтенды и мёртвые узлы.
"""

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from vpn_finder import VALID_SUBS_FILE, safe_save_verified_keys
from vpn_utils import (
    deduplicate_keys,
    fetch_all_subs_parallel,
    ping_and_tls_check,
)

DEFAULT_MAX_PING_MS = 150
DEFAULT_MAX_THREADS = 25


def main():
    parser = argparse.ArgumentParser(description="TLS Handshake валидатор VPN-ключей")
    parser.add_argument(
        "--max-ping",
        type=int,
        default=DEFAULT_MAX_PING_MS,
        help=f"Максимальный TLS RTT в мс (по умолчанию: {DEFAULT_MAX_PING_MS})",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_MAX_THREADS,
        help=f"Число параллельных потоков (по умолчанию: {DEFAULT_MAX_THREADS})",
    )
    parser.add_argument(
        "--input",
        default=VALID_SUBS_FILE,
        help=f"Файл с подписками (по умолчанию: {VALID_SUBS_FILE})",
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Файл {args.input} не найден!")
        return

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        urls = [line.split("|")[0].strip() for line in f if line.strip()]

    urls = [u for u in dict.fromkeys(urls) if u.startswith("http")]
    print(f"[*] Загружено {len(urls)} подписок...")

    print(f"[*] Быстрая параллельная загрузка ключей ({args.threads} потоков)...")
    start_fetch = time.perf_counter()
    sub_results = fetch_all_subs_parallel(urls, max_workers=args.threads, timeout=8.0)

    all_keys: list[str] = []
    for keys in sub_results.values():
        all_keys.extend(keys)

    fetch_time = round(time.perf_counter() - start_fetch, 1)
    unique_keys = deduplicate_keys(all_keys)

    print(f"[*] Найдено уникальных ключей: {len(unique_keys)} (за {fetch_time} сек)")
    if not unique_keys:
        print("[!] Нет ключей для проверки.")
        return

    print(
        f"[*] Запуск TLS Handshake + SNI проверки"
        f" (порог: < {args.max_ping} мс, потоков: {args.threads})..."
    )
    print("=" * 65)

    working_keys: list[tuple[float, str]] = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(ping_and_tls_check, key): key for key in unique_keys}

        for i, future in enumerate(as_completed(futures), 1):
            key, latency = future.result()
            if latency is not None and latency < args.max_ping:
                working_keys.append((latency, key))
                print(f"[{i}/{len(unique_keys)}] [TLS OK] {latency} мс | {key[:55]}...")
            elif latency is not None:
                if i % 50 == 0:
                    print(f"[{i}/{len(unique_keys)}] [SLOW] Медленный TLS ({latency} мс)")
            else:
                if i % 100 == 0:
                    print(f"[{i}/{len(unique_keys)}] ...")

    working_keys.sort(key=lambda x: x[0])
    verified_keys = [k for _, k in working_keys]

    print("=" * 65)
    print("[*] ИТОГИ:")
    print(f"Всего ключей: {len(unique_keys)}")
    print(f"Прошли TLS Handshake и записаны: {len(verified_keys)}")

    if verified_keys:
        safe_save_verified_keys(verified_keys)
    else:
        print("[!] Внимание: ни один ключ не прошел проверку, файлы не затронуты.")


if __name__ == "__main__":
    main()
