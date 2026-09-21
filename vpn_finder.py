import argparse
import base64
import io
import os
import re
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

import requests

from vpn_utils import (
    DEFAULT_HEADERS,
    VPN_PROTOCOLS_REGEX,
    clean_key,
    extract_keys_from_text,
    fetch_all_subs_parallel,
    fetch_keys_from_sub,
    parse_key_details,
    ping_and_tls_check,
    ping_key,
)

VALID_SUBS_FILE = "valid_subscriptions.txt"
HISTORY_SUBS_FILE = "history_subs.txt"
OUTPUT_KEYS_FILE = "working_keys.txt"
OUTPUT_SUB_FILE = "sub.txt"

# Максимальное количество серверов в файле подписки Throne (чтобы клиент не зависал)
MAX_SUB_SERVERS = 100

CURATED_SOURCES = [
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/mix",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/reality",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/trojan",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/shadowsocks",
    "https://raw.githubusercontent.com/vfarid/v2ray-share/master/splitted/normal-reality.txt",
    "https://raw.githubusercontent.com/MrPooyaX/VpnCollectors/main/sub/mix",
    "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/all.txt",
    "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/vless.txt",
    "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/shadowsocks.txt",
]

TELEGRAM_CHANNELS = [
    "Outline_Vpn",
    "PrivateVPNs",
    "DirectVPN",
    "v2ray_outlineir",
    "vpn_ocean",
    "v2rayng_org",
    "customv2ray",
    "V2rayNG_VPNN",
    "v2ray_custom",
    "v2ray_alpha",
    "proxystore11",
]


def load_lines(filepath: str) -> list[str]:
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def load_known_urls() -> tuple[set[str], dict[str, str]]:
    history_urls = set()
    for line in load_lines(HISTORY_SUBS_FILE):
        u = line.split("|")[0].strip()
        if u.startswith("http"):
            history_urls.add(u)

    valid_urls = {}
    for line in load_lines(VALID_SUBS_FILE):
        parts = line.split("|")
        u = parts[0].strip()
        if u.startswith("http"):
            valid_urls[u] = line

    return history_urls, valid_urls


def scrape_telegram_channel(channel: str, timeout: float = 6.0) -> list[str]:
    url = f"https://t.me/s/{channel}"
    try:
        res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=timeout)
        if res.status_code == 200:
            return extract_keys_from_text(res.text)
    except Exception:
        pass
    return []


def search_github_subscriptions(timeout: float = 8.0) -> list[str]:
    found_urls = set()
    queries = [
        "v2ray subscription xray mix in:readme,path",
        "vless configs reality subscription in:path",
    ]
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for q in queries:
        try:
            api_url = f"https://api.github.com/search/repositories?q={requests.utils.quote(q)}&sort=updated&order=desc&per_page=15"
            r = requests.get(api_url, headers=headers, timeout=timeout)
            if r.status_code == 200:
                items = r.json().get("items", [])
                for item in items:
                    full_name = item.get("full_name")
                    branch = item.get("default_branch", "main")
                    if full_name:
                        for path in ["sub/mix", "sub/all.txt", "v2ray", "sub", "sub.txt"]:
                            raw_url = f"https://raw.githubusercontent.com/{full_name}/{branch}/{path}"
                            found_urls.add(raw_url)
        except Exception:
            pass

    return list(found_urls)


def discover_and_update_subscriptions(max_workers: int = 30) -> tuple[list[str], list[str]]:
    print("[*] Поиск новых источников VPN...")
    history_urls, valid_urls = load_known_urls()

    candidate_urls = set(CURATED_SOURCES)
    gh_candidates = search_github_subscriptions()
    candidate_urls.update(gh_candidates)
    print(f"    Найдено кандидатов: {len(candidate_urls)}")

    print(f"[*] Сбор ключей из {len(TELEGRAM_CHANNELS)} публичных каналов Telegram...")
    direct_keys = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        tg_futures = {executor.submit(scrape_telegram_channel, ch): ch for ch in TELEGRAM_CHANNELS}
        for fut in as_completed(tg_futures):
            ch = tg_futures[fut]
            try:
                keys = fut.result()
                if keys:
                    print(f"    [TG] @{ch}: найдено {len(keys)} ключей")
                    direct_keys.extend(keys)
            except Exception:
                pass

    # Исключаем уже проверенные и известные адреса (как валидные, так и мертвые из истории)
    urls_to_check = [u for u in candidate_urls if u not in valid_urls and u not in history_urls]
    print(f"[*] Проверка {len(urls_to_check)} новых потенциальных подписок...")

    new_valid = []
    collected_keys = list(direct_keys)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        fut_to_url = {executor.submit(fetch_keys_from_sub, u): u for u in urls_to_check}
        for fut in as_completed(fut_to_url):
            u = fut_to_url[fut]
            try:
                keys = fut.result()
                if len(keys) >= 2:
                    new_valid.append((u, len(keys)))
                    collected_keys.extend(keys)
                    print(f"    [+] Найдена рабочая подписка: {u} (Ключей: {len(keys)})")
            except Exception:
                pass

    new_history = [u for u in candidate_urls if u not in history_urls]
    if new_history:
        with open(HISTORY_SUBS_FILE, "a", encoding="utf-8") as f:
            for u in new_history:
                f.write(f"{u}\n")

    if new_valid:
        with open(VALID_SUBS_FILE, "a", encoding="utf-8") as f:
            for u, count in new_valid:
                f.write(f"{u} | Ключей: {count}\n")
        print(f"[OK] В {VALID_SUBS_FILE} добавлено {len(new_valid)} новых проверенных подписок!")
    else:
        print("[i] Новых уникальных подписок не добавлено.")

    return [u for u, _ in new_valid], collected_keys


def safe_save_verified_keys(verified_keys: list[str]):
    """
    Сохраняет ИСКЛЮЧИТЕЛЬНО проверенные живые ключи:
    - sub.txt: топ проверенных серверов в Base64 для Throne
    - working_keys.txt: чистый текстовый список проверенных серверов
    """
    if not verified_keys:
        print("[!] Нет проверенных ключей для сохранения.")
        return

    cleaned_keys = []
    seen = set()
    for k in verified_keys:
        ck = clean_key(k)
        if ck and ck not in seen:
            seen.add(ck)
            cleaned_keys.append(ck)

    if not cleaned_keys:
        print("[!] После очистки не осталось ключей для сохранения.")
        return

    # Резервная копия перед перезаписью
    if os.path.exists(OUTPUT_KEYS_FILE) and os.path.getsize(OUTPUT_KEYS_FILE) > 0:
        try:
            shutil.copyfile(OUTPUT_KEYS_FILE, f"{OUTPUT_KEYS_FILE}.bak")
        except Exception:
            pass

    # 1. working_keys.txt (чистые проверенные ключи)
    tmp_file = f"{OUTPUT_KEYS_FILE}.tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        for k in cleaned_keys:
            f.write(f"{k}\n")
    os.replace(tmp_file, OUTPUT_KEYS_FILE)

    # 2. sub.txt (топ самых быстрых серверов в Base64 для Throne)
    top_servers = cleaned_keys[:MAX_SUB_SERVERS]
    raw_sub = "\n".join(top_servers)
    b64_encoded = base64.b64encode(raw_sub.encode("utf-8")).decode("ascii")

    tmp_sub = f"{OUTPUT_SUB_FILE}.tmp"
    with open(tmp_sub, "w", encoding="utf-8") as f:
        f.write(b64_encoded)
    os.replace(tmp_sub, OUTPUT_SUB_FILE)

    print(f"[OK] sub.txt обновлен: {len(top_servers)} ТОП проверенных серверов (Base64)")
    print(f"[OK] working_keys.txt обновлен: {len(cleaned_keys)} серверов")


def main():
    parser = argparse.ArgumentParser(description="VPN Finder & Checker")
    parser.add_argument("--find-only", action="store_true", help="Только найти и обновить подписки")
    parser.add_argument("--check-only", action="store_true", help="Только проверить существующие подписки")
    parser.add_argument("--tls", action="store_true", default=True, help="Глубокая TLS проверка")
    parser.add_argument("--no-tls", dest="tls", action="store_false", help="Только быстрый TCP пинг")
    parser.add_argument("--max-ping", type=int, default=120, help="Максимально допустимый пинг в мс (по умолчанию: 120)")
    parser.add_argument("--threads", type=int, default=35, help="Число параллельных потоков")
    parser.add_argument("--limit-check", type=int, default=1000, help="Максимум ключей для проверки за один прогон")
    args = parser.parse_args()

    collected_keys = []

    # 1. Собираем самые свежие ключи из Telegram и новых подписок
    if not args.check_only:
        _, keys_from_finder = discover_and_update_subscriptions(max_workers=args.threads)
        collected_keys.extend(keys_from_finder)

    if args.find_only:
        print("[OK] Режим --find-only завершен.")
        return

    # 2. Загрузка существующих подписок
    print(f"\n[*] Загрузка подписок из {VALID_SUBS_FILE}...")
    valid_lines = load_lines(VALID_SUBS_FILE)
    urls = [line.split("|")[0].strip() for line in valid_lines if line.split("|")[0].strip().startswith("http")]
    urls = list(dict.fromkeys(urls))

    print(f"[*] Быстрый параллельный опрос {len(urls)} подписок...")
    start_fetch = time.perf_counter()
    sub_results = fetch_all_subs_parallel(urls, max_workers=args.threads, timeout=8.0)
    for u, keys in sub_results.items():
        collected_keys.extend(keys)

    fetch_time = round(time.perf_counter() - start_fetch, 1)

    # Очищаем и дедуплицируем собранные ключи
    unique_keys = []
    seen_raw = set()
    for k in collected_keys:
        ck = clean_key(k)
        if ck and ck not in seen_raw:
            seen_raw.add(ck)
            unique_keys.append(ck)

    print(f"[*] Собрано {len(unique_keys)} уникальных свежих ключей (за {fetch_time} сек).")

    if not unique_keys:
        print("[!] Нет ключей для проверки.")
        return

    # Приоритет: сначала VLESS Reality, Trojan, Hysteria2 (они лучше всего работают в РФ)
    def key_priority(k: str) -> int:
        k_lower = k.lower()
        if "reality" in k_lower:
            return 0
        if k_lower.startswith("vless://"):
            return 1
        if k_lower.startswith("trojan://"):
            return 2
        if k_lower.startswith("hy2://") or k_lower.startswith("hysteria2://"):
            return 3
        return 4

    unique_keys.sort(key=key_priority)

    keys_to_ping = unique_keys[:args.limit_check] if args.limit_check > 0 else unique_keys
    print(f"[*] Начинаем жесткую фильтрацию {len(keys_to_ping)} ключей (порог < {args.max_ping} мс)...")

    check_fn = ping_and_tls_check if args.tls else ping_key
    check_name = "TLS Handshake" if args.tls else "TCP Ping"

    working_keys = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_fn, key, 2.0): key for key in keys_to_ping}
        for i, future in enumerate(as_completed(futures), 1):
            key, latency = future.result()
            if latency is not None and latency < args.max_ping:
                working_keys.append((latency, key))
                print(f"[{i}/{len(keys_to_ping)}] [OK] {latency} мс | {key[:55]}...")
            elif latency is not None:
                if i % 50 == 0:
                    print(f"[{i}/{len(keys_to_ping)}] [SLOW] {latency} мс")
            else:
                if i % 100 == 0:
                    print(f"[{i}/{len(keys_to_ping)}] ...")

    # Сортируем от самых быстрых (минимальный пинг) к более медленным
    working_keys.sort(key=lambda x: x[0])
    verified_fast_keys = [k for _, k in working_keys]

    print("=" * 65)
    print("[*] ИТОГИ ПРОВЕРКИ:")
    print(f"Проверено: {len(keys_to_ping)} ключей")
    print(f"РЕАЛЬНО РАБОЧИХ с пингом < {args.max_ping} мс: {len(verified_fast_keys)}")

    if verified_fast_keys:
        safe_save_verified_keys(verified_fast_keys)


if __name__ == "__main__":
    main()
