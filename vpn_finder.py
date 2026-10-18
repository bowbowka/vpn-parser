import argparse
import base64
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
    deduplicate_keys,
    extract_keys_from_text,
    fetch_all_subs_parallel,
    fetch_keys_from_sub,
    parse_key_details,
    ping_and_tls_check,
    ping_key,
    filter_and_diversify_keys,
)
from xray_checker import batch_verify_keys_xray, ensure_xray_binary

VALID_SUBS_FILE = "valid_subscriptions.txt"
HISTORY_SUBS_FILE = "history_subs.txt"
OUTPUT_KEYS_FILE = "working_keys.txt"
OUTPUT_SUB_FILE = "sub.txt"

# Максимальное количество серверов в файле подписки Throne (чтобы клиент не зависал)
MAX_SUB_SERVERS = 100

CURATED_SOURCES = [
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/mix",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/all.txt",
    "https://cdn.jsdelivr.net/gh/ShatakVPN/ConfigForge-V2Ray@main/configs/vless.txt",
]

TELEGRAM_CHANNELS = [
    "v2ray_alpha",
    "Outline_Vpn",
    "marambashi",
    "proxystore11",
    "vpn_ocean",
    "FreeV2rays",
    "v2ray_free_conf",
    "DirectVPN",
    "PrivateVPNs",
    "v2ray_outlineir",
    "v2rayng_org",
    "customv2ray",
    "V2rayNG_VPNN",
    "v2ray_custom",
]


def load_lines(filepath: str) -> list[str]:
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def load_known_urls() -> tuple[set[str], dict[str, str]]:
    history_urls: set[str] = set()
    for line in load_lines(HISTORY_SUBS_FILE):
        u = line.split("|")[0].strip()
        if u.startswith("http"):
            history_urls.add(u)

    valid_urls: dict[str, str] = {}
    for line in load_lines(VALID_SUBS_FILE):
        parts = line.split("|")
        u = parts[0].strip()
        if u.startswith("http"):
            valid_urls[u] = line

    return history_urls, valid_urls


def scrape_telegram_channel(
    channel: str, timeout: float = 6.0, retries: int = 2
) -> list[str]:
    url = f"https://t.me/s/{channel}"
    for attempt in range(retries + 1):
        try:
            res = requests.get(
                url, headers={"User-Agent": "Mozilla/5.0"}, timeout=timeout
            )
            if res.status_code == 200:
                return extract_keys_from_text(res.text)
            break
        except requests.exceptions.Timeout:
            if attempt < retries:
                time.sleep(1.0)
        except Exception:
            break
    return []


def search_github_subscriptions(timeout: float = 8.0) -> list[str]:
    found_urls: set[str] = set()
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
            api_url = (
                f"https://api.github.com/search/repositories"
                f"?q={requests.utils.quote(q)}&sort=updated&order=desc&per_page=15"
            )
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
            elif r.status_code == 403:
                # Rate limit — прекращаем дальнейшие запросы
                print("[!] GitHub API rate limit достигнут, пропускаем поиск.")
                break
        except Exception:
            pass

    return list(found_urls)


def discover_and_update_subscriptions(
    max_workers: int = 30,
) -> tuple[list[str], list[str]]:
    print("[*] Поиск новых источников VPN...")
    history_urls, valid_urls = load_known_urls()

    candidate_urls: set[str] = set(CURATED_SOURCES)
    gh_candidates = search_github_subscriptions()
    candidate_urls.update(gh_candidates)
    print(f"    Найдено кандидатов: {len(candidate_urls)}")

    print(f"[*] Сбор ключей из {len(TELEGRAM_CHANNELS)} публичных каналов Telegram...")
    direct_keys: list[str] = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        tg_futures = {
            executor.submit(scrape_telegram_channel, ch): ch for ch in TELEGRAM_CHANNELS
        }
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
    urls_to_check = [
        u for u in candidate_urls if u not in valid_urls and u not in history_urls
    ]
    print(f"[*] Проверка {len(urls_to_check)} новых потенциальных подписок...")

    new_valid: list[tuple[str, int]] = []
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
        print(
            f"[OK] В {VALID_SUBS_FILE} добавлено {len(new_valid)} новых проверенных подписок!"
        )
    else:
        print("[i] Новых уникальных подписок не добавлено.")

    return [u for u, _ in new_valid], collected_keys


def safe_save_verified_keys(verified_keys: list[str], max_sub_servers: int = MAX_SUB_SERVERS):
    """
    Сохраняет проверенные живые ключи:
    - Первыми идут проверенные WolfPN ключи
    - Затем проверенные уникальные публичные ключи с защитой от дублирования подсетей
    """
    if not verified_keys:
        print("[!] Нет проверенных ключей для сохранения.")
        return

    existing_keys = load_lines(OUTPUT_KEYS_FILE)

    # 1. Эталонные WolfPN ключи
    wolf_keys = [k for k in existing_keys if "WolfPN" in k or "pyaterka" in k or "ozon" in k or "vkvideo" in k]

    # 2. Фильтруем и диверсифицируем только РЕАЛЬНО проверенные публичные ключи
    diversified_public = filter_and_diversify_keys(verified_keys, max_per_subnet=2)

    combined = wolf_keys + [k for k in diversified_public if k not in wolf_keys]
    cleaned_keys = deduplicate_keys(combined)

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
    top_servers = cleaned_keys[:max_sub_servers]
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
    parser.add_argument(
        "--xray", action="store_true", default=True, help="Глубокая проверка реального трафика через Xray (по умолчанию: включено)"
    )
    parser.add_argument(
        "--no-xray", dest="xray", action="store_false", help="Отключить проверку через Xray"
    )
    parser.add_argument(
        "--limit-xray", type=int, default=100, help="Максимум ключей для проверки через Xray (по умолчанию: 100)"
    )
    parser.add_argument(
        "--xray-threads", type=int, default=10, help="Число параллельных потоков Xray (по умолчанию: 10)"
    )
    parser.add_argument(
        "--tls", action="store_true", default=True, help="Глубокая TLS проверка (fallback, если Xray выключен)"
    )
    parser.add_argument(
        "--no-tls", dest="tls", action="store_false", help="Только быстрый TCP пинг"
    )
    parser.add_argument(
        "--max-ping", type=int, default=300, help="Максимально допустимый TCP пинг в мс (по умолчанию: 300)"
    )
    parser.add_argument("--threads", type=int, default=35, help="Число параллельных потоков для TCP пинга")
    parser.add_argument(
        "--limit-check", type=int, default=1000, help="Максимум ключей для проверки за один прогон"
    )
    parser.add_argument(
        "--max-sub", type=int, default=MAX_SUB_SERVERS,
        help=f"Максимум серверов в sub.txt (по умолчанию: {MAX_SUB_SERVERS})"
    )
    args = parser.parse_args()

    collected_keys: list[str] = []

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
    urls = [
        line.split("|")[0].strip()
        for line in valid_lines
        if line.split("|")[0].strip().startswith("http")
    ]
    urls = list(dict.fromkeys(urls))

    print(f"[*] Быстрый параллельный опрос {len(urls)} подписок...")
    start_fetch = time.perf_counter()
    sub_results = fetch_all_subs_parallel(urls, max_workers=args.threads, timeout=8.0)
    for u, keys in sub_results.items():
        collected_keys.extend(keys)

    fetch_time = round(time.perf_counter() - start_fetch, 1)

    # Очищаем и дедуплицируем собранные ключи
    unique_keys = deduplicate_keys(collected_keys)

    # Фильтруем от цензуры/спама (порты 443/8443, без toxic SNI) и диверсифицируем по подсетям
    clean_candidates = filter_and_diversify_keys(unique_keys, max_per_subnet=3)
    print(f"[*] Собрано {len(unique_keys)} уникальных сырых ключей (за {fetch_time} сек).")
    print(f"[*] Отобрано {len(clean_candidates)} качественных кандидатов для проверки.")

    if not clean_candidates:
        print("[!] Нет подходящих ключей для проверки.")
        return

    # Приоритет: сначала VLESS Reality на 443 порту с российскими и корпоративными SNI
    def key_priority(k: str) -> int:
        k_lower = k.lower()
        d = parse_key_details(k)
        port = d.get("port") if d else None
        sni = (d.get("sni") or "").lower() if d else ""
        
        is_ru_or_corp = any(domain in sni for domain in [
            ".ru", "videobereg.cc", "samsung.com", "logitech.com",
            "apple.com", "microsoft.com", "nvidia.com", "yandex", "vk"
        ])

        if "reality" in k_lower and port == 443 and is_ru_or_corp:
            return 0
        if "reality" in k_lower and port == 443:
            return 1
        if "reality" in k_lower:
            return 2
        if k_lower.startswith("vless://"):
            return 3
        if k_lower.startswith("trojan://"):
            return 4
        if k_lower.startswith("hy2://") or k_lower.startswith("hysteria2://"):
            return 5
        return 6

    clean_candidates.sort(key=key_priority)

    keys_to_ping = clean_candidates[: args.limit_check] if args.limit_check > 0 else clean_candidates
    print(
        f"[*] Этап 1: Предварительный TCP-фильтр {len(keys_to_ping)} ключей"
        f" (порог < {args.max_ping} мс)..."
    )

    tcp_candidates: list[tuple[float, str]] = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(ping_key, key, 1.5): key for key in keys_to_ping}
        for i, future in enumerate(as_completed(futures), 1):
            key, latency = future.result()
            if latency is not None and latency < args.max_ping:
                tcp_candidates.append((latency, key))
                if len(tcp_candidates) % 25 == 0:
                    print(f"    [{i}/{len(keys_to_ping)}] Найдено доступных по TCP: {len(tcp_candidates)}")

    tcp_candidates.sort(key=lambda x: x[0])
    candidates = [k for _, k in tcp_candidates]
    print(f"[OK] Этап 1 завершен: {len(candidates)} кандидатов с открытым портом.")

    verified_fast_keys: list[str] = []
    check_name = "TCP Ping"

    # Этап 2: Глубокая проверка реального трафика через Xray (если доступен)
    xray_bin = ensure_xray_binary() if args.xray else None
    if xray_bin and candidates:
        check_name = "Xray Core 204 Real Traffic Check"
        to_verify = candidates[: args.limit_xray]
        print(f"\n[*] Этап 2: Глубокая проверка {len(to_verify)} лучших кандидатов через Xray Core...")
        verified_results = batch_verify_keys_xray(
            to_verify, xray_bin, max_workers=args.xray_threads, timeout=3.5
        )
        verified_fast_keys = [k for _, k in verified_results]
    else:
        # Fallback: проверка через TLS Handshake или TCP
        check_fn = ping_and_tls_check if args.tls else ping_key
        check_name = "TLS Handshake" if args.tls else "TCP Ping"
        fallback_results: list[tuple[float, str]] = []
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(check_fn, key, 2.0): key for key in candidates[:args.limit_xray]}
            for future in as_completed(futures):
                key, latency = future.result()
                if latency is not None and latency < args.max_ping:
                    fallback_results.append((latency, key))
        fallback_results.sort(key=lambda x: x[0])
        verified_fast_keys = [k for _, k in fallback_results]

    print("=" * 65)
    print("[*] ИТОГИ ПРОВЕРКИ:")
    print(f"Метод проверки: {check_name}")
    print(f"Проверено кандидатов: {len(keys_to_ping)}")
    print(f"РЕАЛЬНО РАБОЧИХ серверов с доступом в интернет: {len(verified_fast_keys)}")

    if verified_fast_keys:
        safe_save_verified_keys(verified_fast_keys, max_sub_servers=args.max_sub)


if __name__ == "__main__":
    main()
