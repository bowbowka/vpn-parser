import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_CHECK_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204"
]

def ensure_xray_binary(dest_dir: str = "/home/bowka/vpn-parser/bin") -> str | None:
    """Проверяет наличие Xray, при необходимости скачивает релиз для linux-64."""
    # 1. Системный xray в PATH
    sys_xray = shutil.which("xray")
    if sys_xray:
        return sys_xray

    # 2. Локальный binary в bin/
    local_bin = os.path.join(dest_dir, "xray")
    if os.path.exists(local_bin) and os.access(local_bin, os.X_OK):
        return local_bin

    # 3. Скачиваем официальный XTLS релиз для Linux x86_64
    if sys.platform.startswith("linux") and os.uname().machine in ("x86_64", "amd64"):
        try:
            os.makedirs(dest_dir, exist_ok=True)
            import zipfile
            url = "https://github.com/XTLS/Xray-core/releases/download/v24.11.11/Xray-linux-64.zip"
            zip_path = os.path.join(dest_dir, "xray.zip")
            print("[*] Скачивание Xray Core для глубокой проверки трафика...")
            urllib.request.urlretrieve(url, zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extract("xray", dest_dir)
            os.chmod(local_bin, 0o755)
            if os.path.exists(zip_path):
                os.remove(zip_path)
            print("[OK] Xray Core успешно установлен.")
            return local_bin
        except Exception as e:
            print(f"[!] Ошибка скачивания Xray Core: {e}")
            return None

    return None

def key_to_xray_outbound(key: str) -> dict | None:
    """Генерирует outbound-конфиг для Xray из URL (VLESS, Trojan, SS, VMess)."""
    try:
        if "://" not in key:
            return None
        proto, rest = key.split("://", 1)
        proto = proto.lower()

        if proto == "vless":
            parsed = urllib.parse.urlparse(key)
            uuid = parsed.username
            host = parsed.hostname
            port = parsed.port or 443
            if not uuid or not host:
                return None

            params = urllib.parse.parse_qs(parsed.query)
            sec = params.get("security", ["none"])[0].lower()
            net = params.get("type", ["tcp"])[0].lower()
            sni = params.get("sni", [host])[0]
            fp = params.get("fp", ["firefox"])[0]
            flow = params.get("flow", [""])[0]
            pbk = params.get("pbk", [""])[0]
            sid = params.get("sid", [""])[0]
            path = params.get("path", ["/"])[0]
            ws_host = params.get("host", [""])[0] or sni
            service_name = params.get("serviceName", [""])[0]

            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{"id": uuid, "encryption": "none", "flow": flow}]
                    }]
                },
                "streamSettings": {
                    "network": net,
                    "security": sec
                }
            }

            if sec == "reality":
                if not pbk:
                    return None
                outbound["streamSettings"]["realitySettings"] = {
                    "fingerprint": fp,
                    "serverName": sni,
                    "publicKey": pbk,
                    "shortId": sid
                }
            elif sec in ("tls", "1", "true") or port == 443:
                outbound["streamSettings"]["security"] = "tls"
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": sni,
                    "fingerprint": fp
                }

            if net == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": path,
                    "headers": {"Host": ws_host}
                }
            elif net == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": service_name,
                    "multiMode": True
                }
            return outbound

        elif proto == "trojan":
            parsed = urllib.parse.urlparse(key)
            password = parsed.username
            host = parsed.hostname
            port = parsed.port or 443
            if not password or not host:
                return None
            params = urllib.parse.parse_qs(parsed.query)
            sni = params.get("sni", [host])[0]
            net = params.get("type", ["tcp"])[0].lower()

            return {
                "protocol": "trojan",
                "settings": {
                    "servers": [{"address": host, "port": port, "password": password}]
                },
                "streamSettings": {
                    "network": net,
                    "security": "tls",
                    "tlsSettings": {"serverName": sni}
                }
            }

        elif proto == "ss":
            body = rest.split("#")[0]
            if "@" in body:
                user_info, hp = body.split("@", 1)
                for dec in [base64.b64decode, base64.urlsafe_b64decode]:
                    try:
                        user_info = dec(user_info.encode() + b"==").decode()
                        break
                    except Exception:
                        pass
                if ":" in user_info:
                    method, password = user_info.split(":", 1)
                else:
                    return None
                parts = hp.rsplit(":", 1)
                host, port = parts[0], int(parts[1])
            else:
                return None

            return {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{"address": host, "port": port, "method": method, "password": password}]
                }
            }

        elif proto == "vmess":
            b64_payload = rest.split("#")[0].split("?")[0].strip()
            rem = len(b64_payload) % 4
            if rem:
                b64_payload += "=" * (4 - rem)
            decoded = None
            for dec in [base64.b64decode, base64.urlsafe_b64decode]:
                try:
                    decoded = dec(b64_payload.encode()).decode()
                    break
                except Exception:
                    pass
            if not decoded:
                return None
            data = json.loads(decoded)
            host = data.get("add") or data.get("host")
            port = int(data.get("port", 0))
            uuid = data.get("id")
            aid = int(data.get("aid", 0))
            net = data.get("net", "tcp")
            tls_val = str(data.get("tls", "")).lower()
            is_tls = tls_val in ("tls", "1", "true") or port == 443

            if not host or not port or not uuid:
                return None

            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{"id": uuid, "alterId": aid, "security": "auto"}]
                    }]
                },
                "streamSettings": {
                    "network": net,
                    "security": "tls" if is_tls else "none"
                }
            }
            if is_tls:
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": data.get("sni") or host
                }
            return outbound

    except Exception:
        return None
    return None

def test_single_key_real_traffic(key: str, xray_bin: str, worker_id: int = 0, timeout: float = 3.5) -> tuple[str, float | None]:
    """Проверяет реальный проход интернет-трафика (204) через Xray core."""
    outbound = key_to_xray_outbound(key)
    if not outbound:
        return key, None

    port = 12000 + (worker_id % 50)
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "http"}],
        "outbounds": [outbound]
    }
    cfg_file = f"/tmp/xray_cfg_{port}.json"
    with open(cfg_file, "w") as f:
        json.dump(cfg, f)

    proc = None
    try:
        proc = subprocess.Popen([xray_bin, "run", "-c", cfg_file],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)

        start = time.perf_counter()
        proxy_handler = urllib.request.ProxyHandler({'http': f'http://127.0.0.1:{port}'})
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request(DEFAULT_CHECK_URLS[0], headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=timeout) as resp:
            if resp.status in (200, 204):
                lat = round((time.perf_counter() - start) * 1000, 1)
                return key, lat
    except Exception:
        pass
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except Exception:
                proc.kill()
        if os.path.exists(cfg_file):
            try:
                os.remove(cfg_file)
            except Exception:
                pass

    return key, None

def batch_verify_keys_xray(keys: list[str], xray_bin: str, max_workers: int = 10, timeout: float = 3.5) -> list[tuple[float, str]]:
    """Параллельно проверяет список ключей на реальный трафик через Xray."""
    results = []
    print(f"[*] Глубокая проверка {len(keys)} ключей через Xray Core (выход в Интернет)...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(test_single_key_real_traffic, key, xray_bin, i, timeout): key
            for i, key in enumerate(keys)
        }
        for i, fut in enumerate(as_completed(futures), 1):
            key, lat = fut.result()
            name = urllib.parse.unquote(key.split("#")[-1]) if "#" in key else key[:30]
            if lat is not None:
                print(f"[{i}/{len(keys)}] [OK 204] {lat} ms | {name}")
                results.append((lat, key))
            else:
                if i % 15 == 0:
                    print(f"[{i}/{len(keys)}] Проверено {i} ключей...")

    results.sort(key=lambda x: x[0])
    return results
