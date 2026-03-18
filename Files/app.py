import pybase64
import json
import re
import requests
import os
import socket
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
TIMEOUT = 15
MAX_WORKERS = 40  # Increased for more links
PING_TIMEOUT = 1.8 
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

FIXED_HEADER = """#profile-title: base64:8J+GkyBHaXRodWIgfCBCYXJyeS1mYXIg8J+ltw==
#profile-update-interval: 1
#subscription-userinfo: upload=0; download=0; total=10737418240000; expire=0
#support-url: https://github.com/barry-far/V2ray-config
"""

PROTOCOLS = ["vmess://", "vless://", "trojan://", "ss://", "ssr://", "hy2://", "tuic://", "warp://"]

# ------------------- SOURCE LINKS -------------------

# Links that return Base64 encoded strings
BASE64_SOURCES = [
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/app/sub.txt",
    "https://raw.githubusercontent.com/yebekhe/vpn-fail/main/sub-link",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
    "https://raw.githubusercontent.com/ninjastrikers/v2ray-configs/main/All_Configs_base64_Sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_base64_Sub.txt",
    "https://raw.githubusercontent.com/tbbatbb/Proxy/main/dist/v2ray.txt",
    "https://raw.githubusercontent.com/vpei/Free-Node-Merge/master/out/node.txt",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all"
]

# Links that return plain text (one config per line)
PLAIN_SOURCES = [
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/all_extracted_configs.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/AllConfigsSub.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/IranianCypherpunks/sub/main/config",
    "https://raw.githubusercontent.com/sashalsk/V2Ray/main/V2Config",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/sarinaesmailzadeh/V2Hub/main/merged",
    "https://raw.githubusercontent.com/C4ssif3r/V2ray-sub/main/all.txt",
    "https://raw.githubusercontent.com/miladtahanian/Config-Collector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/v2rayng-wg.txt",
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/v2ray/base64",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/result/nodes",
    "https://raw.githubusercontent.com/LonUp/NodeList/main/V2RAY/Latest.txt",
    "https://raw.githubusercontent.com/mose-design/v2ray-server/main/config/v2ray-server.txt",
    "https://raw.githubusercontent.com/vakhov/free-v2ray-configs/main/configs.txt",
    "https://mr-v2ray.top/free_v2ray/all_configs.txt",
    "https://sub.f94.top/api/v1/client/subscribe?token=4943f615f5d342a39626b84013444983",
    "https://raw.githubusercontent.com/HebeV2/HebeV2/main/free.txt"
]

# ------------------- UTILITIES -------------------

def decode_b64(data):
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        missing_padding = len(data) % 4
        if missing_padding:
            data += b'=' * (4 - missing_padding)
        return pybase64.b64decode(data).decode("utf-8", errors="ignore")
    except:
        return ""

def fetch_url(url, is_base64=False):
    try:
        res = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
        if res.status_code == 200:
            content = res.text
            # Some "base64" links are actually double-encoded or plain
            if is_base64 and not any(p in content[:20] for p in PROTOCOLS):
                return decode_b64(content)
            return content
    except:
        pass
    return ""

def extract_host_port(config):
    try:
        if config.startswith("vmess://"):
            decoded = decode_b64(config[8:])
            data = json.loads(decoded)
            return data.get("add"), int(data.get("port", 443))
        match = re.search(r'@([^/:]+):(\d+)', config)
        if match:
            return match.group(1), int(match.group(2))
    except:
        pass
    return None, None

def check_connection(config):
    host, port = extract_host_port(config)
    if not host or not port: return None
    try:
        with socket.create_connection((host, port), timeout=PING_TIMEOUT) as sock:
            return config
    except:
        return None

# ------------------- MAIN -------------------

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(root_dir, "..", "All_Configs_Sub.txt")

    # Shuffle to vary the order of fetching
    random.shuffle(BASE64_SOURCES)
    random.shuffle(PLAIN_SOURCES)

    print(f"🌐 Fetching from {len(BASE64_SOURCES) + len(PLAIN_SOURCES)} sources...")
    all_raw = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        tasks = {executor.submit(fetch_url, url, True): url for url in BASE64_SOURCES}
        tasks.update({executor.submit(fetch_url, url, False): url for url in PLAIN_SOURCES})
        
        for future in as_completed(tasks):
            result = future.result()
            if result: all_raw.append(result)

    print("🧹 Cleaning & Deduplicating...")
    unique_set = set()
    final_candidates = []

    for batch in all_raw:
        for line in batch.splitlines():
            line = line.strip()
            if any(line.lower().startswith(p) for p in PROTOCOLS):
                # Use the core part (before #) for deduplication
                core = line.split('#')[0] if '#' in line else line
                if core not in unique_set:
                    unique_set.add(core)
                    final_candidates.append(line)

    print(f"📡 Testing {len(final_candidates)} nodes for life...")
    alive_nodes = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = [executor.submit(check_connection, c) for c in final_candidates]
        for res in as_completed(results):
            if res.result():
                alive_nodes.append(res.result())

    print(f"💾 Saving {len(alive_nodes)} alive nodes...")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(FIXED_HEADER + "\n".join(alive_nodes))

    print("✨ Finished successfully.")

if __name__ == "__main__":
    main()
                                     
