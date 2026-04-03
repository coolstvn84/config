import pybase64
import json
import re
import requests
import os
import socket
import random
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Set
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Configuration ---
DEFAULT_TIMEOUT = 15
DEFAULT_MAX_WORKERS = 50
DEFAULT_PING_TIMEOUT = 2.0
DEFAULT_RETRIES = 2

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Encoding": "gzip, deflate",
    "Accept": "*/*",
    "Connection": "keep-alive"
}

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
    "https://raw.githubusercontent.com/Leon406/SubCrawler/main/sub/share/all",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/base64_all",
    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/v2rayng.txt",
    "https://raw.githubusercontent.com/freefq/free/main/v2",
    "https://raw.githubusercontent.com/Jsnzkpg/Jsnzkpg/Jsnzkpg/Jsnzkpg"
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
    "https://raw.githubusercontent.com/HebeV2/HebeV2/main/free.txt",
    "https://raw.githubusercontent.com/alanbobs999/TopFreeProxies/master/Eternity.txt",
    "https://raw.githubusercontent.com/Paw3l/free-proxy-list/main/configs.txt",
    "https://raw.githubusercontent.com/peasoft/NodelFree/main/Nodes.txt",
    "https://raw.githubusercontent.com/solikethis/solis/main/All"
]


# ------------------- UTILITIES -------------------

def create_session_with_retries(retries: int = DEFAULT_RETRIES, timeout: int = DEFAULT_TIMEOUT) -> requests.Session:
    """Create a requests session with retry strategy and connection pooling."""
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def decode_b64(data: str) -> str:
    """Decode base64 data safely."""
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        missing_padding = len(data) % 4
        if missing_padding:
            data += b'=' * (4 - missing_padding)
        return pybase64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception as e:
        logging.debug("Base64 decode error: %s", e)
        return ""


def fetch_url(session: requests.Session, url: str, is_base64: bool = False, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Fetch and decode content from a URL."""
    try:
        res = session.get(url, timeout=timeout, headers=HEADERS)
        if res.status_code == 200:
            content = res.text
            # Some "base64" links are actually double-encoded or plain
            if is_base64 and not any(p in content[:20] for p in PROTOCOLS):
                return decode_b64(content)
            return content
        else:
            logging.debug("Non-200 status from %s: %d", url, res.status_code)
    except requests.Timeout:
        logging.debug("Timeout fetching %s", url)
    except requests.RequestException as e:
        logging.debug("Request error for %s: %s", url, e)
    except Exception as e:
        logging.debug("Unexpected error fetching %s: %s", url, e)
    return ""


def extract_host_port(config: str) -> Tuple[Optional[str], Optional[int]]:
    """Extract host and port from a proxy config string."""
    try:
        if config.startswith("vmess://"):
            decoded = decode_b64(config[8:])
            data = json.loads(decoded)
            return data.get("add"), int(data.get("port", 443))
        match = re.search(r'@([^/:]+):(\d+)', config)
        if match:
            return match.group(1), int(match.group(2))
    except Exception as e:
        logging.debug("Parse error for config: %s", e)
    return None, None


def check_connection(config: str, timeout: float = DEFAULT_PING_TIMEOUT) -> Optional[str]:
    """Check if a config node is reachable via TCP."""
    host, port = extract_host_port(config)
    if not host or not port:
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return config
    except Exception:
        pass
    return None


# ------------------- MAIN -------------------

def main():
    parser = argparse.ArgumentParser(description="Fetch, deduplicate, and test V2Ray/proxy configs from multiple sources")
    parser.add_argument('--output', '-o', default=None, help='Output file (default ../All_Configs_Sub.txt)')
    parser.add_argument('--workers', '-w', type=int, default=DEFAULT_MAX_WORKERS, help='Number of concurrent workers')
    parser.add_argument('--timeout', '-t', type=int, default=DEFAULT_TIMEOUT, help='HTTP request timeout in seconds')
    parser.add_argument('--ping-timeout', type=float, default=DEFAULT_PING_TIMEOUT, help='TCP ping timeout in seconds')
    parser.add_argument('--retries', '-r', type=int, default=DEFAULT_RETRIES, help='HTTP request retries')
    parser.add_argument('--skip-check', action='store_true', help='Skip alive node checking')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )

    base_path = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(base_path, ".."))
    output_path = args.output or os.path.join(root_dir, "All_Configs_Sub.txt")

    # Shuffle to vary fetch order
    random.shuffle(BASE64_SOURCES)
    random.shuffle(PLAIN_SOURCES)

    total_sources = len(BASE64_SOURCES) + len(PLAIN_SOURCES)
    logging.info("Fetching from %d sources...", total_sources)

    session = create_session_with_retries(retries=args.retries, timeout=args.timeout)
    all_raw: List[str] = []

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            tasks = {
                executor.submit(fetch_url, session, url, True, args.timeout): url
                for url in BASE64_SOURCES
            }
            tasks.update({
                executor.submit(fetch_url, session, url, False, args.timeout): url
                for url in PLAIN_SOURCES
            })

            completed = 0
            for future in as_completed(tasks):
                try:
                    result = future.result()
                    if result:
                        all_raw.append(result)
                    completed += 1
                except Exception as e:
                    logging.debug("Task failed: %s", e)
                    completed += 1

        logging.info("Fetched from %d/%d sources", len(all_raw), total_sources)
    except Exception as e:
        logging.error("Error during fetch phase: %s", e)
        return
    finally:
        session.close()

    logging.info("Cleaning & deduplicating...")
    unique_set: Set[str] = set()
    final_candidates: List[str] = []

    for batch in all_raw:
        for line in batch.splitlines():
            line = line.strip()
            if any(line.lower().startswith(p) for p in PROTOCOLS):
                # Use the core part (before #) for deduplication
                core = line.split('#')[0] if '#' in line else line
                if core not in unique_set:
                    unique_set.add(core)
                    final_candidates.append(line)

    logging.info("Deduplicated to %d unique configs", len(final_candidates))

    alive_nodes: List[str] = []
    if args.skip_check:
        alive_nodes = final_candidates
        logging.info("Skipping alive check (--skip-check enabled)")
    else:
        logging.info("Testing %d nodes for connectivity...", len(final_candidates))
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [
                executor.submit(check_connection, c, args.ping_timeout)
                for c in final_candidates
            ]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        alive_nodes.append(result)
                except Exception as e:
                    logging.debug("Check failed: %s", e)

        logging.info("Found %d alive nodes", len(alive_nodes))

    logging.info("Saving %d configs to %s...", len(alive_nodes), output_path)
    tmp_output = output_path + ".tmp"
    try:
        with open(tmp_output, "w", encoding="utf-8") as f:
            f.write(FIXED_HEADER)
            if alive_nodes:
                f.write("\n".join(alive_nodes))
        os.replace(tmp_output, output_path)
        logging.info("Successfully saved configs")
    except Exception as e:
        logging.error("Failed to save output: %s", e)
        try:
            os.remove(tmp_output)
        except Exception:
            pass
        return

    logging.info("Finished successfully.")

if __name__ == "__main__":
    main()
                                     
