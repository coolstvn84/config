import os
import socket
import ssl
import threading
import base64
import json
import re
import glob
import argparse
import logging
from queue import Queue, Empty
from typing import Optional, Tuple, List

# Configuration defaults
TURKMEN_PROTOCOLS = ["vless", "hy2", "vmess", "trojan", "ss", "ssr", "tuic"]
TLS_PROTOCOLS = ["vmess", "vless", "trojan"]
CHUNK_SIZE = 1000
DEFAULT_THREADS = 40

lock = threading.Lock()


def resolve_host(host: str) -> List[Tuple[int, int, int, str, tuple]]:
    """Resolve host to all available address infos (supports IPv4/IPv6).

    Returns the list from socket.getaddrinfo. Caller should handle failures.
    """
    try:
        return socket.getaddrinfo(host, None)
    except Exception:
        return []


def _attempt_connect(addr_info, port: int, timeout: float, use_tls: bool, server_hostname: Optional[str] = None) -> bool:
    family, socktype, proto, canonname, sockaddr = addr_info
    # sockaddr may contain an address and port placeholder; create socket and connect to (addr, port)
    try:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect((sockaddr[0], port))
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock, server_hostname=server_hostname or sockaddr[0]):
                    return True
            else:
                sock.close()
                return True
        finally:
            # If TLS wrapped socket returned True above, socket already closed by context manager; safe to ignore
            try:
                sock.close()
            except Exception:
                pass
    except Exception:
        return False


def tls_handshake_check(host: str, port: int, timeout: float = 5.0, retries: int = 1) -> bool:
    """Try TLS handshake on resolved addresses. Retries allowed."""
    infos = resolve_host(host)
    if not infos:
        # fallback: try raw host
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (host,))]

    for attempt in range(max(1, retries)):
        for info in infos:
            if _attempt_connect(info, port, timeout, use_tls=True, server_hostname=host):
                return True
    return False


def tcp_check(host: str, port: int, timeout: float = 3.0, retries: int = 1) -> bool:
    """Try TCP connect to host:port across resolved addresses."""
    infos = resolve_host(host)
    if not infos:
        infos = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (host,))]

    for attempt in range(max(1, retries)):
        for info in infos:
            if _attempt_connect(info, port, timeout, use_tls=False):
                return True
    return False


def parse_config(line: str) -> Tuple[Optional[str], Optional[int]]:
    """Extracts connection details from proxy URIs.

    Supports:
    - vmess://<base64>
    - <scheme>://...@host:port
    - fallback regex that captures host:port
    """
    try:
        line = line.strip()
        if not line:
            return None, None

        lower = line.lower()
        if lower.startswith("vmess://"):
            b64_data = line[8:].split('#')[0]
            missing_padding = len(b64_data) % 4
            if missing_padding:
                b64_data += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            return data.get("add"), int(data.get("port", 443))

        # Generic: look for user@host:port or just host:port
        match = re.search(r'@(?:\[?(.+?)\]?):(\d+)', line)
        if match:
            return match.group(1), int(match.group(2))

        match = re.search(r'^(?:[a-z0-9+.-]+://)?\[?(.+?)\]?:?(\d+)$', line, re.I)
        if match:
            return match.group(1), int(match.group(2))
    except Exception:
        logging.debug("parse_config failed for line: %s", line, exc_info=True)
    return None, None


def worker(q: Queue, alive_list: list, use_tls_schemes: List[str], timeouts: dict, retries: int):
    while True:
        try:
            config = q.get_nowait()
        except Empty:
            break
        try:
            host, port = parse_config(config)
            if host and port:
                # Determine scheme from the start of the line
                scheme_match = re.match(r'^([a-z0-9]+)://', config, re.I)
                scheme = scheme_match.group(1).lower() if scheme_match else ''
                is_tls = scheme in use_tls_schemes

                success = False
                if is_tls:
                    success = tls_handshake_check(host, port, timeout=timeouts.get('tls', 5.0), retries=retries)
                else:
                    success = tcp_check(host, port, timeout=timeouts.get('tcp', 3.0), retries=retries)

                if success:
                    with lock:
                        if config not in alive_list:
                            alive_list.append(config)
        except Exception:
            logging.debug("worker error on config: %s", config, exc_info=True)
        finally:
            q.task_done()


def main():
    parser = argparse.ArgumentParser(description="Validate Turkmenistan proxy nodes by basic connectivity/TLS handshake.")
    parser.add_argument('--input', '-i', default=None, help='Input file (default ../All_Configs_Sub.txt)')
    parser.add_argument('--output', '-o', default=None, help='Output master file (default ../Turkmenistan_Alive.txt)')
    parser.add_argument('--threads', '-t', type=int, default=DEFAULT_THREADS, help='Number of worker threads')
    parser.add_argument('--tcp-timeout', type=float, default=3.0, help='TCP connect timeout in seconds')
    parser.add_argument('--tls-timeout', type=float, default=5.0, help='TLS handshake timeout in seconds')
    parser.add_argument('--retries', type=int, default=1, help='Connection retries per address')
    parser.add_argument('--chunk-size', type=int, default=CHUNK_SIZE, help='Lines per chunk file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

    base_path = os.path.dirname(os.path.abspath(__file__))
    root_path = os.path.abspath(os.path.join(base_path, ".."))

    input_file = args.input or os.path.join(root_path, "All_Configs_Sub.txt")
    master_output = args.output or os.path.join(root_path, "Turkmenistan_Alive.txt")

    # --- 1. CLEANUP OLD FILES ---
    logging.info("Cleaning up old results...")
    try:
        if os.path.exists(master_output):
            os.remove(master_output)
    except Exception:
        logging.debug("Failed to remove old master output", exc_info=True)

    # Find and remove all sub*.txt files in root
    old_subs = glob.glob(os.path.join(root_path, "sub*.txt"))
    for f in old_subs:
        try:
            os.remove(f)
        except Exception:
            logging.debug("Failed to remove %s", f, exc_info=True)

    # --- 2. VALIDATION PROCESS ---
    if not os.path.exists(input_file):
        logging.error("Input file not found: %s", input_file)
        return

    with open(input_file, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    candidates = [l for l in lines if any(l.lower().startswith(p + "://") for p in TURKMEN_PROTOCOLS)]
    logging.info("Testing %d nodes...", len(candidates))

    q = Queue()
    for c in candidates:
        q.put(c)

    alive_configs = []
    threads_to_use = min(max(1, args.threads), max(1, q.qsize()))
    logging.info("Starting %d worker threads", threads_to_use)

    timeouts = {'tcp': args.tcp_timeout, 'tls': args.tls_timeout}

    threads = []
    for _ in range(threads_to_use):
        t = threading.Thread(target=worker, args=(q, alive_configs, TLS_PROTOCOLS, timeouts, args.retries))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    # Ensure threads terminate
    for t in threads:
        t.join(timeout=0.1)

    # --- 3. WRITING NEW RESULTS ---
    header = "#profile-title: base64:8J+HuPCfhY0gVHVya21lbmlzdGFuIFZlcmlmaWVk\n"

    try:
        # Save the Master File atomically
        tmp_master = master_output + ".tmp"
        with open(tmp_master, "w", encoding="utf-8") as f:
            f.write(header + "\n".join(alive_configs))
        os.replace(tmp_master, master_output)
        logging.info("Master file saved: %s (%d total)", master_output, len(alive_configs))
    except Exception:
        logging.exception("Failed to write master output")

    # Save Divided Subs
    for i in range(0, len(alive_configs), args.chunk_size):
        chunk = alive_configs[i: i + args.chunk_size]
        sub_idx = (i // args.chunk_size) + 1
        sub_path = os.path.join(root_path, f"sub{sub_idx}.txt")
        try:
            tmp_sub = sub_path + ".tmp"
            with open(tmp_sub, "w", encoding="utf-8") as f:
                f.write(header + "\n".join(chunk))
            os.replace(tmp_sub, sub_path)
            logging.info("Created: %s", sub_path)
        except Exception:
            logging.debug("Failed to write sub file %s", sub_path, exc_info=True)

    logging.info("All operations complete.")


if __name__ == "__main__":
    main()
    
