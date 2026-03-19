import os
import socket
import ssl
import threading
import base64
import json
import re
import glob
from queue import Queue

# Configuration
TURKMEN_PROTOCOLS = ["vless", "hy2", "vmess", "trojan", "ss", "ssr", "tuic"]
TLS_PROTOCOLS = ["vmess", "vless", "trojan"]
CHUNK_SIZE = 1000
THREADS = 80

lock = threading.Lock()

def tls_handshake_check(host, port, timeout=5):
    """Verifies if the server can actually complete a TLS handshake."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except:
        return False

def tcp_check(host, port, timeout=3):
    """Simple TCP check for non-TLS protocols."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def parse_config(line):
    """Extracts connection details from proxy URIs."""
    try:
        if line.startswith("vmess://"):
            b64_data = line[8:].split('#')[0]
            missing_padding = len(b64_data) % 4
            if missing_padding: b64_data += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            return data.get("add"), int(data.get("port", 443))
        match = re.search(r'@(?:\[?(.+?)\]?):(\d+)', line)
        if match: return match.group(1), int(match.group(2))
    except: pass
    return None, None

def worker(q, alive_list):
    while not q.empty():
        config = q.get()
        host, port = parse_config(config)
        if host and port:
            is_tls = any(config.lower().startswith(p) for p in TLS_PROTOCOLS)
            success = tls_handshake_check(host, port) if is_tls else tcp_check(host, port)
            if success:
                with lock:
                    if config not in alive_list:
                        alive_list.append(config)
        q.task_done()

def main():
    base_path = os.path.dirname(os.path.abspath(__file__))
    root_path = os.path.abspath(os.path.join(base_path, ".."))
    
    input_file = os.path.join(root_path, "All_Configs_Sub.txt")
    master_output = os.path.join(root_path, "Turkmenistan_Alive.txt")

    # --- 1. CLEANUP OLD FILES ---
    print("🧹 Cleaning up old results...")
    if os.path.exists(master_output):
        os.remove(master_output)
    
    # Find and remove all sub*.txt files in root
    old_subs = glob.glob(os.path.join(root_path, "sub*.txt"))
    for f in old_subs:
        try:
            os.remove(f)
        except: pass

    # --- 2. VALIDATION PROCESS ---
    if not os.path.exists(input_file):
        print(f"❌ Error: {input_file} not found.")
        return

    with open(input_file, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    candidates = [l for l in lines if any(l.lower().startswith(p + "://") for p in TURKMEN_PROTOCOLS)]
    print(f"🔍 Testing {len(candidates)} nodes...")

    q = Queue()
    for c in candidates: q.put(c)

    alive_configs = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker, args=(q, alive_configs))
        t.daemon = True
        t.start()

    q.join()

    # --- 3. WRITING NEW RESULTS ---
    header = "#profile-title: base64:8J+HuPCfhY0gVHVya21lbmlzdGFuIFZlcmlmaWVk\n"

    # Save the Master File
    with open(master_output, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(alive_configs))
    print(f"✅ Master file saved: Turkmenistan_Alive.txt ({len(alive_configs)} total)")

    # Save Divided Subs
    for i in range(0, len(alive_configs), CHUNK_SIZE):
        chunk = alive_configs[i : i + CHUNK_SIZE]
        sub_idx = (i // CHUNK_SIZE) + 1
        sub_path = os.path.join(root_path, f"sub{sub_idx}.txt")
        
        with open(sub_path, "w", encoding="utf-8") as f:
            f.write(header + "\n".join(chunk))
        print(f"📄 Created: sub{sub_idx}.txt")

    print("\n✨ All operations complete.")

if __name__ == "__main__":
    main()
    
