import os
import socket
import ssl
import threading
import base64
import json
import re
from queue import Queue

# Protocols that are most likely to bypass deep packet inspection (DPI)
TURKMEN_PROTOCOLS = ["vless", "hy2", "vmess", "trojan", "ss", "ssr", "tuic"]
# Protocols that usually wrap data in TLS
TLS_PROTOCOLS = ["vmess", "vless", "trojan"]

lock = threading.Lock()

def tls_handshake_check(host, port, timeout=5):
    """
    Attempts a real TLS handshake. 
    Crucial for bypassing blocks that allow TCP but kill SSL.
    """
    try:
        # Create a context that ignores expired/self-signed certs (common in free nodes)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except Exception:
        return False

def tcp_check(host, port, timeout=3):
    """Fallback for protocols like Shadowsocks or Hysteria2"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def parse_config(line):
    """Extracts Host and Port from various V2Ray URI formats."""
    try:
        if line.startswith("vmess://"):
            b64_data = line[8:].split('#')[0] # Remove remarks
            missing_padding = len(b64_data) % 4
            if missing_padding:
                b64_data += '=' * (4 - missing_padding)
            data = json.loads(base64.b64decode(b64_data).decode('utf-8'))
            return data.get("add"), int(data.get("port", 443))

        # Regex to handle protocol://[uuid/info]@host:port
        # Handles IPv6 [2001:db8::1]:8080 and IPv4 1.1.1.1:443
        match = re.search(r'@(?:\[?(.+?)\]?):(\d+)', line)
        if match:
            return match.group(1), int(match.group(2))
    except Exception:
        pass
    return None, None

def worker(q, results):
    while not q.empty():
        config = q.get()
        host, port = parse_config(config)
        
        if host and port:
            is_tls = any(config.lower().startswith(p) for p in TLS_PROTOCOLS)
            
            # Perform the check
            success = tls_handshake_check(host, port) if is_tls else tcp_check(host, port)
            
            if success:
                with lock:
                    if config not in results:
                        results.append(config)
        q.task_done()

def main():
    # Dynamic pathing based on your folder structure
    base_path = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(base_path, "..", "All_Configs_Sub.txt")
    output_file = os.path.join(base_path, "..", "Turkmenistan_Alive.txt")

    if not os.path.exists(input_file):
        print(f"❌ Input file not found: {input_file}")
        return

    with open(input_file, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    # Filter for protocols that generally work better in TM
    candidates = [l for l in lines if any(l.lower().startswith(p + "://") for p in TURKMEN_PROTOCOLS)]
    
    print(f"🔍 Testing {len(candidates)} candidates for Turkmenistan...")

    q = Queue()
    for c in candidates:
        q.put(c)

    alive_configs = []
    threads = []
    for _ in range(60): # Higher thread count for faster validation
        t = threading.Thread(target=worker, args=(q, alive_configs))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    # Save results
    with open(output_file, "w", encoding="utf-8") as f:
        header = "#profile-title: base64:8J+HuPCfhY0gVHVya21lbmlzdGFuIFZlcmlmaWVk\n"
        f.write(header)
        f.write("\n".join(alive_configs))

    print(f"✅ Success! {len(alive_configs)} nodes verified and saved to Turkmenistan_Alive.txt")

if __name__ == "__main__":
    main()
              
