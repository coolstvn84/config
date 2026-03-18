import os
from collections import defaultdict

def sort_protocols():
    # Path configuration
    base_path = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(base_path, ".."))
    input_file = os.path.join(root_dir, "All_Configs_Sub.txt")
    output_dir = os.path.join(root_dir, "Splitted-By-Protocol")

    # 1. Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # 2. Define protocols we care about
    protocols = ['vmess', 'vless', 'trojan', 'ss', 'ssr', 'hy2', 'tuic', 'warp']
    
    # Use a dictionary to store lists of configs for each protocol
    # This avoids opening/closing files repeatedly in a loop
    sorted_data = defaultdict(list)

    # 3. Read and Sort in memory
    if not os.path.exists(input_file):
        print(f"⚠️ {input_file} not found. Skipping sort.")
        return

    print(f"📂 Sorting configs from {input_file}...")
    
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                
            for proto in protocols:
                if line.lower().startswith(f"{proto}://"):
                    sorted_data[proto].append(line)
                    break

    # 4. Batch Write to files
    for proto in protocols:
        file_path = os.path.join(output_dir, f"{proto}.txt")
        configs = sorted_data[proto]
        
        with open(file_path, "w", encoding="utf-8") as out:
            # Add a header for the subscription
            out.write(f"# {proto.upper()} Configs - Updated 🤝\n")
            if configs:
                out.write("\n".join(configs) + "\n")
        
        print(f"✅ Saved {len(configs)} {proto.upper()} nodes.")

    print("✨ Sorting completed successfully!")

if __name__ == "__main__":
    sort_protocols()
  
