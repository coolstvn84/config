import os
import argparse
import logging
from collections import defaultdict
from typing import List


def sort_protocols(input_file: str, output_dir: str, protocols: List[str], write_unknown: bool = True) -> None:
    """Sort configs from input_file into files under output_dir by protocol.

    Args:
        input_file: Path to All_Configs_Sub.txt (one config per line)
        output_dir: Directory where <protocol>.txt files will be written
        protocols: List of protocols to extract (order preserved)
        write_unknown: Whether to write unmatched lines to unknown.txt
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        logging.error("Failed to create output directory %s: %s", output_dir, e)
        return

    sorted_data = defaultdict(list)
    unknowns = []

    if not os.path.exists(input_file):
        logging.warning("Input file not found: %s", input_file)
        return

    logging.info("Sorting configs from %s...", input_file)

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                matched = False
                low = line.lower()
                for proto in protocols:
                    if low.startswith(f"{proto}://"):
                        sorted_data[proto].append(line)
                        matched = True
                        break

                if not matched:
                    unknowns.append(line)
    except Exception as e:
        logging.error("Failed to read input file %s: %s", input_file, e)
        return

    # Write files atomically
    for proto in protocols:
        file_path = os.path.join(output_dir, f"{proto}.txt")
        configs = sorted_data.get(proto, [])
        tmp_path = file_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as out:
                out.write(f"# {proto.upper()} Configs - Updated\n")
                out.write(f"# Count: {len(configs)}\n")
                if configs:
                    out.write("\n".join(configs) + "\n")
            os.replace(tmp_path, file_path)
            logging.info("Saved %d %s nodes -> %s", len(configs), proto.upper(), file_path)
        except Exception as e:
            logging.error("Failed to write %s: %s", file_path, e)
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    if write_unknown and unknowns:
        unknown_path = os.path.join(output_dir, "unknown.txt")
        tmp_unknown = unknown_path + ".tmp"
        try:
            with open(tmp_unknown, "w", encoding="utf-8") as out:
                out.write("# Unknown/Other Protocols - Lines that did not match known protocols\n")
                out.write(f"# Count: {len(unknowns)}\n")
                out.write("\n".join(unknowns) + "\n")
            os.replace(tmp_unknown, unknown_path)
            logging.info("Saved %d unknown nodes -> %s", len(unknowns), unknown_path)
        except Exception as e:
            logging.error("Failed to write unknown file %s: %s", unknown_path, e)
            try:
                os.remove(tmp_unknown)
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description="Split All_Configs_Sub.txt into protocol-specific files")
    parser.add_argument('--input', '-i', default=None, help='Input file (default ../All_Configs_Sub.txt)')
    parser.add_argument('--outdir', '-d', default=None, help='Output directory (default ../Splitted-By-Protocol)')
    parser.add_argument('--protocols', '-p', default=None, help='Comma-separated list of protocols (default set in script)')
    parser.add_argument('--no-unknown', action='store_true', help="Don't write unknown.txt")
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s'
    )

    base_path = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(base_path, ".."))
    input_file = args.input or os.path.join(root_dir, "All_Configs_Sub.txt")
    output_dir = args.outdir or os.path.join(root_dir, "Splitted-By-Protocol")

    default_protocols = ['vmess', 'vless', 'trojan', 'ss', 'ssr', 'hy2', 'tuic', 'warp']
    if args.protocols:
        protocols = [p.strip().lower() for p in args.protocols.split(',') if p.strip()]
    else:
        protocols = default_protocols

    sort_protocols(
        input_file=input_file,
        output_dir=output_dir,
        protocols=protocols,
        write_unknown=not args.no_unknown
    )
    logging.info("Sorting completed.")


if __name__ == "__main__":
    main()
  
