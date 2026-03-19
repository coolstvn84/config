"""
Turkmenistan Proxy Validator (check_tm.py)
Validates proxy configurations for connectivity in Turkmenistan
Supports: VLESS, Hy2, VMess, Trojan, SS, SSR, TUIC
"""

import asyncio
import base64
import json
import logging
import os
import re
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Set, List, Tuple
from datetime import datetime


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class Config:
    """Configuration for the validator"""
    # Proxy protocols
    SUPPORTED_PROTOCOLS: List[str] = field(default_factory=lambda: [
        "vless", "hy2", "vmess", "trojan", "ss", "ssr", "tuic"
    ])
    TLS_PROTOCOLS: List[str] = field(default_factory=lambda: [
        "vmess", "vless", "trojan"
    ])
    
    # Performance
    CHUNK_SIZE: int = 1000
    MAX_CONCURRENT_TASKS: int = 80
    TLS_TIMEOUT: float = 5.0
    TCP_TIMEOUT: float = 3.0
    
    # File paths
    INPUT_FILE: str = "All_Configs_Sub.txt"
    MASTER_OUTPUT: str = "Turkmenistan_Alive.txt"
    SUB_FILE_PREFIX: str = "sub"
    LOG_FILE: str = "turkmenistan_validator.log"
    
    # Profile header (base64 encoded: "рџ”’рџ•µпёЏ Turkmenistan Verified")
    PROFILE_HEADER: str = "#profile-title: base64:8J+HuPCfhY0gVHVya21lbmlzdGFuIFZlcmlmaWVk"


# ============================================================================
# Logging Setup
# ============================================================================

def setup_logging(log_file: Optional[str] = None) -> logging.Logger:
    """Configure logging with both console and file output"""
    logger = logging.getLogger("TurkmenValidator")
    
    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    
    # Format
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not setup file logging: {e}")
    
    return logger


logger = setup_logging()


# ============================================================================
# Connectivity Checks
# ============================================================================

async def check_tls_handshake(
    host: str,
    port: int,
    timeout: float = 5.0
) -> bool:
    """
    Verify TLS handshake with the server
    
    Args:
        host: Hostname or IP address
        port: Port number
        timeout: Connection timeout in seconds
        
    Returns:
        True if TLS handshake successful, False otherwise
    """
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        
        logger.debug(f"вњ“ TLS handshake successful: {host}:{port}")
        return True
        
    except asyncio.TimeoutError:
        logger.debug(f"вњ— TLS handshake timeout: {host}:{port}")
        return False
    except (OSError, ssl.SSLError) as e:
        logger.debug(f"вњ— TLS handshake failed: {host}:{port}")
        return False
    except Exception as e:
        logger.debug(f"вњ— Unexpected error during TLS check: {host}:{port}")
        return False


async def check_tcp_connection(
    host: str,
    port: int,
    timeout: float = 3.0
) -> bool:
    """
    Perform simple TCP connection check
    
    Args:
        host: Hostname or IP address
        port: Port number
        timeout: Connection timeout in seconds
        
    Returns:
        True if TCP connection successful, False otherwise
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        
        logger.debug(f"вњ“ TCP connection successful: {host}:{port}")
        return True
        
    except asyncio.TimeoutError:
        logger.debug(f"вњ— TCP connection timeout: {host}:{port}")
        return False
    except OSError as e:
        logger.debug(f"вњ— TCP connection failed: {host}:{port}")
        return False
    except Exception as e:
        logger.debug(f"вњ— Unexpected error during TCP check: {host}:{port}")
        return False


# ============================================================================
# Configuration Parsing
# ============================================================================

def parse_vmess_config(uri: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Parse VMess URI format
    
    Example: vmess://base64_encoded_json_data
    
    Args:
        uri: VMess URI string
        
    Returns:
        Tuple of (host, port) or (None, None) if parsing fails
    """
    try:
        # Remove vmess:// prefix and extract base64 data
        b64_data = uri[8:].split('#')[0]
        
        # Add padding if needed
        padding_needed = len(b64_data) % 4
        if padding_needed:
            b64_data += '=' * (4 - padding_needed)
        
        # Decode and parse JSON
        decoded = base64.b64decode(b64_data).decode('utf-8')
        data = json.loads(decoded)
        
        host = data.get("add")
        port = data.get("port")
        
        if host and port:
            return host, int(port)
            
    except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.debug(f"Failed to parse VMess config: {e}")
    
    return None, None


def parse_uri_config(uri: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Parse other URI formats (VLESS, Trojan, SS, etc.)
    
    Format: protocol://[user[:pass]@]host:port[/?params][#anchor]
    
    Args:
        uri: URI string
        
    Returns:
        Tuple of (host, port) or (None, None) if parsing fails
    """
    try:
        # Extract host:port using regex
        # Matches: @[ipv6_or_host]:port or @host:port
        match = re.search(r'@(?:\[?([^\]:]+)\]?):(\d+)', uri)
        
        if match:
            host = match.group(1)
            port = int(match.group(2))
            return host, port
            
    except (ValueError, AttributeError) as e:
        logger.debug(f"Failed to parse URI config: {e}")
    
    return None, None


def parse_config(uri: str) -> Tuple[Optional[str], Optional[int]]:
    """
    Extract host and port from proxy URI
    
    Args:
        uri: Proxy configuration URI
        
    Returns:
        Tuple of (host, port) or (None, None) if parsing fails
    """
    if not uri or not isinstance(uri, str):
        return None, None
    
    uri = uri.strip()
    
    # Handle VMess format
    if uri.lower().startswith("vmess://"):
        return parse_vmess_config(uri)
    
    # Handle other formats (VLESS, Trojan, SS, SSR, Hy2, TUIC)
    return parse_uri_config(uri)


# ============================================================================
# Main Validation Logic
# ============================================================================

async def validate_config(
    uri: str,
    config: Config
) -> Optional[str]:
    """
    Validate a single proxy configuration
    
    Args:
        uri: Proxy configuration URI
        config: Configuration object
        
    Returns:
        The URI if validation successful, None otherwise
    """
    host, port = parse_config(uri)
    
    if not host or not port:
        logger.debug(f"Failed to parse config: {uri}")
        return None
    
    # Determine if protocol uses TLS
    protocol = uri.split("://")[0].lower() if "://" in uri else ""
    uses_tls = protocol in config.TLS_PROTOCOLS
    
    # Perform appropriate check
    if uses_tls:
        success = await check_tls_handshake(host, port, config.TLS_TIMEOUT)
    else:
        success = await check_tcp_connection(host, port, config.TCP_TIMEOUT)
    
    if success:
        logger.info(f"вњ“ ALIVE: {protocol}://{host}:{port}")
        return uri
    
    return None


async def validate_configs_batch(
    uris: List[str],
    config: Config
) -> Set[str]:
    """
    Validate multiple configs concurrently with progress tracking
    
    Args:
        uris: List of proxy URIs
        config: Configuration object
        
    Returns:
        Set of alive configurations
    """
    alive_configs: Set[str] = set()
    lock = asyncio.Lock()
    
    # Use semaphore to limit concurrent tasks
    semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_TASKS)
    progress_counter = 0
    total = len(uris)
    
    async def validate_with_semaphore(uri: str) -> None:
        nonlocal progress_counter
        async with semaphore:
            result = await validate_config(uri, config)
            if result:
                async with lock:
                    alive_configs.add(result)
            
            progress_counter += 1
            if progress_counter % 10 == 0:
                logger.info(f"Progress: {progress_counter}/{total} configs checked")
    
    # Create tasks for all URIs
    tasks = [validate_with_semaphore(uri) for uri in uris]
    
    # Run all tasks
    await asyncio.gather(*tasks)
    
    return alive_configs


# ============================================================================
# File Operations
# ============================================================================

def read_configs(file_path: Path) -> List[str]:
    """
    Read proxy configurations from file
    
    Args:
        file_path: Path to configuration file
        
    Returns:
        List of non-comment, non-empty configuration lines
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Filter out comments and empty lines
    configs = [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith('#')
    ]
    
    logger.info(f"Loaded {len(configs)} configurations from {file_path.name}")
    return configs


def filter_supported_protocols(
    configs: List[str],
    supported: List[str]
) -> List[str]:
    """
    Filter configurations to only supported protocols
    
    Args:
        configs: List of configurations
        supported: List of supported protocol names
        
    Returns:
        Filtered list of configurations
    """
    filtered = [
        config for config in configs
        if any(config.lower().startswith(f"{proto}://") for proto in supported)
    ]
    
    logger.info(
        f"Filtered {len(configs)} configs down to {len(filtered)} "
        f"supported protocols"
    )
    return filtered


def write_results(
    output_path: Path,
    configs: Set[str],
    header: str
) -> None:
    """
    Write validation results to file
    
    Args:
        output_path: Output file path
        configs: Set of alive configurations
        header: Profile header to include
    """
    sorted_configs = sorted(configs)
    content = f"{header}\n" + "\n".join(sorted_configs)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    logger.info(f"вњ“ Wrote {len(configs)} configs to {output_path.name}")


def write_chunked_results(
    output_dir: Path,
    configs: Set[str],
    chunk_size: int,
    prefix: str,
    header: str
) -> None:
    """
    Write results to multiple files in chunks
    
    Args:
        output_dir: Output directory
        configs: Set of alive configurations
        chunk_size: Maximum configs per file
        prefix: File name prefix
        header: Profile header to include
    """
    sorted_configs = sorted(configs)
    
    for i, chunk_start in enumerate(range(0, len(sorted_configs), chunk_size), 1):
        chunk = sorted_configs[chunk_start:chunk_start + chunk_size]
        content = f"{header}\n" + "\n".join(chunk)
        
        output_file = output_dir / f"{prefix}{i}.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"вњ“ Created {output_file.name} ({len(chunk)} configs)")


def cleanup_old_files(
    output_dir: Path,
    pattern: str
) -> None:
    """
    Remove old result files
    
    Args:
        output_dir: Directory containing old files
        pattern: File pattern to match (e.g., "sub*.txt")
    """
    try:
        old_files = list(output_dir.glob(pattern))
        for file_path in old_files:
            file_path.unlink()
            logger.debug(f"Removed old file: {file_path.name}")
        
        if old_files:
            logger.info(f"Cleaned up {len(old_files)} old files")
    except Exception as e:
        logger.warning(f"Error during cleanup: {e}")


# ============================================================================
# Main Application
# ============================================================================

async def main():
    """Main application entry point"""
    config = Config()
    
    # Setup logging
    logger = setup_logging(config.LOG_FILE)
    
    # Determine base directory
    base_dir = Path(__file__).parent
    root_dir = base_dir.parent
    
    input_file = root_dir / config.INPUT_FILE
    master_output = root_dir / config.MASTER_OUTPUT
    
    logger.info("=" * 70)
    logger.info("рџ”’ TURKMENISTAN PROXY VALIDATOR")
    logger.info("=" * 70)
    logger.info(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Supported protocols: {', '.join(config.SUPPORTED_PROTOCOLS)}")
    logger.info(f"Max concurrent checks: {config.MAX_CONCURRENT_TASKS}")
    logger.info(f"TLS timeout: {config.TLS_TIMEOUT}s")
    logger.info(f"TCP timeout: {config.TCP_TIMEOUT}s")
    logger.info(f"Chunk size: {config.CHUNK_SIZE}")
    logger.info("=" * 70)
    
    try:
        # Step 1: Cleanup
        logger.info("\nрџ§№ STEP 1: Cleaning up old results...")
        if master_output.exists():
            master_output.unlink()
            logger.info(f"Removed old master file: {config.MASTER_OUTPUT}")
        await asyncio.sleep(0)  # Allow other tasks to run
        cleanup_old_files(root_dir, f"{config.SUB_FILE_PREFIX}*.txt")
        
        # Step 2: Load configurations
        logger.info("\nрџ“– STEP 2: Loading configurations...")
        all_configs = read_configs(input_file)
        
        # Step 3: Filter supported protocols
        logger.info("\nрџ”Ќ STEP 3: Filtering supported protocols...")
        supported_configs = filter_supported_protocols(
            all_configs,
            config.SUPPORTED_PROTOCOLS
        )
        
        if not supported_configs:
            logger.error("вќЊ No supported configurations found!")
            return
        
        # Step 4: Validate configurations
        logger.info(f"\nрџљЂ STEP 4: Starting validation of {len(supported_configs)} configs...")
        alive_configs = await validate_configs_batch(supported_configs, config)
        
        if not alive_configs:
            logger.warning("вљ пёЏ  No alive configs found!")
        else:
            logger.info(f"\nвњЁ Validation complete! Found {len(alive_configs)} alive configs")
        
        # Step 5: Write results
        logger.info("\nрџ’ѕ STEP 5: Writing results...")
        write_results(master_output, alive_configs, config.PROFILE_HEADER)
        write_chunked_results(
            root_dir,
            alive_configs,
            config.CHUNK_SIZE,
            config.SUB_FILE_PREFIX,
            config.PROFILE_HEADER
        )
        
        # Summary
        logger.info("\n" + "=" * 70)
        logger.info("вњ… ALL OPERATIONS COMPLETE!")
        logger.info("=" * 70)
        logger.info("рџ“Љ SUMMARY:")
        logger.info(f"   Total tested: {len(supported_configs)}")
        logger.info(f"   Alive configs: {len(alive_configs)}")
        success_rate = (len(alive_configs) / len(supported_configs) * 100) if supported_configs else 0
        logger.info(f"   Success rate: {success_rate:.2f}%")
        logger.info(f"   Master output: {config.MASTER_OUTPUT}")
        logger.info(f"   End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("=" * 70)
        
    except FileNotFoundError as e:
        logger.error(f"вќЊ Error: {e}")
    except Exception as e:
        logger.error(f"вќЊ Unexpected error: {e}", exc_info=True)


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nвЏ№пёЏ  Validation interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
