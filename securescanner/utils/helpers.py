"""Utility functions for the security scanner."""
import ipaddress
from typing import Optional
import logging
from pathlib import Path

def setup_logging(output_dir: Optional[Path] = None) -> None:
    """Configure logging with file and console handlers."""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler()]
    if output_dir:
        log_file = output_dir / 'security_scan.log'
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
    
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=handlers
    )

def validate_ip(ip: str) -> bool:
    """Validate an IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port_range(start_port: int, end_port: int) -> bool:
    """Validate port range."""
    if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
        return False
    return start_port <= end_port

def calculate_progress(current: int, total: int) -> float:
    """Calculate progress percentage."""
    return (current / total) * 100 if total > 0 else 0
