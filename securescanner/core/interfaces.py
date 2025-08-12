"""Base interfaces for scanner components."""
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class PortScanner(ABC):
    """Base interface for port scanning functionality."""
    
    @abstractmethod
    def scan_port(self, port: int) -> None:
        """Scan a single port."""
        pass
    
    @abstractmethod
    def scan(self, start_port: int, end_port: int, num_threads: int) -> None:
        """Perform the complete port scan."""
        pass

class ServiceDetector(ABC):
    """Base interface for service detection."""
    
    @abstractmethod
    def get_service_name(self, port: int) -> str:
        """Get the service name for a port."""
        pass
    
    @abstractmethod
    def get_service_banner(self, port: int) -> str:
        """Get the service banner for a port."""
        pass

class OSDetector(ABC):
    """Base interface for OS detection."""
    
    @abstractmethod
    def detect_os(self) -> str:
        """Detect the target system's operating system."""
        pass

class VulnerabilityScanner(ABC):
    """Base interface for vulnerability scanning."""
    
    @abstractmethod
    def check_vulnerabilities(self, port: int) -> List[str]:
        """Check for vulnerabilities on a specific port."""
        pass

class Reporter(ABC):
    """Base interface for report generation."""
    
    @abstractmethod
    def generate_report(self, scan_data: Dict[str, Any]) -> None:
        """Generate a report from scan data."""
        pass
