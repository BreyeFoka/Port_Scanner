"""Vulnerability database and related functionality."""
from typing import Dict, List

class VulnerabilityDatabase:
    """Database of common vulnerabilities for different ports and services."""
    
    COMMON_VULNERABILITIES: Dict[int, List[str]] = {
        21: ["Anonymous FTP login", "FTP Bounce Attack"],
        22: ["OpenSSH < 7.7 Username Enumeration", "SSH Protocol 1.0"],
        23: ["Telnet Unencrypted", "Default Credentials"],
        80: ["Directory Traversal", "SQL Injection", "XSS"],
        443: ["Heartbleed", "POODLE", "BEAST"],
        3306: ["MySQL Weak Password", "CVE-2016-6662"],
        3389: ["BlueKeep (CVE-2019-0708)", "RDP Session Hijacking"]
    }
    
    @classmethod
    def get_vulnerabilities(cls, port: int) -> List[str]:
        """Get list of known vulnerabilities for a port."""
        return cls.COMMON_VULNERABILITIES.get(port, [])
