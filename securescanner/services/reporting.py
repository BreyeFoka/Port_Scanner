"""Report generation implementations."""
import json
import csv
from pathlib import Path
from typing import Dict, Any, List, Tuple
from securescanner.core.interfaces import Reporter

class SecurityReporter(Reporter):
    """Generates security reports in multiple formats."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, scan_data: Dict[str, Any]) -> None:
        """Generate comprehensive security reports."""
        self._print_console_report(scan_data)
        self._save_json_report(scan_data)
        self._save_csv_report(scan_data)
    
    def _print_console_report(self, scan_data: Dict[str, Any]) -> None:
        """Print report to console."""
        print("\n=== Security Assessment Report ===")
        print(f"\nTarget: {scan_data['scan_info']['target']}")
        print(f"OS Detection: {scan_data['scan_info']['os_detection']}")
        print("\nOpen Ports and Security Findings:")
        
        if scan_data['open_ports']:
            for port_info in scan_data['open_ports']:
                print(f"\n[OPEN] Port {port_info['port']}")
                print(f"Service: {port_info['service']}")
                print(f"Banner: {port_info['banner']}")
                if port_info['vulnerabilities']:
                    print("Potential Vulnerabilities:")
                    for vuln in port_info['vulnerabilities']:
                        print(f"  - {vuln}")
        else:
            print("\nNo open ports found.")
    
    def _save_json_report(self, scan_data: Dict[str, Any]) -> None:
        """Save report in JSON format."""
        json_path = self.output_dir / 'security_report.json'
        with open(json_path, 'w') as f:
            json.dump(scan_data, f, indent=4)
    
    def _save_csv_report(self, scan_data: Dict[str, Any]) -> None:
        """Save report in CSV format."""
        csv_path = self.output_dir / 'security_report.csv'
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Service', 'Banner', 'Vulnerabilities'])
            
            for port_info in scan_data['open_ports']:
                writer.writerow([
                    port_info['port'],
                    port_info['service'],
                    port_info['banner'],
                    '; '.join(port_info['vulnerabilities'])
                ])
