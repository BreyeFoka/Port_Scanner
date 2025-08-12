"""OS detection implementations."""
import socket
from securescanner.core.interfaces import OSDetector

class HTTPBasedOSDetector(OSDetector):
    """OS detection based on HTTP response analysis."""
    
    def __init__(self, target: str):
        self.target = target
    
    def detect_os(self) -> str:
        """Detect OS using HTTP response patterns."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect((self.target, 80))
                sock.send(b"GET / HTTP/1.1\r\n\r\n")
                response = sock.recv(1024)
                return self._analyze_response(response)
        except:
            return "OS Detection Failed"
    
    def _analyze_response(self, response: bytes) -> str:
        """Analyze HTTP response for OS indicators."""
        response_str = str(response)
        
        if "Windows" in response_str:
            return "Windows"
        elif "Ubuntu" in response_str:
            return "Ubuntu Linux"
        elif "Apache" in response_str:
            return "Linux (Apache)"
        else:
            return "Unknown OS"
