"""Service detection implementations."""
import socket
import ssl
from typing import Optional
from securescanner.core.interfaces import ServiceDetector

class StandardServiceDetector(ServiceDetector):
    """Standard implementation of service detection."""
    
    def __init__(self, target: str):
        self.target = target
        
    def get_service_name(self, port: int) -> str:
        """Get service name from port number."""
        try:
            return socket.getservbyport(port)
        except (socket.error, OSError):
            return "unknown"
    
    def get_service_banner(self, port: int) -> str:
        """Attempt to grab service banner safely."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((self.target, port))
                
                banner = self._get_basic_banner(sock)
                if not banner:
                    banner = self._try_http_banner(sock, port)
                return banner[:100]  # Truncate long banners
        except Exception as e:
            return f"Banner grab failed: {str(e)}"
    
    def _get_basic_banner(self, sock: socket.socket) -> str:
        """Get banner from basic connection."""
        try:
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            return ""
    
    def _try_http_banner(self, sock: socket.socket, port: int) -> str:
        """Attempt to get HTTP/HTTPS banner."""
        if port == 80:
            return self._get_http_banner(sock)
        elif port == 443:
            return self._get_https_banner(sock)
        return ""
    
    def _get_http_banner(self, sock: socket.socket) -> str:
        """Get HTTP banner."""
        try:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            return ""
    
    def _get_https_banner(self, sock: socket.socket) -> str:
        """Get HTTPS banner."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock) as ssock:
                ssock.send(b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                return ssock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            return ""
