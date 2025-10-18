"""
Network utilities for LearnShells
"""

import socket
import netifaces
import subprocess
import re
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse


class NetworkUtils:
    """Network-related utility functions."""
    
    @staticmethod
    def get_vpn_interface() -> Optional[str]:
        """
        Detect VPN interface (tun0, tap0, etc.).
        
        Returns:
            str: Interface name or None if not found
        """
        interfaces = netifaces.interfaces()
        
        # Common VPN interface patterns
        vpn_patterns = ['tun', 'tap', 'utun', 'wg']
        
        for iface in interfaces:
            for pattern in vpn_patterns:
                if iface.startswith(pattern):
                    # Verify it has an IP address
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        return iface
        
        return None
    
    @staticmethod
    def get_interface_ip(interface: str) -> Optional[str]:
        """
        Get IP address of specific interface.
        
        Args:
            interface: Network interface name
            
        Returns:
            str: IP address or None
        """
        try:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
        except (ValueError, KeyError, IndexError):
            pass
        return None
    
    @staticmethod
    def get_local_ip() -> str:
        """
        Get local IP address (non-loopback).
        
        Returns:
            str: Local IP address
        """
        try:
            # Try VPN interface first
            vpn_iface = NetworkUtils.get_vpn_interface()
            if vpn_iface:
                ip = NetworkUtils.get_interface_ip(vpn_iface)
                if ip:
                    return ip
            
            # Fall back to primary interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        """
        Check if a port is open on target.
        
        Args:
            host: Target hostname/IP
            port: Port number
            timeout: Connection timeout in seconds
            
        Returns:
            bool: True if port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    @staticmethod
    def test_egress_ports(target_host: str, ports: List[int] = None) -> List[int]:
        """
        Test which ports can connect back from target.
        
        Args:
            target_host: Target IP/hostname
            ports: List of ports to test (default: common ports)
            
        Returns:
            List of open ports
        """
        if ports is None:
            # Common egress ports
            ports = [443, 80, 8080, 53, 22, 21, 25, 110, 143, 3389, 4444, 1234]
        
        open_ports = []
        for port in ports:
            if NetworkUtils.is_port_open(target_host, port, timeout=1.0):
                open_ports.append(port)
        
        return open_ports
    
    @staticmethod
    def parse_url(url: str) -> Dict[str, str]:
        """
        Parse URL into components.
        
        Args:
            url: URL string
            
        Returns:
            Dict with scheme, host, port, path, query
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        
        return {
            'scheme': parsed.scheme,
            'host': parsed.hostname or '',
            'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
            'path': parsed.path or '/',
            'query': parsed.query or '',
            'full_url': url
        }
    
    @staticmethod
    def extract_ip_from_url(url: str) -> Optional[str]:
        """
        Extract IP address from URL.
        
        Args:
            url: URL string
            
        Returns:
            IP address or None
        """
        parsed = NetworkUtils.parse_url(url)
        host = parsed['host']
        
        # Check if already an IP
        if NetworkUtils.is_valid_ip(host):
            return host
        
        # Try to resolve hostname
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Validate IP address format.
        
        Args:
            ip: IP address string
            
        Returns:
            bool: True if valid IPv4 address
        """
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if IP is in private range.
        
        Args:
            ip: IP address string
            
        Returns:
            bool: True if private IP
        """
        if not NetworkUtils.is_valid_ip(ip):
            return False
        
        # Private IP ranges
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255'),
        ]
        
        ip_int = NetworkUtils._ip_to_int(ip)
        
        for start, end in private_ranges:
            if NetworkUtils._ip_to_int(start) <= ip_int <= NetworkUtils._ip_to_int(end):
                return True
        
        return False
    
    @staticmethod
    def _ip_to_int(ip: str) -> int:
        """Convert IP address to integer."""
        parts = ip.split('.')
        return sum(int(part) << (8 * (3 - i)) for i, part in enumerate(parts))
    
    @staticmethod
    def get_hostname(ip: str) -> Optional[str]:
        """
        Get hostname from IP address.
        
        Args:
            ip: IP address
            
        Returns:
            Hostname or None
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None
    
    @staticmethod
    def ping(host: str, count: int = 1, timeout: int = 2) -> bool:
        """
        Ping a host.
        
        Args:
            host: Target hostname/IP
            count: Number of ping packets
            timeout: Timeout in seconds
            
        Returns:
            bool: True if host responds
        """
        try:
            # Determine ping command based on OS
            import platform
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            
            command = ['ping', param, str(count), timeout_param, str(timeout), host]
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except Exception:
            return False
    
    @staticmethod
    def get_mac_address(ip: str) -> Optional[str]:
        """
        Get MAC address for IP (requires arp).
        
        Args:
            ip: Target IP address
            
        Returns:
            MAC address or None
        """
        try:
            # Try arp command
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            # Parse MAC from output
            mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
            match = re.search(mac_pattern, result.stdout)
            if match:
                return match.group(0)
        except Exception:
            pass
        
        return None
    
    @staticmethod
    def url_encode(text: str) -> str:
        """
        URL encode text for payloads.
        
        Args:
            text: Text to encode
            
        Returns:
            URL encoded string
        """
        from urllib.parse import quote
        return quote(text)
    
    @staticmethod
    def base64_encode(text: str) -> str:
        """
        Base64 encode text.
        
        Args:
            text: Text to encode
            
        Returns:
            Base64 encoded string
        """
        import base64
        return base64.b64encode(text.encode()).decode()
    
    @staticmethod
    def base64_decode(text: str) -> str:
        """
        Base64 decode text.
        
        Args:
            text: Base64 encoded text
            
        Returns:
            Decoded string
        """
        import base64
        return base64.b64decode(text.encode()).decode()
    
    @staticmethod
    def hex_encode(text: str) -> str:
        """
        Hex encode text.
        
        Args:
            text: Text to encode
            
        Returns:
            Hex encoded string
        """
        return text.encode().hex()
    
    @staticmethod
    def get_free_port(start_port: int = 4444, end_port: int = 5000) -> int:
        """
        Find a free port in range.
        
        Args:
            start_port: Start of port range
            end_port: End of port range
            
        Returns:
            Free port number
        """
        for port in range(start_port, end_port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(('', port))
                sock.close()
                return port
            except OSError:
                continue
        
        raise RuntimeError(f"No free ports in range {start_port}-{end_port}")
    
    @staticmethod
    def check_internet_connection() -> bool:
        """
        Check if internet connection is available.
        
        Returns:
            bool: True if connected
        """
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError:
            return False
