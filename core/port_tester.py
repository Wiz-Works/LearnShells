"""
Port testing and egress detection
"""

import socket
import subprocess
import threading
import time
from typing import List, Dict, Optional
from learnshells.utils.network import NetworkUtils
from learnshells.utils.logger import Logger
from learnshells.ui.colors import Colors


class PortTester:
    """Test ports for connectivity and egress filtering."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize port tester.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.open_ports = []
    
    def test_common_ports(self, target_ip: str = None) -> List[int]:
        """
        Test common ports that reverse shells use.
        
        Args:
            target_ip: Target IP to test against (for egress testing)
            
        Returns:
            List of open/allowed ports
        """
        # Common reverse shell ports (in order of preference)
        ports = [
            443,   # HTTPS - most likely to be allowed
            80,    # HTTP - very common
            8080,  # Alt HTTP
            8443,  # Alt HTTPS
            53,    # DNS - sometimes allowed
            22,    # SSH - common
            21,    # FTP
            25,    # SMTP
            110,   # POP3
            143,   # IMAP
            3389,  # RDP
            4444,  # Metasploit default
            1234,  # Common shell port
            9001,  # Common shell port
        ]
        
        self.logger.info("Testing common egress ports...")
        
        open_ports = []
        
        for port in ports:
            if self._test_port_local(port):
                open_ports.append(port)
                self.logger.status(f"Port {port} {Colors.GREEN}AVAILABLE{Colors.RESET}", "success")
            else:
                self.logger.debug(f"Port {port} in use or unavailable")
        
        self.open_ports = open_ports
        
        if open_ports:
            self.logger.success(f"Found {len(open_ports)} available ports for listener")
            self._explain_port_selection(open_ports)
        else:
            self.logger.error(
                "No available ports found!",
                explain="All tested ports are in use. Try closing other services or use a different port range."
            )
        
        return open_ports
    
    def _test_port_local(self, port: int, timeout: float = 0.5) -> bool:
        """
        Test if we can bind to a port locally (for listener).
        
        Args:
            port: Port number to test
            timeout: Timeout in seconds
            
        Returns:
            bool: True if port is available
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.bind(('', port))
            sock.close()
            return True
        except Exception:
            return False
    
    def test_target_ports(self, target_ip: str, ports: List[int] = None) -> List[int]:
        """
        Test which ports are open on target (for egress testing).
        
        Args:
            target_ip: Target IP address
            ports: List of ports to test (default: common ports)
            
        Returns:
            List of open ports on target
        """
        if ports is None:
            ports = [443, 80, 8080, 22, 21, 3306, 3389, 4444]
        
        self.logger.info(f"Testing ports on {target_ip}...")
        
        open_ports = []
        
        for port in ports:
            if NetworkUtils.is_port_open(target_ip, port, timeout=1.0):
                open_ports.append(port)
                self.logger.status(f"Port {port} {Colors.GREEN}OPEN{Colors.RESET}", "success")
            else:
                self.logger.debug(f"Port {port} closed or filtered")
        
        if open_ports:
            self.logger.success(f"Found {len(open_ports)} open ports on target")
        else:
            self.logger.warning(
                "No open ports found on target",
                explain="Target may have firewall, or wrong IP. Verify target is reachable."
            )
        
        return open_ports
    
    def find_best_port(self, prefer_stealth: bool = True) -> int:
        """
        Find the best port to use for reverse shell.
        
        Args:
            prefer_stealth: Prefer common service ports (443, 80, 22)
            
        Returns:
            Best port number
        """
        if not self.open_ports:
            self.test_common_ports()
        
        if not self.open_ports:
            self.logger.warning("No tested ports available, defaulting to 443")
            return 443
        
        # Preference order for stealth
        if prefer_stealth:
            preferred = [443, 80, 22, 53]
            
            for port in preferred:
                if port in self.open_ports:
                    self.logger.success(
                        f"Selected port {port}",
                        explain=self._get_port_explanation(port)
                    )
                    return port
        
        # Return first available
        port = self.open_ports[0]
        self.logger.success(f"Selected port {port}")
        return port
    
    def _get_port_explanation(self, port: int) -> str:
        """Get explanation for why a port was chosen."""
        explanations = {
            443: "Port 443 (HTTPS) is almost always allowed through firewalls. "
                 "It's the best choice for stealth and reliability.",
            80: "Port 80 (HTTP) is commonly allowed. Good second choice after 443.",
            22: "Port 22 (SSH) is often allowed for legitimate remote access.",
            53: "Port 53 (DNS) is sometimes allowed, though less reliable for shells.",
            4444: "Port 4444 is Metasploit's default. Easy to remember but often blocked.",
            8080: "Port 8080 (Alt HTTP) is commonly used for web services.",
        }
        return explanations.get(port, f"Port {port} is available.")
    
    def _explain_port_selection(self, open_ports: List[int]):
        """Explain the port selection results."""
        if 443 in open_ports:
            explanation = "Great! Port 443 (HTTPS) is available. This is ideal for reverse shells " \
                         "because it looks like normal encrypted web traffic and is rarely blocked by firewalls."
        elif 80 in open_ports:
            explanation = "Port 80 (HTTP) is available. This is a good alternative to 443. " \
                         "Web traffic ports are commonly allowed."
        elif any(p in open_ports for p in [22, 53, 21, 25]):
            explanation = "Common service ports are available. These can work for shells " \
                         "but might be monitored more closely than web ports."
        else:
            explanation = "Only non-standard ports are available. These work but might be " \
                         "noticed by network monitoring. Consider ports like 443 or 80 if possible."
        
        self.logger.educational_note("Port Selection Strategy", explanation)
    
    def test_egress_filtering(
        self,
        local_ip: str,
        target_url: str = None,
        ports: List[int] = None,
        timeout: int = 10
    ) -> List[int]:
        """
        Test for egress filtering by checking which ports can connect out.
        This requires RCE on target to test properly.
        
        Args:
            local_ip: Local IP to test connections to
            target_url: Target URL with RCE (optional)
            ports: Ports to test (default: common ports)
            timeout: How long to wait for connections
            
        Returns:
            List of ports that are not filtered
        """
        if ports is None:
            ports = [443, 80, 8080, 53, 22, 21, 4444, 1234]
        
        self.logger.info("Testing egress filtering...")
        
        if not target_url:
            # Can only test local availability
            self.logger.warning(
                "No target URL provided, testing local port availability only",
                explain="For true egress testing, we need RCE on target to test outbound connections."
            )
            return self.test_common_ports()
        
        # Set up listeners and test
        results = {}
        listeners = []
        
        for port in ports:
            listener = self._start_test_listener(local_ip, port, results, timeout)
            if listener:
                listeners.append(listener)
        
        self.logger.info(f"Listeners active. Waiting {timeout} seconds for connections...")
        
        # In a real scenario, you'd trigger connections from target here
        # For now, just wait
        time.sleep(timeout)
        
        # Get successful ports
        successful_ports = [port for port, success in results.items() if success]
        
        if successful_ports:
            self.logger.success(
                f"Egress confirmed on ports: {', '.join(map(str, successful_ports))}",
                explain="These ports successfully connected back, meaning they're not filtered."
            )
        else:
            self.logger.warning("No egress connections detected during test")
        
        return successful_ports
    
    def _start_test_listener(
        self,
        ip: str,
        port: int,
        results: Dict,
        timeout: int
    ) -> Optional[threading.Thread]:
        """Start a listener thread for egress testing."""
        def listen():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(timeout)
                sock.bind((ip, port))
                sock.listen(1)
                
                self.logger.debug(f"Listening on {ip}:{port}")
                
                conn, addr = sock.accept()
                results[port] = True
                self.logger.status(f"Connection received on port {port}", "success")
                conn.close()
                sock.close()
                
            except socket.timeout:
                results[port] = False
                self.logger.debug(f"Timeout on port {port}")
            except Exception as e:
                results[port] = False
                self.logger.debug(f"Error on port {port}: {e}")
        
        try:
            thread = threading.Thread(target=listen, daemon=True)
            thread.start()
            return thread
        except Exception as e:
            self.logger.debug(f"Failed to start listener on port {port}: {e}")
            return None
    
    def generate_egress_test_commands(
        self,
        local_ip: str,
        ports: List[int] = None
    ) -> Dict[str, str]:
        """
        Generate commands to test egress from target.
        
        Args:
            local_ip: Your IP to connect back to
            ports: Ports to test
            
        Returns:
            Dict of payload_type: command
        """
        if ports is None:
            ports = [443, 80, 4444]
        
        commands = {}
        
        for port in ports:
            # Bash command
            commands[f'bash_{port}'] = f"timeout 2 bash -c 'cat < /dev/tcp/{local_ip}/{port}' 2>/dev/null && echo 'Port {port} OPEN' || echo 'Port {port} BLOCKED'"
            
            # Netcat command
            commands[f'nc_{port}'] = f"timeout 2 nc -zv {local_ip} {port}"
            
            # Curl command
            commands[f'curl_{port}'] = f"timeout 2 curl -v telnet://{local_ip}:{port}"
            
            # Python command
            commands[f'python_{port}'] = (
                f"python3 -c \"import socket; s=socket.socket(); "
                f"s.settimeout(2); s.connect(('{local_ip}', {port})); "
                f"print('Port {port} OPEN')\""
            )
        
        return commands
    
    def get_port_info(self, port: int) -> Dict[str, str]:
        """
        Get information about a specific port.
        
        Args:
            port: Port number
            
        Returns:
            Dict with port information
        """
        common_ports = {
            21: {"service": "FTP", "description": "File Transfer Protocol"},
            22: {"service": "SSH", "description": "Secure Shell"},
            23: {"service": "Telnet", "description": "Telnet Protocol"},
            25: {"service": "SMTP", "description": "Simple Mail Transfer Protocol"},
            53: {"service": "DNS", "description": "Domain Name System"},
            80: {"service": "HTTP", "description": "Hypertext Transfer Protocol"},
            110: {"service": "POP3", "description": "Post Office Protocol v3"},
            143: {"service": "IMAP", "description": "Internet Message Access Protocol"},
            443: {"service": "HTTPS", "description": "HTTP Secure"},
            445: {"service": "SMB", "description": "Server Message Block"},
            3306: {"service": "MySQL", "description": "MySQL Database"},
            3389: {"service": "RDP", "description": "Remote Desktop Protocol"},
            4444: {"service": "Metasploit", "description": "Metasploit Default"},
            5432: {"service": "PostgreSQL", "description": "PostgreSQL Database"},
            8080: {"service": "HTTP-Alt", "description": "Alternative HTTP"},
            8443: {"service": "HTTPS-Alt", "description": "Alternative HTTPS"},
        }
        
        return common_ports.get(port, {
            "service": "Unknown",
            "description": f"Port {port}"
        })
    
    def display_port_recommendations(self):
        """Display port selection recommendations."""
        self.logger.header("Port Selection Recommendations")
        
        recommendations = [
            {
                "port": 443,
                "rating": "⭐⭐⭐⭐⭐",
                "reason": "Best choice - HTTPS traffic, rarely blocked"
            },
            {
                "port": 80,
                "rating": "⭐⭐⭐⭐",
                "reason": "Very good - HTTP traffic, commonly allowed"
            },
            {
                "port": 22,
                "rating": "⭐⭐⭐",
                "reason": "Good - SSH traffic, often allowed"
            },
            {
                "port": 53,
                "rating": "⭐⭐",
                "reason": "Fair - DNS traffic, sometimes allowed"
            },
            {
                "port": 4444,
                "rating": "⭐",
                "reason": "Poor - Known Metasploit port, often blocked"
            },
        ]
        
        headers = ["Port", "Rating", "Reason"]
        rows = [[r["port"], r["rating"], r["reason"]] for r in recommendations]
        
        self.logger.table(headers, rows)
        
        self.logger.educational_note(
            "Stealth Considerations",
            "Using common service ports (443, 80) makes your reverse shell traffic "
            "blend in with normal network activity. Port 4444 is a known hacking tool port "
            "and is more likely to be blocked or trigger alerts."
        )
