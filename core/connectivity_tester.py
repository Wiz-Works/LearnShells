"""
Connectivity testing and validation
"""

import socket
import subprocess
import time
from typing import Dict, List, Optional, Tuple
from learnshells.utils.logger import Logger
from learnshells.utils.network import NetworkUtils


class ConnectivityTester:
    """Test and validate network connectivity."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize connectivity tester.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
    
    def test_full_connectivity(
        self,
        local_ip: str,
        target_ip: str,
        port: int
    ) -> Dict[str, any]:
        """
        Comprehensive connectivity test.
        
        Args:
            local_ip: Local IP address
            target_ip: Target IP address
            port: Port to test
            
        Returns:
            Dict with test results
        """
        self.logger.header("Connectivity Testing")
        
        results = {
            'local_ip': local_ip,
            'target_ip': target_ip,
            'port': port,
            'tests': {}
        }
        
        # Test 1: Can we reach the target?
        results['tests']['target_reachable'] = self.test_target_reachable(target_ip)
        
        # Test 2: Can we bind to the port locally?
        results['tests']['port_available'] = self.test_port_available(port)
        
        # Test 3: Is target port accessible?
        results['tests']['target_port_open'] = self.test_target_port(target_ip, port)
        
        # Test 4: Network path test
        results['tests']['network_path'] = self.test_network_path(target_ip)
        
        # Display results
        self._display_connectivity_results(results)
        
        return results
    
    def test_target_reachable(self, target_ip: str) -> bool:
        """
        Test if target is reachable via ping.
        
        Args:
            target_ip: Target IP address
            
        Returns:
            bool: True if reachable
        """
        self.logger.info(f"Testing if {target_ip} is reachable...")
        
        if NetworkUtils.ping(target_ip, count=3, timeout=2):
            self.logger.status(f"Target {target_ip} is reachable", "success")
            return True
        else:
            self.logger.status(f"Target {target_ip} not responding to ping", "warning")
            self.logger.educational_note(
                "Ping Failure",
                "Target not responding to ping doesn't always mean it's down. "
                "Many servers block ICMP (ping) packets for security. "
                "The target might still be accessible via TCP connections."
            )
            return False
    
    def test_port_available(self, port: int) -> bool:
        """
        Test if port is available locally for listener.
        
        Args:
            port: Port number
            
        Returns:
            bool: True if available
        """
        self.logger.info(f"Testing if port {port} is available locally...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', port))
            sock.close()
            self.logger.status(f"Port {port} is available", "success")
            return True
        except OSError:
            self.logger.status(f"Port {port} is in use", "error")
            self.logger.educational_note(
                "Port In Use",
                f"Port {port} is already being used by another process. "
                "You can either:\n"
                "1. Stop the other process\n"
                "2. Use a different port\n"
                "3. Find what's using it: lsof -i :{port} or netstat -tulpn | grep {port}"
            )
            return False
    
    def test_target_port(self, target_ip: str, port: int) -> bool:
        """
        Test if specific port is open on target.
        
        Args:
            target_ip: Target IP
            port: Port number
            
        Returns:
            bool: True if open
        """
        self.logger.info(f"Testing if port {port} is open on {target_ip}...")
        
        if NetworkUtils.is_port_open(target_ip, port, timeout=3.0):
            self.logger.status(f"Port {port} is open on target", "success")
            return True
        else:
            self.logger.status(f"Port {port} appears closed/filtered", "warning")
            return False
    
    def test_network_path(self, target_ip: str) -> Dict[str, any]:
        """
        Test network path to target (similar to traceroute).
        
        Args:
            target_ip: Target IP
            
        Returns:
            Dict with path information
        """
        self.logger.info(f"Testing network path to {target_ip}...")
        
        try:
            # Try traceroute (Linux) or tracert (Windows)
            import platform
            cmd = 'traceroute' if platform.system() != 'Windows' else 'tracert'
            
            result = subprocess.run(
                [cmd, '-m', '10', target_ip],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            hops = len([line for line in result.stdout.split('\n') if line.strip()])
            
            path_info = {
                'hops': hops,
                'output': result.stdout,
                'success': result.returncode == 0
            }
            
            if path_info['success']:
                self.logger.status(f"Network path found ({hops} hops)", "success")
            else:
                self.logger.status("Network path test inconclusive", "warning")
            
            return path_info
            
        except Exception as e:
            self.logger.debug(f"Network path test failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def test_vpn_connectivity(self, vpn_interface: str) -> bool:
        """
        Test if VPN is working properly.
        
        Args:
            vpn_interface: VPN interface name (e.g., tun0)
            
        Returns:
            bool: True if VPN is functional
        """
        self.logger.info(f"Testing VPN interface {vpn_interface}...")
        
        # Check if interface exists and has IP
        vpn_ip = NetworkUtils.get_interface_ip(vpn_interface)
        
        if not vpn_ip:
            self.logger.status(f"VPN interface {vpn_interface} not found or has no IP", "error")
            return False
        
        self.logger.status(f"VPN interface {vpn_interface} has IP {vpn_ip}", "success")
        
        # Try to ping common VPN gateways
        gateways = ['10.10.10.2', '10.10.14.1', '10.9.0.1']
        
        for gateway in gateways:
            if NetworkUtils.ping(gateway, count=1, timeout=2):
                self.logger.status(f"VPN gateway {gateway} reachable", "success")
                return True
        
        self.logger.status("No VPN gateways responded", "warning")
        return False
    
    def diagnose_connection_failure(
        self,
        local_ip: str,
        target_ip: str,
        port: int
    ) -> List[Tuple[str, str]]:
        """
        Diagnose why a connection might fail.
        
        Args:
            local_ip: Local IP address
            target_ip: Target IP address
            port: Port number
            
        Returns:
            List of (issue, solution) tuples
        """
        self.logger.header("Connection Failure Diagnosis")
        
        issues = []
        
        # Check 1: Wrong IP in payload
        if not NetworkUtils.is_valid_ip(local_ip):
            issues.append((
                "Invalid local IP address",
                f"Check your IP address. Current: {local_ip}"
            ))
        
        # Check 2: Not using VPN IP
        vpn_ip = NetworkUtils.get_interface_ip(NetworkUtils.get_vpn_interface() or '')
        if vpn_ip and local_ip != vpn_ip:
            issues.append((
                "Not using VPN IP address",
                f"You should use VPN IP {vpn_ip} instead of {local_ip}"
            ))
        
        # Check 3: Port already in use
        if not self.test_port_available(port):
            issues.append((
                f"Port {port} is already in use",
                f"Stop the process using port {port} or use a different port"
            ))
        
        # Check 4: Target not reachable
        if not NetworkUtils.ping(target_ip, count=1, timeout=2):
            issues.append((
                "Target not reachable",
                "Verify target IP is correct and target is online"
            ))
        
        # Check 5: Firewall blocking
        common_ports = [443, 80, 22]
        if port not in common_ports:
            issues.append((
                f"Port {port} might be blocked by firewall",
                f"Try using common ports like 443 or 80 which are less likely to be blocked"
            ))
        
        # Display diagnosis
        if issues:
            self.logger.error("Found potential issues:")
            for issue, solution in issues:
                self.logger.list_item(f"{issue}")
                self.logger.list_item(f"  → Solution: {solution}", indent=1)
        else:
            self.logger.success("No obvious connectivity issues detected")
        
        return issues
    
    def _display_connectivity_results(self, results: Dict):
        """Display connectivity test results."""
        self.logger.subheader("Test Results")
        
        tests = results['tests']
        
        status_icon = lambda x: "✓" if x else "✗"
        
        self.logger.list_item(
            f"{status_icon(tests.get('target_reachable'))} Target Reachable: "
            f"{'Yes' if tests.get('target_reachable') else 'No'}"
        )
        self.logger.list_item(
            f"{status_icon(tests.get('port_available'))} Port Available Locally: "
            f"{'Yes' if tests.get('port_available') else 'No'}"
        )
        self.logger.list_item(
            f"{status_icon(tests.get('target_port_open'))} Target Port Open: "
            f"{'Yes' if tests.get('target_port_open') else 'No/Unknown'}"
        )
        
        # Overall assessment
        all_passed = all([
            tests.get('port_available'),
            # Note: target_reachable and target_port_open can fail but connection might still work
        ])
        
        if all_passed:
            self.logger.success("\nConnectivity looks good! Ready for reverse shell.")
        else:
            self.logger.warning("\nSome connectivity issues detected. Review results above.")
    
    def suggest_port_alternatives(self, blocked_port: int) -> List[int]:
        """
        Suggest alternative ports if one is blocked.
        
        Args:
            blocked_port: Port that was blocked
            
        Returns:
            List of alternative ports to try
        """
        # Common alternative ports in order of preference
        alternatives = [443, 80, 22, 53, 8080, 8443, 21, 25]
        
        # Remove the blocked port
        alternatives = [p for p in alternatives if p != blocked_port]
        
        self.logger.info(f"Port {blocked_port} blocked, suggesting alternatives:")
        for port in alternatives[:3]:
            self.logger.list_item(f"Port {port}")
        
        return alternatives[:5]
    
    def test_reverse_connection(
        self,
        local_ip: str,
        port: int,
        timeout: int = 30
    ) -> bool:
        """
        Start a listener and wait for reverse connection (for testing).
        
        Args:
            local_ip: Local IP to listen on
            port: Port to listen on
            timeout: How long to wait
            
        Returns:
            bool: True if connection received
        """
        self.logger.info(f"Starting test listener on {local_ip}:{port}")
        self.logger.info(f"Waiting {timeout} seconds for connection...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            sock.bind((local_ip, port))
            sock.listen(1)
            
            self.logger.status("Listener active, waiting for connection...", "working")
            
            conn, addr = sock.accept()
            self.logger.success(f"Connection received from {addr[0]}:{addr[1]}!")
            conn.close()
            sock.close()
            return True
            
        except socket.timeout:
            self.logger.warning("Timeout - no connection received")
            sock.close()
            return False
        except Exception as e:
            self.logger.error(f"Listener error: {e}")
            return False
