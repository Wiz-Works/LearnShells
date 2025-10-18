"""
VPN and network interface detection for LearnShells
"""

import netifaces
import subprocess
import re
from typing import Optional, Dict, List
from learnshells.utils.network import NetworkUtils
from learnshells.utils.logger import Logger
from learnshells.utils.colors import Colors


class InterfaceDetector:
    """Detects and manages network interfaces, especially VPN interfaces."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize interface detector.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.vpn_interface = None
        self.vpn_ip = None
        self.all_interfaces = []
    
    def detect_vpn_interface(self, preferred: str = None) -> Optional[str]:
        """
        Detect VPN interface automatically.
        
        Args:
            preferred: Preferred interface name (optional)
            
        Returns:
            Interface name or None if not found
        """
        self.logger.info("Detecting VPN interface...")
        
        # If preferred interface specified, check it first
        if preferred:
            if self._verify_interface(preferred):
                self.vpn_interface = preferred
                self.vpn_ip = NetworkUtils.get_interface_ip(preferred)
                self.logger.success(
                    f"Using specified interface: {preferred} ({self.vpn_ip})",
                    explain="This is the network interface you specified."
                )
                return preferred
            else:
                self.logger.warning(f"Specified interface '{preferred}' not found or invalid")
        
        # Auto-detect VPN interfaces
        interfaces = netifaces.interfaces()
        vpn_candidates = []
        
        # Common VPN interface patterns
        vpn_patterns = {
            'tun': 'OpenVPN/WireGuard TUN interface',
            'tap': 'OpenVPN TAP interface',
            'utun': 'macOS VPN interface',
            'wg': 'WireGuard interface',
            'ppp': 'PPP VPN interface'
        }
        
        self.logger.debug(f"Scanning interfaces: {interfaces}")
        
        for iface in interfaces:
            for pattern, description in vpn_patterns.items():
                if iface.startswith(pattern):
                    ip = NetworkUtils.get_interface_ip(iface)
                    if ip:
                        vpn_candidates.append({
                            'interface': iface,
                            'ip': ip,
                            'description': description
                        })
                        self.logger.debug(f"Found VPN candidate: {iface} ({ip})")
        
        if not vpn_candidates:
            self.logger.error(
                "No VPN interface detected!",
                explain="VPN interfaces are typically named tun0, tap0, etc. "
                       "Make sure you're connected to HTB/THM VPN before running LearnShells."
            )
            return None
        
        # If multiple candidates, prefer tun0 (most common for HTB/THM)
        if len(vpn_candidates) > 1:
            self.logger.debug(f"Found {len(vpn_candidates)} VPN interfaces")
            for candidate in vpn_candidates:
                if candidate['interface'] == 'tun0':
                    vpn_candidates = [candidate]
                    break
        
        # Use first (or preferred) candidate
        selected = vpn_candidates[0]
        self.vpn_interface = selected['interface']
        self.vpn_ip = selected['ip']
        
        self.logger.success(
            f"VPN detected: {self.vpn_interface} ({self.vpn_ip})",
            explain=f"This is your {selected['description']}. "
                   f"We'll use this IP address for reverse shell connections."
        )
        
        # Show other VPN interfaces if multiple found
        if len(vpn_candidates) > 1:
            self.logger.info("Other VPN interfaces detected:")
            for candidate in vpn_candidates[1:]:
                self.logger.list_item(
                    f"{candidate['interface']} ({candidate['ip']}) - {candidate['description']}"
                )
            self.logger.educational_note(
                "Multiple VPN Interfaces",
                "If you're connected to multiple VPNs, make sure you're using "
                "the correct one for your target network (HTB, THM, etc.)."
            )
        
        return self.vpn_interface
    
    def _verify_interface(self, interface: str) -> bool:
        """
        Verify interface exists and has an IP address.
        
        Args:
            interface: Interface name
            
        Returns:
            bool: True if valid
        """
        try:
            ip = NetworkUtils.get_interface_ip(interface)
            return ip is not None
        except Exception as e:
            self.logger.debug(f"Interface verification failed: {e}")
            return False
    
    def get_all_interfaces(self) -> List[Dict[str, str]]:
        """
        Get all network interfaces with details.
        
        Returns:
            List of interface info dicts
        """
        interfaces = []
        
        for iface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface)
                
                # Get IPv4 address
                ipv4 = None
                if netifaces.AF_INET in addrs:
                    ipv4 = addrs[netifaces.AF_INET][0]['addr']
                
                # Get MAC address
                mac = None
                if netifaces.AF_LINK in addrs:
                    mac = addrs[netifaces.AF_LINK][0]['addr']
                
                # Only include interfaces with IP addresses
                if ipv4:
                    interfaces.append({
                        'name': iface,
                        'ipv4': ipv4,
                        'mac': mac,
                        'is_vpn': self._is_vpn_interface(iface),
                        'is_loopback': iface == 'lo' or ipv4 == '127.0.0.1'
                    })
            except Exception as e:
                self.logger.debug(f"Error reading interface {iface}: {e}")
                continue
        
        self.all_interfaces = interfaces
        return interfaces
    
    def _is_vpn_interface(self, interface: str) -> bool:
        """
        Check if interface is likely a VPN interface.
        
        Args:
            interface: Interface name
            
        Returns:
            bool: True if VPN interface
        """
        vpn_patterns = ['tun', 'tap', 'utun', 'wg', 'ppp']
        return any(interface.startswith(pattern) for pattern in vpn_patterns)
    
    def get_interface_stats(self, interface: str) -> Optional[Dict]:
        """
        Get statistics for a specific interface.
        
        Args:
            interface: Interface name
            
        Returns:
            Dict with stats or None if error
        """
        try:
            # Try ifconfig first (more universal)
            try:
                result = subprocess.run(
                    ['ifconfig', interface],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                output = result.stdout
            except FileNotFoundError:
                # Fall back to ip command on Linux systems without ifconfig
                result = subprocess.run(
                    ['ip', 'addr', 'show', interface],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                output = result.stdout
            
            # Parse basic info
            stats = {
                'interface': interface,
                'up': 'UP' in output or 'state UP' in output,
                'running': 'RUNNING' in output,
            }
            
            # Extract RX/TX bytes if available
            rx_match = re.search(r'RX.*?bytes[:\s]+(\d+)', output)
            tx_match = re.search(r'TX.*?bytes[:\s]+(\d+)', output)
            
            if rx_match:
                stats['rx_bytes'] = int(rx_match.group(1))
            if tx_match:
                stats['tx_bytes'] = int(tx_match.group(1))
            
            return stats
            
        except Exception as e:
            self.logger.debug(f"Failed to get stats for {interface}: {e}")
            return None
    
    def test_vpn_connectivity(self) -> bool:
        """
        Test if VPN is actually working by pinging common gateways.
        
        Returns:
            bool: True if VPN is functional
        """
        if not self.vpn_interface or not self.vpn_ip:
            self.logger.error("No VPN interface detected to test")
            return False
        
        self.logger.info(f"Testing VPN connectivity on {self.vpn_interface}...")
        
        # Check if interface is up
        stats = self.get_interface_stats(self.vpn_interface)
        if stats and not stats.get('up'):
            self.logger.error(
                f"Interface {self.vpn_interface} is DOWN",
                explain="The VPN interface exists but is not active. "
                       "Try reconnecting to your VPN."
            )
            return False
        
        # Try to ping common VPN gateway IPs
        gateways = [
            ('10.10.10.2', 'HackTheBox'),
            ('10.10.14.1', 'HackTheBox'),
            ('10.9.0.1', 'TryHackMe'),
            ('10.8.0.1', 'TryHackMe'),
        ]
        
        self.logger.info("Pinging VPN gateways...")
        
        for gateway_ip, platform in gateways:
            if NetworkUtils.ping(gateway_ip, count=1, timeout=2):
                self.logger.success(
                    f"VPN connectivity confirmed ({platform} gateway: {gateway_ip})",
                    explain=f"Successfully reached {platform}'s VPN gateway. "
                           "Your VPN connection is working properly."
                )
                return True
        
        # No gateways responded
        self.logger.warning(
            "Could not verify VPN connectivity",
            explain="Unable to ping common VPN gateways. This doesn't necessarily mean "
                   "your VPN isn't working - some VPNs block ICMP. Your connection might "
                   "still work for TCP connections (reverse shells)."
        )
        return False
    
    def suggest_interface(self) -> Optional[str]:
        """
        Suggest the best interface to use.
        
        Returns:
            Suggested interface name or None
        """
        self.logger.info("Analyzing network interfaces...")
        
        # First priority: Try to find VPN
        vpn = self.detect_vpn_interface()
        if vpn:
            return vpn
        
        # Second priority: Non-loopback interface
        interfaces = self.get_all_interfaces()
        
        for iface in interfaces:
            if not iface['is_loopback'] and iface['ipv4'] != '127.0.0.1':
                self.logger.warning(
                    f"No VPN detected, suggesting {iface['name']} ({iface['ipv4']})",
                    explain="This is your primary network interface. "
                           "However, this might not work for CTF platforms like HTB/THM. "
                           "Consider connecting to the VPN first."
                )
                return iface['name']
        
        self.logger.error("No suitable network interfaces found")
        return None
    
    def display_interface_info(self):
        """Display detailed information about all interfaces."""
        interfaces = self.get_all_interfaces()
        
        if not interfaces:
            self.logger.error("No network interfaces found")
            return
        
        self.logger.header("Network Interfaces")
        
        headers = ["Interface", "IP Address", "MAC Address", "Type"]
        rows = []
        
        for iface in interfaces:
            # Determine type
            if iface['is_loopback']:
                iface_type = "Loopback"
            elif iface['is_vpn']:
                iface_type = f"{Colors.GREEN}VPN{Colors.RESET}"
            else:
                iface_type = "Standard"
            
            rows.append([
                iface['name'],
                iface['ipv4'],
                iface['mac'] or "N/A",
                iface_type
            ])
        
        self.logger.table(headers, rows)
        
        # Show selected interface
        if self.vpn_interface:
            self.logger.info(
                f"\n{Colors.HIGHLIGHT}Selected VPN:{Colors.RESET} "
                f"{self.vpn_interface} ({self.vpn_ip})"
            )
        else:
            self.logger.warning("\nNo VPN interface selected")
    
    def get_interface_ip(self, interface: str = None) -> Optional[str]:
        """
        Get IP address for interface.
        
        Args:
            interface: Interface name (uses VPN interface if None)
            
        Returns:
            IP address or None
        """
        if interface is None:
            if self.vpn_interface:
                return self.vpn_ip
            else:
                self.logger.warning("No interface specified and no VPN detected")
                return None
        
        return NetworkUtils.get_interface_ip(interface)
    
    def check_vpn_required(self, target_ip: str) -> bool:
        """
        Check if target IP suggests VPN is required.
        
        Args:
            target_ip: Target IP address
            
        Returns:
            bool: True if VPN likely required
        """
        # HTB/THM IP ranges
        vpn_ranges = [
            ('10.10.10.', 'HackTheBox'),
            ('10.10.11.', 'HackTheBox'),
            ('10.129.', 'HackTheBox'),
            ('10.9.', 'TryHackMe'),
            ('10.10.', 'TryHackMe/HackTheBox'),
        ]
        
        for prefix, platform in vpn_ranges:
            if target_ip.startswith(prefix):
                if not self.vpn_interface:
                    self.logger.error(
                        f"Target IP {target_ip} appears to be on {platform}",
                        explain=f"This IP range is typically used by {platform}. "
                               "You need to connect to their VPN to access this target."
                    )
                return True
        
        return False
    
    def troubleshoot_vpn(self):
        """Run VPN troubleshooting diagnostics."""
        self.logger.header("VPN Troubleshooting")
        
        # Check 1: VPN interface exists
        if not self.vpn_interface:
            self.logger.error("❌ No VPN interface detected")
            self.logger.info("\nTroubleshooting steps:")
            self.logger.list_item("1. Verify you're connected to VPN (openvpn, wireguard, etc.)")
            self.logger.list_item("2. Check VPN client is running: ps aux | grep vpn")
            self.logger.list_item("3. Look for tun/tap interfaces: ip addr show")
            return
        
        self.logger.success(f"✓ VPN interface detected: {self.vpn_interface}")
        
        # Check 2: Interface has IP
        if not self.vpn_ip:
            self.logger.error("❌ VPN interface has no IP address")
            self.logger.info("\nTroubleshooting steps:")
            self.logger.list_item("1. Reconnect to VPN")
            self.logger.list_item("2. Check VPN logs for errors")
            return
        
        self.logger.success(f"✓ VPN IP address: {self.vpn_ip}")
        
        # Check 3: Interface is up
        stats = self.get_interface_stats(self.vpn_interface)
        if stats and stats.get('up'):
            self.logger.success("✓ VPN interface is UP")
        else:
            self.logger.error("❌ VPN interface is DOWN")
            self.logger.info("\nTroubleshooting steps:")
            self.logger.list_item("1. Bring interface up: sudo ifconfig tun0 up")
            self.logger.list_item("2. Restart VPN connection")
            return
        
        # Check 4: Connectivity
        if self.test_vpn_connectivity():
            self.logger.success("✓ VPN connectivity working")
        else:
            self.logger.warning("⚠ VPN connectivity uncertain")
            self.logger.info("\nThis might be normal - some VPNs block ping")
        
        self.logger.success("\nVPN appears to be configured correctly!")
