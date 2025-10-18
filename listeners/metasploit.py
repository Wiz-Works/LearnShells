"""
Metasploit Framework listener for catching reverse shells
"""

import subprocess
import shutil
import os
import time
from typing import Optional, List
from learnshells.utils.logger import Logger


class MetasploitListener:
    """Metasploit Framework reverse shell listener."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize Metasploit listener.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.process = None
        self.is_running = False
        self.session_id = None
    
    def check_availability(self) -> bool:
        """
        Check if Metasploit Framework is available.
        
        Returns:
            bool: True if msfconsole is available
        """
        if shutil.which('msfconsole'):
            self.logger.success(
                "Found Metasploit Framework",
                explain="Metasploit is a comprehensive penetration testing framework. "
                       "It provides advanced features like session management, post-exploitation, "
                       "and automated privilege escalation."
            )
            return True
        
        self.logger.error(
            "Metasploit not found!",
            explain="Metasploit Framework is not installed. Install it with:\n"
                   "  Kali Linux: Already installed by default\n"
                   "  Ubuntu/Debian: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall\n"
                   "  Or download from: https://www.metasploit.com/"
        )
        return False
    
    def start(
        self,
        lhost: str,
        lport: int,
        payload: str = "generic/shell_reverse_tcp",
        auto_session: bool = True
    ) -> bool:
        """
        Start Metasploit multi/handler.
        
        Args:
            lhost: Local host IP (LHOST)
            lport: Local port (LPORT)
            payload: Metasploit payload to use
            auto_session: Automatically interact with session
            
        Returns:
            bool: True if listener started successfully
        """
        if not self.check_availability():
            return False
        
        # Display listener info
        self.logger.listener_info(lhost, lport, f"Metasploit ({payload})")
        
        # Build msfconsole resource script
        resource_script = self._generate_resource_script(
            lhost, lport, payload, auto_session
        )
        
        # Save resource script
        script_path = "/tmp/learnshells_msf.rc"
        try:
            with open(script_path, 'w') as f:
                f.write(resource_script)
        except Exception as e:
            self.logger.error(f"Failed to create resource script: {e}")
            return False
        
        self.logger.info("Starting Metasploit multi/handler...")
        
        if self.logger.educational:
            self.logger.educational_note(
                "Metasploit Multi/Handler",
                "Multi/handler is Metasploit's universal listener.\n"
                "It can catch shells from any compatible payload.\n\n"
                "Features:\n"
                "• Session management (background/foreground)\n"
                "• Post-exploitation modules\n"
                "• Automatic privilege escalation\n"
                "• Meterpreter upgrade paths\n"
                "• Network pivoting capabilities"
            )
        
        try:
            # Start msfconsole with resource script
            msf_args = ['msfconsole', '-q', '-r', script_path]
            
            self.process = subprocess.Popen(
                msf_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.is_running = True
            self.logger.success("Metasploit handler started!")
            
            # Wait for process
            self.process.wait()
            
            # Cleanup
            if os.path.exists(script_path):
                os.remove(script_path)
            
            return True
            
        except KeyboardInterrupt:
            self.logger.warning("\nListener interrupted by user")
            self.stop()
            if os.path.exists(script_path):
                os.remove(script_path)
            return False
        except Exception as e:
            self.logger.error(f"Failed to start Metasploit: {e}")
            if os.path.exists(script_path):
                os.remove(script_path)
            return False
    
    def _generate_resource_script(
        self,
        lhost: str,
        lport: int,
        payload: str,
        auto_session: bool
    ) -> str:
        """Generate Metasploit resource script."""
        script = f"""# LearnShells Metasploit Handler
use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j -z
"""
        return script
    
    def get_command(self, lhost: str, lport: int, payload: str = "generic/shell_reverse_tcp") -> str:
        """
        Get msfconsole command string.
        
        Args:
            lhost: Local host IP
            lport: Local port
            payload: Payload type
            
        Returns:
            Command string
        """
        return f"msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {lport}; exploit'"
    
    def stop(self):
        """Stop the running Metasploit handler."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                self.logger.info("Metasploit handler stopped")
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.logger.warning("Metasploit forcefully killed")
            except Exception as e:
                self.logger.debug(f"Error stopping handler: {e}")
            finally:
                self.process = None
                self.is_running = False
    
    def is_alive(self) -> bool:
        """Check if handler is still running."""
        if not self.process:
            return False
        return self.process.poll() is None
    
    def get_common_payloads(self) -> List[dict]:
        """Get list of common Metasploit payloads."""
        payloads = [
            {
                "name": "generic/shell_reverse_tcp",
                "description": "Generic reverse shell (works with most)",
                "platform": "multi"
            },
            {
                "name": "cmd/unix/reverse",
                "description": "Unix command shell",
                "platform": "unix"
            },
            {
                "name": "cmd/windows/reverse_powershell",
                "description": "Windows PowerShell reverse shell",
                "platform": "windows"
            },
            {
                "name": "linux/x86/shell_reverse_tcp",
                "description": "Linux x86 reverse shell",
                "platform": "linux"
            },
            {
                "name": "linux/x64/shell_reverse_tcp",
                "description": "Linux x64 reverse shell",
                "platform": "linux"
            },
            {
                "name": "windows/shell_reverse_tcp",
                "description": "Windows command shell",
                "platform": "windows"
            },
            {
                "name": "windows/meterpreter/reverse_tcp",
                "description": "Windows Meterpreter (staged)",
                "platform": "windows"
            },
            {
                "name": "python/shell_reverse_tcp",
                "description": "Python reverse shell",
                "platform": "python"
            }
        ]
        return payloads
    
    def list_payloads(self):
        """Display common payloads."""
        self.logger.header("Common Metasploit Payloads")
        
        payloads = self.get_common_payloads()
        
        headers = ["Payload", "Platform", "Description"]
        rows = [[p["name"], p["platform"], p["description"]] for p in payloads]
        
        self.logger.table(headers, rows)
    
    def get_usage_instructions(self) -> str:
        """Get usage instructions for Metasploit."""
        instructions = """
📋 METASPLOIT LISTENER USAGE:

Quick Start:
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD generic/shell_reverse_tcp; set LHOST 10.10.14.5; set LPORT 443; exploit"

Step by Step:
1. Start msfconsole:
   msfconsole

2. Use multi/handler:
   use exploit/multi/handler

3. Set payload:
   set PAYLOAD generic/shell_reverse_tcp

4. Set options:
   set LHOST 10.10.14.5
   set LPORT 443

5. Start handler:
   exploit

Common Options:
• LHOST: Your IP address (attacker machine)
• LPORT: Port to listen on
• PAYLOAD: Type of shell to catch
• ExitOnSession: false (keep handler running for multiple shells)

Session Management:
• sessions: List all active sessions
• sessions -i 1: Interact with session 1
• sessions -k 1: Kill session 1
• background: Background current session (Ctrl+Z)

Upgrading to Meterpreter:
1. Get basic shell first
2. Background it: background
3. Search for upgrade: search shell_to_meterpreter
4. Use module: use post/multi/manage/shell_to_meterpreter
5. Set session: set SESSION 1
6. Run: exploit

Post-Exploitation:
• sysinfo: System information
• getuid: Current user
• ps: List processes
• migrate <PID>: Migrate to another process
• shell: Drop to system shell
• upload/download: File transfer
• hashdump: Dump password hashes

Useful Commands:
• search <keyword>: Search modules
• info <module>: Module information
• show options: Show required options
• set <option> <value>: Set option
• exploit or run: Execute module

Why Use Metasploit?
✓ Session management (multiple shells)
✓ Post-exploitation modules
✓ Automatic privilege escalation
✓ Meterpreter features
✓ Network pivoting
✓ Database integration
✓ Extensive module library

When to Use Metasploit:
✓ Need session management
✓ Want post-exploitation capabilities
✓ Need to upgrade shells to Meterpreter
✓ Multiple targets
✓ Require pivoting
✓ Professional engagements

Disadvantages:
✗ Heavier than netcat/socat
✗ More complex setup
✗ Signatures often detected
✗ Startup time is slower
"""
        return instructions
    
    def explain_metasploit(self) -> str:
        """Explain Metasploit and multi/handler."""
        explanation = """
🎓 METASPLOIT FRAMEWORK EXPLAINED:

What is Metasploit?
Metasploit is a comprehensive penetration testing framework
developed by Rapid7. It's the most popular exploitation
framework in the security industry.

Components:
• msfconsole: Main command-line interface
• msfvenom: Payload generation tool
• msfdb: Database for storing results
• Modules: Exploits, payloads, post-exploitation

What is Multi/Handler?
Multi/handler (exploit/multi/handler) is Metasploit's
universal listener. It can catch shells from ANY compatible
payload, regardless of how it was generated.

How Multi/Handler Works:
1. You configure LHOST, LPORT, and PAYLOAD
2. Handler starts listening on specified port
3. Target executes your payload
4. Payload connects back to handler
5. Handler recognizes payload type
6. Session is created and managed

Session Management:
Unlike netcat (one connection, then done), Metasploit
manages multiple sessions:
• Background sessions (Ctrl+Z)
• Switch between sessions
• List all active sessions
• Kill specific sessions
• Interact with any session

Why Sessions Matter:
• Keep multiple shells organized
• Switch between targets easily
• Background while running post-exploitation
• Maintain access even if one shell dies

Meterpreter:
Meterpreter is Metasploit's advanced payload.
It runs in memory (fileless) and provides:
• File system access
• Screenshot capture
• Keylogging
• Webcam access
• Privilege escalation
• Process migration
• Network pivoting

Staged vs Stageless:
Staged: Small initial payload, downloads rest
  Example: windows/meterpreter/reverse_tcp
  Pros: Smaller initial size
  Cons: Two connections needed

Stageless: Complete payload in one package
  Example: windows/meterpreter_reverse_tcp
  Pros: Single connection, more reliable
  Cons: Larger payload size

Generic vs Specific Payloads:
generic/shell_reverse_tcp: Works with ANY shell
  Use this to catch shells from custom payloads

platform/specific/payload: Optimized for platform
  Use this for msfvenom-generated payloads

Post-Exploitation:
Metasploit shines in post-exploitation:
• Automated privilege escalation
• Credential dumping
• Lateral movement
• Persistence mechanisms
• Log cleaning
• Evidence collection

When to Use Metasploit:
✓ Professional penetration tests
✓ Need comprehensive tooling
✓ Managing multiple targets
✓ Require post-exploitation
✓ Want session management
✓ Need pivoting capabilities

When NOT to Use:
✗ Quick simple shells (use netcat)
✗ Heavily monitored environments (easily detected)
✗ Resource-constrained systems
✗ Need speed (msfconsole is slow to start)
"""
        return explanation
    
    def troubleshoot(self):
        """Help troubleshoot Metasploit issues."""
        self.logger.header("Metasploit Listener Troubleshooting")
        
        issues = []
        
        # Check 1: Is Metasploit installed?
        if not self.check_availability():
            issues.append((
                "Metasploit not installed",
                "Install from: https://www.metasploit.com/"
            ))
            return
        
        # Check 2: Is PostgreSQL running? (for msfdb)
        try:
            result = subprocess.run(
                ['msfdb', 'status'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if 'running' in result.stdout.lower():
                self.logger.success("✓ Metasploit database is running")
            else:
                issues.append((
                    "Metasploit database not running",
                    "Start it with: msfdb init && msfdb start"
                ))
        except Exception:
            self.logger.warning("⚠ Could not check database status")
        
        # Display issues
        if issues:
            self.logger.error("Found potential issues:")
            for issue, solution in issues:
                self.logger.list_item(f"{issue}")
                self.logger.list_item(f"  → Solution: {solution}", indent=1)
        else:
            self.logger.success("Metasploit appears to be configured correctly!")
        
        # Tips
        self.logger.tip(
            "First time using Metasploit?\n"
            "  1. Initialize database: msfdb init\n"
            "  2. Update Metasploit: msfupdate\n"
            "  3. Start console: msfconsole\n"
            "  4. Use multi/handler for catching shells"
        )
