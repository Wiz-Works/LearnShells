"""
Netcat listener for catching reverse shells
"""

import subprocess
import shutil
import os
import signal
import time
from typing import Optional
from learnshells.utils.logger import Logger
from learnshells.utils.colors import Colors


class NetcatListener:
    """Netcat-based reverse shell listener."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize netcat listener.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.process = None
        self.nc_path = None
        self.nc_variant = None
        self.is_running = False
    
    def check_availability(self) -> bool:
        """
        Check if netcat is available on system.
        
        Returns:
            bool: True if netcat is available
        """
        # Try common netcat commands
        nc_commands = ['nc', 'ncat', 'netcat']
        
        for cmd in nc_commands:
            path = shutil.which(cmd)
            if path:
                self.nc_path = cmd
                self._detect_variant()
                self.logger.success(
                    f"Found netcat: {cmd} ({self.nc_variant})",
                    explain="Netcat is the classic tool for network connections. "
                           "It's perfect for catching reverse shells and is available on virtually every system."
                )
                return True
        
        self.logger.error(
            "Netcat not found!",
            explain="Netcat (nc) is not installed. Install it with:\n"
                   "  Ubuntu/Debian: sudo apt install netcat-traditional\n"
                   "  Or ncat: sudo apt install ncat\n"
                   "  Kali Linux: Already installed by default"
        )
        return False
    
    def _detect_variant(self):
        """Detect which variant of netcat is installed."""
        try:
            result = subprocess.run(
                [self.nc_path, '-h'],
                capture_output=True,
                text=True,
                timeout=2
            )
            output = result.stdout + result.stderr
            
            if 'nmap' in output.lower() or 'ncat' in output.lower():
                self.nc_variant = 'ncat (Nmap)'
            elif 'openbsd' in output.lower():
                self.nc_variant = 'OpenBSD netcat'
            elif 'traditional' in output.lower():
                self.nc_variant = 'Traditional netcat'
            else:
                self.nc_variant = 'Unknown variant'
            
            self.logger.debug(f"Detected netcat variant: {self.nc_variant}")
                
        except Exception as e:
            self.logger.debug(f"Could not detect variant: {e}")
            self.nc_variant = 'Unknown'
    
    def start(
        self,
        port: int,
        interface: str = "0.0.0.0",
        use_rlwrap: bool = True,
        verbose: bool = False
    ) -> bool:
        """
        Start netcat listener.
        
        Args:
            port: Port to listen on
            interface: Interface to bind to (default: all interfaces)
            use_rlwrap: Use rlwrap for better command history
            verbose: Verbose output
            
        Returns:
            bool: True if listener started successfully
        """
        if not self.check_availability():
            return False
        
        # Build netcat command
        nc_args = [self.nc_path, '-lvnp', str(port)]
        
        # Check if rlwrap is available and requested
        if use_rlwrap and shutil.which('rlwrap'):
            nc_args = ['rlwrap'] + nc_args
            self.logger.info(
                "Using rlwrap for better shell experience",
                explain="rlwrap provides command history and line editing. "
                       "You can use arrow keys to navigate through your command history, "
                       "just like a normal terminal!"
            )
        elif use_rlwrap:
            self.logger.warning(
                "rlwrap not found, proceeding without it",
                explain="rlwrap improves the shell experience with command history and line editing. "
                       "Install it with: sudo apt install rlwrap"
            )
        
        # Display listener info
        self.logger.listener_info(interface, port, f"Netcat ({self.nc_variant})")
        
        self.logger.info(f"Starting listener: {' '.join(nc_args)}")
        self.logger.separator()
        
        if self.logger.educational:
            self.logger.educational_note(
                "Netcat Listener",
                "Netcat will listen for incoming connections on the specified port.\n"
                "When the target executes your payload, it will connect back here.\n"
                "Once connected, you'll have an interactive shell!\n\n"
                "Listener Workflow:\n"
                "1. Netcat binds to the port and waits\n"
                "2. Target executes reverse shell payload\n"
                "3. Target connects back to this listener\n"
                "4. Connection established - you have a shell!\n\n"
                "Important Tips:\n"
                "• Use Ctrl+C carefully - it might kill your shell\n"
                "• Use Ctrl+Z to background the shell (for TTY upgrade)\n"
                "• Type 'exit' in the shell to disconnect gracefully\n"
                "• Keep the listener running until shell connects"
            )
        
        try:
            # Start listener
            self.logger.loading("Starting netcat listener")
            
            self.process = subprocess.Popen(
                nc_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.is_running = True
            self.logger.success("Listener started! Waiting for connection...")
            self.logger.info("Press Ctrl+C to stop the listener\n")
            
            # Wait for the process (blocking - this is interactive mode)
            self.process.wait()
            
            return True
            
        except KeyboardInterrupt:
            self.logger.warning("\nListener interrupted by user")
            self.stop()
            return False
        except Exception as e:
            self.logger.error(f"Failed to start listener: {e}")
            return False
    
    def start_background(
        self,
        port: int,
        interface: str = "0.0.0.0"
    ) -> bool:
        """
        Start listener in background (non-blocking).
        
        Args:
            port: Port to listen on
            interface: Interface to bind to
            
        Returns:
            bool: True if started successfully
        """
        if not self.check_availability():
            return False
        
        nc_args = [self.nc_path, '-lvnp', str(port)]
        
        try:
            self.process = subprocess.Popen(
                nc_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setpgrp  # Create new process group
            )
            
            self.is_running = True
            self.logger.success(f"Background listener started on port {port}")
            
            # Give it a moment to start
            time.sleep(0.5)
            
            # Check if still running
            if self.process.poll() is not None:
                self.logger.error("Listener failed to start")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start background listener: {e}")
            return False
    
    def stop(self):
        """Stop the running listener."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
                self.logger.info("Listener stopped")
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.logger.warning("Listener forcefully killed")
            except Exception as e:
                self.logger.debug(f"Error stopping listener: {e}")
            finally:
                self.process = None
                self.is_running = False
    
    def is_alive(self) -> bool:
        """
        Check if listener is still running.
        
        Returns:
            bool: True if listener is active
        """
        if not self.process:
            return False
        return self.process.poll() is None
    
    def get_command(self, port: int, use_rlwrap: bool = True) -> str:
        """
        Get the netcat command string.
        
        Args:
            port: Port to listen on
            use_rlwrap: Include rlwrap
            
        Returns:
            Command string
        """
        cmd = f"nc -lvnp {port}"
        
        if use_rlwrap and shutil.which('rlwrap'):
            cmd = f"rlwrap {cmd}"
        
        return cmd
    
    def get_usage_instructions(self) -> str:
        """Get usage instructions for netcat."""
        instructions = """
📋 NETCAT LISTENER USAGE:

Basic Command:
nc -lvnp <port>

With rlwrap (recommended):
rlwrap nc -lvnp <port>

Flags Explained:
• -l: Listen mode (wait for incoming connection)
• -v: Verbose (show connection details)
• -n: No DNS lookups (faster, more reliable)
• -p: Port to listen on

Example:
nc -lvnp 443

Common Ports to Use:
• 443 (HTTPS): Most likely to work through firewalls
• 80 (HTTP): Also commonly allowed
• 22 (SSH): Often allowed for outbound connections
• 4444: Metasploit default (often blocked by security)
• 1234, 9001: Common alternatives

WHY THESE PORTS?
Ports 443 and 80 are standard web traffic ports.
Firewalls rarely block outbound connections to these ports,
making them ideal for reverse shells.

RLWRAP Benefits:
✓ Command history (up/down arrows)
✓ Line editing (left/right arrows)
✓ Ctrl+R for reverse search
✓ Better overall shell experience
✓ Makes basic shells feel more interactive

Install rlwrap:
sudo apt install rlwrap

Once Connected:
• Type commands normally
• Use 'exit' to disconnect gracefully
• Ctrl+C kills the shell (be careful!)
• Ctrl+Z backgrounds shell (useful for TTY upgrade)

Shell Upgrade (Linux):
After getting a basic shell, upgrade to full TTY:

1. Spawn PTY:
   python3 -c 'import pty; pty.spawn("/bin/bash")'
   
2. Background shell:
   Press Ctrl+Z
   
3. Configure terminal:
   stty raw -echo; fg
   
4. Set terminal type:
   export TERM=xterm
   
5. Fix terminal size:
   stty rows 38 columns 116

Troubleshooting:
• "Address already in use": Port is taken
  Solution: Try different port or: lsof -ti:<port> | xargs kill
  
• "Permission denied": Ports < 1024 need root
  Solution: Use port >= 1024 or run with sudo
  
• Connection drops immediately: Unstable payload
  Solution: Try different payload or check firewall
  
• No prompt appears: Shell connected but waiting
  Solution: Press Enter or type a command

Alternative Netcat Variants:
• nc: Traditional netcat (most common)
• ncat: Nmap's netcat (more features, SSL support)
• netcat: OpenBSD netcat (modern, secure)

All variants work similarly for basic reverse shells.

TIPS:
✓ Start listener BEFORE executing payload on target
✓ Use rlwrap for better experience
✓ Choose common ports (443, 80) for better success
✓ Keep terminal window open while waiting
✓ Be patient - connection might take a few seconds
"""
        return instructions
    
    def explain_netcat(self) -> str:
        """Explain how netcat works."""
        explanation = """
🎓 HOW NETCAT WORKS:

What is Netcat?
Netcat (nc) is a networking utility that reads and writes data
across network connections using TCP or UDP protocols.
It's called the "Swiss Army knife" of networking because it
can do almost anything network-related.

Created by: Hobbit in 1995
Purpose: Network debugging and exploration
Nickname: "nc" (the command)

Listener Mode (-l):
When you use the -l flag, netcat enters "listen mode".
It binds to a specified port and waits for incoming connections.
Think of it like a server waiting for clients.

What Happens When You Start a Listener:
1. Netcat binds to the specified port (e.g., 443)
2. Netcat enters listening state (waiting for connections)
3. Your terminal shows "listening on [any] 443..."
4. When a connection arrives, netcat accepts it
5. Now you have a bidirectional channel!

Reverse Shell Flow:
┌─────────────┐                    ┌─────────────┐
│   ATTACKER  │                    │   TARGET    │
│  (You)      │                    │  (Victim)   │
└─────────────┘                    └─────────────┘
      │                                  │
      │ 1. Start listener                │
      │    nc -lvnp 443                  │
      │                                  │
      │                                  │ 2. Execute payload
      │                                  │    connects to you
      │                                  │
      │ <──────── Connection ────────────│
      │         established              │
      │                                  │
      │ 3. Type: whoami                  │
      │ ──────────────────────────────> │
      │                                  │
      │                                  │ 4. Execute & return
      │ <────────── www-data ────────────│
      │                                  │

Why "Reverse" Shell?
Normal shell:  You connect TO target (often blocked)
Reverse shell: Target connects TO you (usually allowed)

Firewalls typically:
✓ Allow outbound connections (target → you)
✗ Block inbound connections (you → target)

This is why reverse shells work so well!

The -lvnp Flags Breakdown:
• -l (listen): Wait for incoming connection
• -v (verbose): Show detailed connection info
• -n (no DNS): Don't resolve hostnames (faster)
• -p (port): Specify which port to listen on

Why These Flags Matter:
-l: Without this, nc tries to connect OUT instead of listening
-v: Shows you when connection arrives and details about it
-n: Speeds up connection and avoids DNS issues
-p: Tells nc exactly which port to use

Data Flow in Netcat:
Your keyboard → Netcat → Network → Target shell
Target shell → Network → Netcat → Your screen

Everything you type goes to the target's shell.
Everything the shell outputs comes back to you.

Netcat vs Other Listeners:
• Netcat: Simple, fast, universal, no frills
• Socat: Advanced, full TTY, encryption support
• Metasploit: Full framework, session management

When to Use Netcat:
✓ Quick and simple shells
✓ Testing connectivity
✓ File transfers
✓ Port scanning
✓ Banner grabbing
✓ Learning pentesting
✓ CTF challenges (HTB, THM)

Advantages of Netcat:
✓ Available on almost every Unix system
✓ Tiny footprint (lightweight)
✓ Simple syntax (easy to remember)
✓ Fast startup (instant)
✓ Versatile (many use cases)
✓ No dependencies
✓ Works immediately

Disadvantages of Netcat:
✗ Basic shells (not full TTY by default)
✗ No encryption
✗ No session management
✗ Single connection (one shell at a time)
✗ Ctrl+C kills the shell
✗ No command history (without rlwrap)

This is why we:
• Use rlwrap for better experience
• Upgrade to full TTY after connecting
• Use socat for advanced features
• Use Metasploit for session management
"""
        return explanation
    
    def troubleshoot(self, port: int):
        """Help troubleshoot listener issues."""
        self.logger.header("Netcat Listener Troubleshooting")
        
        issues = []
        
        # Check 1: Is netcat installed?
        if not self.check_availability():
            issues.append((
                "Netcat not installed",
                "Install netcat: sudo apt install netcat-traditional or ncat"
            ))
            return
        
        self.logger.info(f"Testing port {port}...")
        
        # Check 2: Is port available?
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('', port))
            sock.close()
            self.logger.success(f"✓ Port {port} is available")
        except OSError:
            issues.append((
                f"Port {port} is already in use",
                f"Find what's using it: lsof -ti:{port}\n"
                f"  Kill the process: lsof -ti:{port} | xargs kill\n"
                f"  Or use a different port"
            ))
        
        # Check 3: Permission for low ports
        if port < 1024:
            issues.append((
                f"Port {port} requires root privileges",
                "Use port >= 1024 (e.g., 4444, 9001) or run with sudo"
            ))
        
        # Check 4: Is rlwrap available?
        if not shutil.which('rlwrap'):
            self.logger.warning("⚠ rlwrap not installed (optional but recommended)")
            self.logger.info("  Install: sudo apt install rlwrap")
            self.logger.info("  Benefit: Adds command history and line editing to shells")
        else:
            self.logger.success("✓ rlwrap is available")
        
        # Display issues
        if issues:
            self.logger.error("Found potential issues:")
            for issue, solution in issues:
                self.logger.list_item(f"{issue}")
                self.logger.list_item(f"  → Solution: {solution}", indent=1)
        else:
            self.logger.success("No obvious issues found! Ready to catch shells.")
        
        # Additional tips
        self.logger.newline()
        self.logger.tip(
            "If connection fails after listener starts:\n"
            "  • Check local firewall: sudo ufw allow <port>/tcp\n"
            "  • Verify you're using correct VPN IP in payload\n"
            "  • Test egress filtering on target\n"
            "  • Try common ports: 443, 80, 22"
        )
        
        self.logger.tip(
            "For better shell experience:\n"
            "  1. Use rlwrap: rlwrap nc -lvnp 443\n"
            "  2. Upgrade to TTY after connection\n"
            "  3. Or use socat for automatic full TTY"
        )
    
    def test_connection(self, port: int) -> bool:
        """
        Test if we can bind to the port.
        
        Args:
            port: Port to test
            
        Returns:
            bool: True if port is available
        """
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', port))
            sock.close()
            self.logger.success(f"Port {port} test successful")
            return True
        except OSError as e:
            self.logger.error(f"Port {port} test failed: {e}")
            return False
    
    def get_shell_upgrade_commands(self) -> dict:
        """Get commands for upgrading basic shells to full TTY."""
        commands = {
            "python3": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "python2": "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "script": "script -qc /bin/bash /dev/null",
            "background": "Press Ctrl+Z",
            "configure": "stty raw -echo; fg",
            "export_term": "export TERM=xterm",
            "resize": "stty rows 38 columns 116"
        }
        
        return commands
    
    def display_upgrade_guide(self):
        """Display step-by-step shell upgrade guide."""
        self.logger.header("Shell Upgrade Guide")
        
        self.logger.numbered_item(1, "Spawn a PTY (Pseudo-Terminal)")
        self.logger.code_block("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
        
        self.logger.numbered_item(2, "Background the shell")
        self.logger.info("Press: Ctrl+Z")
        
        self.logger.numbered_item(3, "Configure your terminal for raw input")
        self.logger.code_block("stty raw -echo; fg")
        
        self.logger.numbered_item(4, "Set terminal type")
        self.logger.code_block("export TERM=xterm")
        
        self.logger.numbered_item(5, "Fix terminal size (optional)")
        self.logger.code_block("stty rows 38 columns 116")
        
        self.logger.success("\nYour shell now has:")
        self.logger.list_item("Tab completion")
        self.logger.list_item("Arrow key history")
        self.logger.list_item("Ctrl+C works properly")
        self.logger.list_item("Text editors work (vim, nano)")
        self.logger.list_item("Proper terminal rendering")
