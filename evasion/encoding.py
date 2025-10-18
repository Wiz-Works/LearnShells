"""
Encoding techniques for payload evasion
"""

import base64
import binascii
from urllib.parse import quote, quote_plus, unquote
from typing import Dict, List, Optional
from learnshells.utils.logger import Logger


class Encoder:
    """Encode payloads to evade detection."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize encoder.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
    
    # ========== Base64 Encoding ==========
    
    def base64_encode(self, text: str) -> str:
        """
        Base64 encode text.
        
        Args:
            text: Text to encode
            
        Returns:
            Base64 encoded string
        """
        encoded = base64.b64encode(text.encode()).decode()
        
        self.logger.success(
            "Base64 encoded",
            explain="Base64 encoding converts binary data to ASCII text. "
                   "Common for bypassing filters and hiding content."
        )
        
        return encoded
    
    def base64_decode(self, encoded: str) -> str:
        """
        Base64 decode text.
        
        Args:
            encoded: Base64 encoded string
            
        Returns:
            Decoded string
        """
        try:
            decoded = base64.b64decode(encoded.encode()).decode()
            self.logger.success("Base64 decoded")
            return decoded
        except Exception as e:
            self.logger.error(f"Base64 decode failed: {e}")
            return ""
    
    def base64_encode_unicode(self, text: str) -> str:
        """
        Base64 encode with UTF-16LE (for PowerShell -EncodedCommand).
        
        Args:
            text: Text to encode
            
        Returns:
            Base64 encoded UTF-16LE string
        """
        # PowerShell expects UTF-16LE encoding
        encoded_bytes = text.encode('utf-16le')
        b64 = base64.b64encode(encoded_bytes).decode()
        
        self.logger.success(
            "Base64 UTF-16LE encoded (PowerShell compatible)",
            explain="PowerShell's -EncodedCommand expects UTF-16LE encoding. "
                   "Use this for: powershell.exe -EncodedCommand <BASE64>"
        )
        
        return b64
    
    # ========== URL Encoding ==========
    
    def url_encode(self, text: str, safe: str = '') -> str:
        """
        URL encode text.
        
        Args:
            text: Text to encode
            safe: Characters to not encode
            
        Returns:
            URL encoded string
        """
        encoded = quote(text, safe=safe)
        
        self.logger.success(
            "URL encoded",
            explain="URL encoding replaces special characters with %XX notation. "
                   "Useful for web-based payloads and bypassing WAFs."
        )
        
        return encoded
    
    def url_encode_plus(self, text: str) -> str:
        """
        URL encode with plus signs for spaces.
        
        Args:
            text: Text to encode
            
        Returns:
            URL encoded string with + for spaces
        """
        encoded = quote_plus(text)
        
        self.logger.success("URL encoded (+ for spaces)")
        
        return encoded
    
    def url_decode(self, encoded: str) -> str:
        """
        URL decode text.
        
        Args:
            encoded: URL encoded string
            
        Returns:
            Decoded string
        """
        try:
            decoded = unquote(encoded)
            self.logger.success("URL decoded")
            return decoded
        except Exception as e:
            self.logger.error(f"URL decode failed: {e}")
            return ""
    
    def double_url_encode(self, text: str) -> str:
        """
        Double URL encode (encode twice).
        
        Args:
            text: Text to encode
            
        Returns:
            Double URL encoded string
        """
        first_pass = quote(text)
        second_pass = quote(first_pass)
        
        self.logger.success(
            "Double URL encoded",
            explain="Double encoding can bypass some WAFs that only decode once."
        )
        
        return second_pass
    
    # ========== Hex Encoding ==========
    
    def hex_encode(self, text: str) -> str:
        """
        Hex encode text.
        
        Args:
            text: Text to encode
            
        Returns:
            Hex encoded string
        """
        encoded = binascii.hexlify(text.encode()).decode()
        
        self.logger.success(
            "Hex encoded",
            explain="Hex encoding converts each byte to hexadecimal representation."
        )
        
        return encoded
    
    def hex_decode(self, encoded: str) -> str:
        """
        Hex decode text.
        
        Args:
            encoded: Hex encoded string
            
        Returns:
            Decoded string
        """
        try:
            decoded = binascii.unhexlify(encoded).decode()
            self.logger.success("Hex decoded")
            return decoded
        except Exception as e:
            self.logger.error(f"Hex decode failed: {e}")
            return ""
    
    def hex_encode_with_prefix(self, text: str, prefix: str = '\\x') -> str:
        """
        Hex encode with custom prefix (like \\x for Python).
        
        Args:
            text: Text to encode
            prefix: Prefix for each byte
            
        Returns:
            Hex encoded string with prefix
        """
        encoded = ''.join(f'{prefix}{byte:02x}' for byte in text.encode())
        
        self.logger.success(f"Hex encoded with {prefix} prefix")
        
        return encoded
    
    # ========== Octal Encoding ==========
    
    def octal_encode(self, text: str) -> str:
        """
        Octal encode text.
        
        Args:
            text: Text to encode
            
        Returns:
            Octal encoded string
        """
        encoded = ''.join(f'\\{ord(c):03o}' for c in text)
        
        self.logger.success(
            "Octal encoded",
            explain="Octal encoding uses base-8 representation. "
                   "Useful in some shells and programming contexts."
        )
        
        return encoded
    
    # ========== ROT13 Encoding ==========
    
    def rot13_encode(self, text: str) -> str:
        """
        ROT13 encode text (Caesar cipher).
        
        Args:
            text: Text to encode
            
        Returns:
            ROT13 encoded string
        """
        import codecs
        encoded = codecs.encode(text, 'rot_13')
        
        self.logger.success(
            "ROT13 encoded",
            explain="ROT13 rotates each letter by 13 positions. "
                   "Simple obfuscation, not for security."
        )
        
        return encoded
    
    # ========== Special Encodings ==========
    
    def unicode_escape(self, text: str) -> str:
        """
        Unicode escape encoding.
        
        Args:
            text: Text to encode
            
        Returns:
            Unicode escaped string
        """
        encoded = text.encode('unicode_escape').decode()
        
        self.logger.success("Unicode escaped")
        
        return encoded
    
    def html_entity_encode(self, text: str) -> str:
        """
        HTML entity encode text.
        
        Args:
            text: Text to encode
            
        Returns:
            HTML entity encoded string
        """
        import html
        encoded = html.escape(text)
        
        self.logger.success(
            "HTML entity encoded",
            explain="HTML entities replace special characters with &codes;. "
                   "Useful for XSS and HTML injection payloads."
        )
        
        return encoded
    
    # ========== PowerShell Specific ==========
    
    def powershell_char_encoding(self, text: str) -> str:
        """
        Encode as PowerShell [char] array.
        
        Args:
            text: Text to encode
            
        Returns:
            PowerShell char array string
        """
        chars = ','.join(str(ord(c)) for c in text)
        encoded = f"[char[]]({chars}) -join ''"
        
        self.logger.success(
            "PowerShell char array encoded",
            explain="Converts string to array of character codes. "
                   "PowerShell reconstructs the string at runtime."
        )
        
        return encoded
    
    def powershell_format_string(self, text: str) -> str:
        """
        Encode using PowerShell format string.
        
        Args:
            text: Text to encode
            
        Returns:
            PowerShell format string
        """
        # Split into chunks and use format operator
        chars = [c for c in text]
        format_str = "'{0}' -f " + ",".join(f"'{c}'" for c in chars)
        
        self.logger.success("PowerShell format string encoded")
        
        return format_str
    
    # ========== Bash Specific ==========
    
    def bash_octal_encoding(self, text: str) -> str:
        """
        Encode for Bash using $'...' syntax with octal.
        
        Args:
            text: Text to encode
            
        Returns:
            Bash octal encoded string
        """
        encoded = "$'" + ''.join(f'\\{ord(c):03o}' for c in text) + "'"
        
        self.logger.success(
            "Bash octal encoded",
            explain="Bash $'...' syntax interprets escape sequences including octal."
        )
        
        return encoded
    
    def bash_hex_encoding(self, text: str) -> str:
        """
        Encode for Bash using $'...' syntax with hex.
        
        Args:
            text: Text to encode
            
        Returns:
            Bash hex encoded string
        """
        encoded = "$'" + ''.join(f'\\x{ord(c):02x}' for c in text) + "'"
        
        self.logger.success("Bash hex encoded")
        
        return encoded
    
    # ========== Multiple Encoding ==========
    
    def encode_multiple(
        self,
        text: str,
        methods: List[str]
    ) -> str:
        """
        Apply multiple encoding methods in sequence.
        
        Args:
            text: Text to encode
            methods: List of encoding methods to apply in order
            
        Returns:
            Multi-encoded string
        """
        encoded = text
        
        for method in methods:
            if method == 'base64':
                encoded = self.base64_encode(encoded)
            elif method == 'url':
                encoded = self.url_encode(encoded)
            elif method == 'hex':
                encoded = self.hex_encode(encoded)
            elif method == 'rot13':
                encoded = self.rot13_encode(encoded)
        
        self.logger.success(
            f"Applied {len(methods)} encoding methods: {' → '.join(methods)}",
            explain="Multiple encoding layers increase evasion but require proper decoding."
        )
        
        return encoded
    
    # ========== Encoding Analysis ==========
    
    def get_all_encodings(self, text: str) -> Dict[str, str]:
        """
        Get all available encodings for text.
        
        Args:
            text: Text to encode
            
        Returns:
            Dict of encoding_name: encoded_value
        """
        encodings = {
            'base64': self.base64_encode(text),
            'base64_unicode': self.base64_encode_unicode(text),
            'url': self.url_encode(text),
            'url_plus': self.url_encode_plus(text),
            'double_url': self.double_url_encode(text),
            'hex': self.hex_encode(text),
            'hex_with_prefix': self.hex_encode_with_prefix(text),
            'octal': self.octal_encode(text),
            'rot13': self.rot13_encode(text),
            'unicode_escape': self.unicode_escape(text),
            'html_entity': self.html_entity_encode(text),
            'powershell_char': self.powershell_char_encoding(text),
            'bash_octal': self.bash_octal_encoding(text),
            'bash_hex': self.bash_hex_encoding(text)
        }
        
        return encodings
    
    def display_all_encodings(self, text: str):
        """
        Display all encodings in a formatted table.
        
        Args:
            text: Text to encode
        """
        self.logger.header(f"All Encodings for: {text[:50]}...")
        
        encodings = self.get_all_encodings(text)
        
        for name, encoded in encodings.items():
            self.logger.subheader(name.replace('_', ' ').title())
            # Truncate if too long
            display = encoded if len(encoded) < 100 else encoded[:97] + "..."
            self.logger.code_block(display)
    
    def explain_encoding(self) -> str:
        """Explain encoding techniques and their uses."""
        explanation = """
🎓 ENCODING EXPLAINED:

What is Encoding?
Encoding transforms data from one format to another.
Unlike encryption, encoding is reversible without a key.

Purpose in Hacking:
• Bypass input filters
• Evade signature detection
• Hide malicious content
• Avoid special character issues
• Bypass WAFs (Web Application Firewalls)

Common Encodings:

1. BASE64:
   Input:  "hello"
   Output: "aGVsbG8="
   
   Uses:
   • Universal encoding
   • Binary-safe transmission
   • PowerShell -EncodedCommand
   • Email attachments
   
   Detection: Easy (looks like Base64)

2. URL ENCODING:
   Input:  "test=value&cmd=whoami"
   Output: "test%3Dvalue%26cmd%3Dwhoami"
   
   Uses:
   • Web payloads
   • GET/POST parameters
   • XSS attacks
   • SQL injection
   
   Detection: Medium (expected in URLs)

3. HEX ENCODING:
   Input:  "abc"
   Output: "616263" or "\\x61\\x62\\x63"
   
   Uses:
   • Binary data representation
   • SQL injection (0x...)
   • Memory addresses
   • Shellcode
   
   Detection: Easy (pattern of hex digits)

4. UNICODE ESCAPING:
   Input:  "test"
   Output: "\\u0074\\u0065\\u0073\\u0074"
   
   Uses:
   • JavaScript payloads
   • JSON data
   • XSS bypass
   
   Detection: Medium

5. HTML ENTITIES:
   Input:  "<script>"
   Output: "&lt;script&gt;"
   
   Uses:
   • XSS prevention (defense)
   • XSS bypass (attack)
   • HTML injection
   
   Detection: Low (normal in HTML)

Encoding Chains:

Single Encoding:
Text → Base64 → "dGVzdA=="

Double Encoding:
Text → URL encode → URL encode again
"test" → "test" → "%74%65%73%74" → "%25%37%34%25%36%35..."

Multiple Methods:
Text → Base64 → URL encode → Hex
Creates complex encoding layers

Why Chain Encodings?
• Bypass multiple filters
• Defeat simple decoders
• Increase evasion
• Complicate analysis

But Remember:
• More encoding = larger payload
• Each layer must be decoded
• Can break functionality
• Increases complexity

Platform-Specific:

PowerShell:
• -EncodedCommand (Base64 UTF-16LE)
• [char[]] arrays
• [Convert]::FromBase64String()

Bash:
• $'\\xHH' hex notation
• $'\\OOO' octal notation
• echo -e "\\x..."

Python:
• '\\x' prefix for bytes
• .encode('hex')
• base64.b64encode()

PHP:
• base64_encode()
• urlencode()
• bin2hex()

Detection Methods:

Defenders detect encoding via:
• Entropy analysis
• Pattern recognition
• Known encoding signatures
• Decoder attempts
• Behavioral analysis

Evasion Tips:
✓ Use appropriate encoding for context
✓ Test decoded output works
✓ Mix encoding types
✓ Add legitimate-looking padding
✓ Time your decoding carefully

Best Practices:

For Attack:
1. Know your target's decoder
2. Test encoding/decoding locally
3. Keep encoded payload small
4. Have fallback if detected
5. Document your encoding chain

For Defense:
1. Decode all inputs
2. Check multiple encoding levels
3. Normalize data before validation
4. Log suspicious encodings
5. Use WAF with decoder

Common Mistakes:

❌ Encoding without testing decode
❌ Too many encoding layers
❌ Wrong encoding for platform
❌ Forgetting to decode
❌ Breaking syntax with encoding

✓ Test decode before attack
✓ Minimal necessary encoding
✓ Platform-appropriate encoding
✓ Verify decode works
✓ Maintain valid syntax

Real-World Examples:

XSS Bypass:
Normal:    <script>alert(1)</script>
URL:       %3Cscript%3Ealert(1)%3C/script%3E
Hex:       \\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E
Unicode:   \\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E

SQL Injection:
Normal:    ' OR 1=1--
URL:       %27%20OR%201%3D1--
Hex:       0x27204f5220313d312d2d

PowerShell:
Normal:    Invoke-Expression
Base64:    SW52b2tlLUV4cHJlc3Npb24=
Char:      [char[]]73,110,118,111,107,101 -join ''

Remember:
Encoding is NOT encryption!
Anyone can decode encoded data.
Use encoding for evasion, not security.
"""
        return explanation
    
    def get_decoder_command(self, encoding_type: str, encoded_text: str) -> str:
        """
        Get command to decode specific encoding.
        
        Args:
            encoding_type: Type of encoding
            encoded_text: Encoded text
            
        Returns:
            Decoder command
        """
        decoders = {
            'base64': f"echo '{encoded_text}' | base64 -d",
            'base64_powershell': f"[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{encoded_text}'))",
            'url': f"python3 -c \"from urllib.parse import unquote; print(unquote('{encoded_text}'))\"",
            'hex': f"echo '{encoded_text}' | xxd -r -p",
            'rot13': f"echo '{encoded_text}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'"
        }
        
        return decoders.get(encoding_type, "# Decoder not available")
    
    def recommend_encoding(self, context: str) -> List[str]:
        """
        Recommend encodings for specific context.
        
        Args:
            context: Usage context (web, powershell, bash, etc.)
            
        Returns:
            List of recommended encodings
        """
        recommendations = {
            'web': ['url', 'double_url', 'html_entity', 'unicode_escape'],
            'powershell': ['base64_unicode', 'powershell_char', 'base64'],
            'bash': ['bash_hex', 'bash_octal', 'base64'],
            'python': ['hex_with_prefix', 'unicode_escape', 'base64'],
            'general': ['base64', 'url', 'hex']
        }
        
        return recommendations.get(context.lower(), recommendations['general'])
