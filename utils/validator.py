"""
Validation utilities for LearnShells
"""

import re
import os
from typing import Optional, List
from urllib.parse import urlparse


class Validator:
    """Input validation and sanitization utilities."""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """
        Validate IPv4 address format.
        
        Args:
            ip: IP address string
            
        Returns:
            bool: True if valid
        """
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        
        # Check each octet is 0-255
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """
        Validate port number.
        
        Args:
            port: Port number
            
        Returns:
            bool: True if valid (1-65535)
        """
        return 1 <= port <= 65535
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """
        Validate URL format.
        
        Args:
            url: URL string
            
        Returns:
            bool: True if valid
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        """
        Validate hostname format.
        
        Args:
            hostname: Hostname string
            
        Returns:
            bool: True if valid
        """
        # Basic hostname validation
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        return bool(re.match(pattern, hostname))
    
    @staticmethod
    def validate_payload_type(payload_type: str) -> bool:
        """
        Validate payload type is supported.
        
        Args:
            payload_type: Payload type (bash, python, php, etc.)
            
        Returns:
            bool: True if supported
        """
        valid_types = [
            'bash', 'sh',
            'python', 'python2', 'python3',
            'php',
            'powershell', 'ps',
            'perl',
            'ruby', 'rb',
            'nodejs', 'node', 'javascript', 'js',
            'nc', 'netcat',
            'socat',
            'msfvenom'
        ]
        return payload_type.lower() in valid_types
    
    @staticmethod
    def sanitize_command(command: str) -> str:
        """
        Sanitize command for safe execution.
        
        Args:
            command: Command string
            
        Returns:
            Sanitized command
        """
        # Remove dangerous characters
        dangerous = ['&', '|', ';', '`', '$', '(', ')', '<', '>', '\n', '\r']
        sanitized = command
        for char in dangerous:
            sanitized = sanitized.replace(char, '')
        return sanitized.strip()
    
    @staticmethod
    def validate_file_path(path: str, must_exist: bool = False) -> bool:
        """
        Validate file path.
        
        Args:
            path: File path
            must_exist: Whether file must exist
            
        Returns:
            bool: True if valid
        """
        try:
            # Check for path traversal attempts
            if '..' in path or path.startswith('/'):
                return False
            
            if must_exist:
                return os.path.isfile(path)
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def validate_interface_name(interface: str) -> bool:
        """
        Validate network interface name.
        
        Args:
            interface: Interface name (e.g., tun0, eth0)
            
        Returns:
            bool: True if valid format
        """
        pattern = r'^[a-zA-Z0-9]+$'
        return bool(re.match(pattern, interface))
    
    @staticmethod
    def validate_mac_address(mac: str) -> bool:
        """
        Validate MAC address format.
        
        Args:
            mac: MAC address
            
        Returns:
            bool: True if valid
        """
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac))
    
    @staticmethod
    def is_safe_payload(payload: str) -> tuple[bool, Optional[str]]:
        """
        Check if payload is safe (not targeting localhost, etc.).
        
        Args:
            payload: Payload string
            
        Returns:
            Tuple of (is_safe, reason)
        """
        # Check for localhost targets
        localhost_patterns = [
            '127.0.0.1',
            'localhost',
            '::1',
            '0.0.0.0'
        ]
        
        for pattern in localhost_patterns:
            if pattern in payload:
                return False, f"Payload targets localhost ({pattern})"
        
        # Check for destructive commands
        destructive_commands = [
            'rm -rf /',
            'dd if=/dev/zero',
            'mkfs',
            ':(){:|:&};:',  # Fork bomb
            'chmod -R 777 /',
        ]
        
        for cmd in destructive_commands:
            if cmd in payload:
                return False, f"Payload contains destructive command"
        
        return True, None
    
    @staticmethod
    def extract_ips_from_text(text: str) -> List[str]:
        """
        Extract all IP addresses from text.
        
        Args:
            text: Text to search
            
        Returns:
            List of IP addresses found
        """
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(pattern, text)
        return [ip for ip in matches if Validator.validate_ip(ip)]
    
    @staticmethod
    def extract_urls_from_text(text: str) -> List[str]:
        """
        Extract URLs from text.
        
        Args:
            text: Text to search
            
        Returns:
            List of URLs found
        """
        pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(pattern, text)
    
    @staticmethod
    def validate_encoding(encoding: str) -> bool:
        """
        Validate encoding type.
        
        Args:
            encoding: Encoding type (base64, url, hex)
            
        Returns:
            bool: True if valid
        """
        valid_encodings = ['base64', 'url', 'hex', 'none']
        return encoding.lower() in valid_encodings
    
    @staticmethod
    def validate_shell_type(shell_type: str) -> bool:
        """
        Validate shell type.
        
        Args:
            shell_type: Shell type (bash, sh, zsh, etc.)
            
        Returns:
            bool: True if valid
        """
        valid_shells = [
            'bash', 'sh', 'zsh', 'fish', 'ksh',
            'cmd', 'powershell', 'pwsh'
        ]
        return shell_type.lower() in valid_shells
    
    @staticmethod
    def is_elevated_command(command: str) -> bool:
        """
        Check if command requires elevated privileges.
        
        Args:
            command: Command string
            
        Returns:
            bool: True if requires sudo/admin
        """
        elevated_patterns = [
            r'\bsudo\b',
            r'\bsu\b',
            r'\bsudo\s+-',
            r'\/etc\/',
            r'\/root\/',
            r'\/sys\/',
            r'\/proc\/',
        ]
        
        return any(re.search(pattern, command) for pattern in elevated_patterns)
    
    @staticmethod
    def normalize_payload_type(payload_type: str) -> str:
        """
        Normalize payload type to standard name.
        
        Args:
            payload_type: Input payload type
            
        Returns:
            Normalized payload type
        """
        mapping = {
            'sh': 'bash',
            'python2': 'python',
            'python3': 'python',
            'py': 'python',
            'ps': 'powershell',
            'pwsh': 'powershell',
            'rb': 'ruby',
            'js': 'nodejs',
            'javascript': 'nodejs',
            'node': 'nodejs',
            'nc': 'netcat',
        }
        
        normalized = payload_type.lower()
        return mapping.get(normalized, normalized)
