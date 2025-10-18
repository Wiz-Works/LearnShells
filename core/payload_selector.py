"""
Intelligent payload selection based on target environment
"""

from typing import Dict, List, Optional, Tuple
from learnshells.utils.logger import Logger


class PayloadSelector:
    """Select optimal payload based on target characteristics."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize payload selector.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.payload_rankings = self._initialize_rankings()
    
    def _initialize_rankings(self) -> Dict:
        """Initialize payload rankings by OS and criteria."""
        return {
            'linux': {
                'reliability': ['python3', 'python', 'bash', 'sh', 'perl', 'nc'],
                'stealth': ['bash', 'sh', 'python3', 'perl', 'nc'],
                'speed': ['nc', 'bash', 'sh', 'python3'],
            },
            'windows': {
                'reliability': ['powershell', 'cmd', 'msfvenom'],
                'stealth': ['powershell', 'msfvenom', 'cmd'],
                'speed': ['cmd', 'powershell'],
            }
        }
    
    def select_payload_type(
        self,
        target_info: Dict,
        criteria: str = 'reliability'
    ) -> Tuple[str, str]:
        """
        Select best payload type for target.
        
        Args:
            target_info: Dict with target OS, tools, environment info
            criteria: Selection criteria (reliability, stealth, speed)
            
        Returns:
            Tuple of (payload_type, reason)
        """
        self.logger.info(f"Selecting optimal payload (criteria: {criteria})...")
        
        os_type = target_info.get('os', 'unknown').lower()
        available_tools = target_info.get('tools', [])
        technologies = target_info.get('technologies', [])
        web_context = target_info.get('web_context', False)
        
        # Windows targets
        if os_type == 'windows':
            return self._select_windows_payload(available_tools, criteria)
        
        # Linux targets
        elif os_type == 'linux':
            return self._select_linux_payload(available_tools, technologies, criteria)
        
        # Unknown OS - try to infer from context
        else:
            return self._select_unknown_os_payload(technologies, web_context)
    
    def _select_linux_payload(
        self,
        available_tools: List[str],
        technologies: List[str],
        criteria: str
    ) -> Tuple[str, str]:
        """Select best payload for Linux target."""
        
        # Get preference order based on criteria
        preferences = self.payload_rankings['linux'].get(criteria, 
                                                         self.payload_rankings['linux']['reliability'])
        
        # Check available tools in order of preference
        for tool in preferences:
            if tool in available_tools:
                reason = self._get_payload_reason('linux', tool, criteria)
                self.logger.success(
                    f"Selected {tool.upper()} payload",
                    explain=reason
                )
                return tool, reason
        
        # If PHP web context and no tools found
        if any('php' in str(t).lower() for t in technologies):
            reason = "PHP detected in web context - using PHP web shell"
            self.logger.success("Selected PHP payload", explain=reason)
            return 'php', reason
        
        # Default to bash (most universal)
        reason = "No specific tools detected, using bash (most common shell)"
        self.logger.warning("Defaulting to bash payload", explain=reason)
        return 'bash', reason
    
    def _select_windows_payload(
        self,
        available_tools: List[str],
        criteria: str
    ) -> Tuple[str, str]:
        """Select best payload for Windows target."""
        
        preferences = self.payload_rankings['windows'].get(criteria,
                                                           self.payload_rankings['windows']['reliability'])
        
        for tool in preferences:
            if tool in available_tools or tool == 'powershell':  # PowerShell usually available
                reason = self._get_payload_reason('windows', tool, criteria)
                self.logger.success(
                    f"Selected {tool.upper()} payload",
                    explain=reason
                )
                return tool, reason
        
        # Default to PowerShell (available on all modern Windows)
        reason = "PowerShell is available on all modern Windows systems"
        self.logger.info("Selected PowerShell payload", explain=reason)
        return 'powershell', reason
    
    def _select_unknown_os_payload(
        self,
        technologies: List[str],
        web_context: bool
    ) -> Tuple[str, str]:
        """Select payload when OS is unknown."""
        
        # Try to infer from technologies
        tech_lower = [str(t).lower() for t in technologies]
        
        if any('php' in t for t in tech_lower):
            reason = "PHP detected - using PHP payload"
            self.logger.info("Selected PHP payload (OS unknown)", explain=reason)
            return 'php', reason
        
        if any('asp' in t or '.net' in t for t in tech_lower):
            reason = "ASP.NET detected - likely Windows, using PowerShell"
            self.logger.info("Selected PowerShell payload (OS unknown)", explain=reason)
            return 'powershell', reason
        
        if any('node' in t or 'express' in t or 'javascript' in t for t in tech_lower):
            reason = "Node.js detected - using Node.js payload"
            self.logger.info("Selected Node.js payload (OS unknown)", explain=reason)
            return 'nodejs', reason
        
        if any('jsp' in t or 'java' in t for t in tech_lower):
            reason = "Java/JSP detected - using Java payload"
            self.logger.info("Selected Java payload (OS unknown)", explain=reason)
            return 'java', reason
        
        # Default to bash (most common)
        reason = "OS unknown, defaulting to bash (most universal)"
        self.logger.warning("Selected bash payload (OS unknown)", explain=reason)
        return 'bash', reason
    
    def _get_payload_reason(self, os_type: str, payload_type: str, criteria: str) -> str:
        """Get explanation for why a payload was selected."""
        
        reasons = {
            'linux': {
                'python3': {
                    'reliability': "Python 3 is very reliable, handles errors well, and creates stable connections.",
                    'stealth': "Python 3 is common on Linux systems and won't raise suspicion.",
                    'speed': "Python 3 provides good balance of speed and reliability."
                },
                'python': {
                    'reliability': "Python 2 is reliable but less common on newer systems.",
                    'stealth': "Python is a standard system tool and looks legitimate.",
                    'speed': "Python provides good performance for reverse shells."
                },
                'bash': {
                    'reliability': "Bash is available on virtually all Linux systems and very stable.",
                    'stealth': "Bash is the most common shell and won't trigger alerts.",
                    'speed': "Bash is extremely fast with minimal overhead."
                },
                'sh': {
                    'reliability': "POSIX shell is universal but has fewer features than bash.",
                    'stealth': "Shell scripts are normal on any Unix system.",
                    'speed': "Shell is very lightweight and fast."
                },
                'perl': {
                    'reliability': "Perl is reliable but less common on modern systems.",
                    'stealth': "Perl is a standard scripting language on Linux.",
                    'speed': "Perl is fast for scripting tasks."
                },
                'nc': {
                    'reliability': "Netcat is very reliable when available, but syntax varies.",
                    'stealth': "Netcat is a network tool that may or may not be installed.",
                    'speed': "Netcat is the fastest option - direct TCP connection."
                },
                'php': {
                    'reliability': "PHP is reliable in web contexts where it's available.",
                    'stealth': "PHP is normal for web applications.",
                    'speed': "PHP provides good performance for web-based shells."
                }
            },
            'windows': {
                'powershell': {
                    'reliability': "PowerShell is the most powerful and reliable option for Windows.",
                    'stealth': "PowerShell is a legitimate Windows administration tool.",
                    'speed': "PowerShell provides good performance and features."
                },
                'cmd': {
                    'reliability': "CMD is reliable but limited in functionality.",
                    'stealth': "CMD is a standard Windows component.",
                    'speed': "CMD is lightweight and fast for simple tasks."
                },
                'msfvenom': {
                    'reliability': "Metasploit payloads are very reliable and feature-rich.",
                    'stealth': "Binary payloads may trigger antivirus detection.",
                    'speed': "Compiled payloads are fast and efficient."
                }
            }
        }
        
        default_reason = f"{payload_type} selected based on {criteria} criteria"
        
        return reasons.get(os_type, {}).get(payload_type, {}).get(criteria, default_reason)
    
    def recommend_alternatives(
        self,
        target_info: Dict,
        primary_payload: str
    ) -> List[Tuple[str, str]]:
        """
        Recommend alternative payloads if primary fails.
        
        Args:
            target_info: Target information
            primary_payload: Primary payload that failed
            
        Returns:
            List of (payload_type, reason) tuples
        """
        os_type = target_info.get('os', 'unknown').lower()
        available_tools = target_info.get('tools', [])
        
        alternatives = []
        
        if os_type == 'linux':
            # Get all Linux payloads except the primary
            all_payloads = self.payload_rankings['linux']['reliability']
            for payload in all_payloads:
                if payload != primary_payload and payload in available_tools:
                    reason = f"Alternative to {primary_payload}"
                    alternatives.append((payload, reason))
        
        elif os_type == 'windows':
            all_payloads = self.payload_rankings['windows']['reliability']
            for payload in all_payloads:
                if payload != primary_payload:
                    reason = f"Alternative to {primary_payload}"
                    alternatives.append((payload, reason))
        
        return alternatives[:3]  # Return top 3 alternatives
    
    def get_payload_requirements(self, payload_type: str) -> Dict[str, any]:
        """
        Get requirements for a specific payload type.
        
        Args:
            payload_type: Type of payload
            
        Returns:
            Dict with requirements
        """
        requirements = {
            'python3': {
                'tool': 'python3',
                'command': 'python3',
                'min_version': '3.6',
                'common_paths': ['/usr/bin/python3', '/usr/local/bin/python3'],
                'test_command': 'python3 --version'
            },
            'python': {
                'tool': 'python',
                'command': 'python',
                'min_version': '2.7',
                'common_paths': ['/usr/bin/python', '/usr/local/bin/python'],
                'test_command': 'python --version'
            },
            'bash': {
                'tool': 'bash',
                'command': 'bash',
                'min_version': '4.0',
                'common_paths': ['/bin/bash', '/usr/bin/bash'],
                'test_command': 'bash --version'
            },
            'php': {
                'tool': 'php',
                'command': 'php',
                'min_version': '5.3',
                'common_paths': ['/usr/bin/php', '/usr/local/bin/php'],
                'test_command': 'php --version'
            },
            'powershell': {
                'tool': 'powershell',
                'command': 'powershell.exe',
                'min_version': '3.0',
                'common_paths': ['C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'],
                'test_command': 'powershell.exe -Command $PSVersionTable'
            },
            'nc': {
                'tool': 'nc',
                'command': 'nc',
                'min_version': 'any',
                'common_paths': ['/bin/nc', '/usr/bin/nc', '/usr/local/bin/nc'],
                'test_command': 'nc -h'
            }
        }
        
        return requirements.get(payload_type, {})
    
    def compare_payloads(self, os_type: str) -> None:
        """
        Display comparison of available payloads for OS.
        
        Args:
            os_type: Operating system type
        """
        self.logger.header(f"Payload Comparison for {os_type.upper()}")
        
        comparisons = {
            'linux': [
                {
                    'payload': 'Python3',
                    'reliability': '⭐⭐⭐⭐⭐',
                    'stealth': '⭐⭐⭐⭐',
                    'ease': '⭐⭐⭐⭐⭐',
                    'notes': 'Best overall choice'
                },
                {
                    'payload': 'Bash',
                    'reliability': '⭐⭐⭐⭐⭐',
                    'stealth': '⭐⭐⭐⭐⭐',
                    'ease': '⭐⭐⭐⭐',
                    'notes': 'Universal, very stealthy'
                },
                {
                    'payload': 'Netcat',
                    'reliability': '⭐⭐⭐⭐',
                    'stealth': '⭐⭐⭐',
                    'ease': '⭐⭐⭐⭐⭐',
                    'notes': 'Fast but often missing'
                },
                {
                    'payload': 'PHP',
                    'reliability': '⭐⭐⭐⭐',
                    'stealth': '⭐⭐⭐⭐',
                    'ease': '⭐⭐⭐⭐',
                    'notes': 'Good for web contexts'
                },
            ],
            'windows': [
                {
                    'payload': 'PowerShell',
                    'reliability': '⭐⭐⭐⭐⭐',
                    'stealth': '⭐⭐⭐',
                    'ease': '⭐⭐⭐⭐',
                    'notes': 'Most powerful, may trigger AV'
                },
                {
                    'payload': 'CMD',
                    'reliability': '⭐⭐⭐',
                    'stealth': '⭐⭐⭐⭐',
                    'ease': '⭐⭐⭐',
                    'notes': 'Limited but stealthy'
                },
            ]
        }
        
        data = comparisons.get(os_type.lower(), [])
        
        if data:
            headers = ['Payload', 'Reliability', 'Stealth', 'Ease of Use', 'Notes']
            rows = [[d['payload'], d['reliability'], d['stealth'], d['ease'], d['notes']] for d in data]
            self.logger.table(headers, rows)
        else:
            self.logger.warning(f"No comparison data for {os_type}")
