"""
Terminal UI Dashboard for LearnShells
Real-time status display and monitoring
"""

import time
from typing import Dict, List, Optional
from datetime import datetime
from .colors import Colors


class TUIDashboard:
    """Terminal User Interface Dashboard"""
    
    def __init__(self):
        self.status_data = {
            'mode': 'Unknown',
            'listener': None,
            'shell_type': None,
            'target_ip': None,
            'target_port': None,
            'connection_status': 'Disconnected',
            'stability': 'Unstable',
            'start_time': None,
            'shells_caught': 0,
            'payloads_generated': 0,
        }
        
        self.log_buffer: List[str] = []
        self.max_logs = 10
    
    def update_status(self, **kwargs):
        """Update dashboard status"""
        self.status_data.update(kwargs)
    
    def add_log(self, message: str, level: str = 'INFO'):
        """Add log entry"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        color_map = {
            'INFO': Colors.INFO,
            'SUCCESS': Colors.SUCCESS,
            'ERROR': Colors.ERROR,
            'WARNING': Colors.WARNING,
        }
        
        color = color_map.get(level, Colors.INFO)
        log_entry = f"{Colors.DIM}[{timestamp}]{Colors.RESET} {color}{message}{Colors.RESET}"
        
        self.log_buffer.append(log_entry)
        if len(self.log_buffer) > self.max_logs:
            self.log_buffer.pop(0)
    
    def clear_screen(self):
        """Clear terminal screen"""
        print("\033[2J\033[H", end='')
    
    def render(self):
        """Render the dashboard"""
        self.clear_screen()
        
        # Header
        print(f"{Colors.BRIGHT_CYAN}{'='*80}")
        print(f"{Colors.BOLD}LearnShells Dashboard{Colors.RESET} {Colors.DIM}(Press Ctrl+C to exit){Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{'='*80}{Colors.RESET}\n")
        
        # Status Section
        self._render_status()
        print()
        
        # Connection Section
        self._render_connection()
        print()
        
        # Statistics Section
        self._render_statistics()
        print()
        
        # Logs Section
        self._render_logs()
        
        # Footer
        print(f"\n{Colors.BRIGHT_CYAN}{'='*80}{Colors.RESET}")
    
    def _render_status(self):
        """Render status section"""
        print(f"{Colors.BRIGHT_YELLOW}┌─ Status {'─'*68}┐{Colors.RESET}")
        
        mode = self.status_data['mode']
        mode_color = {
            'Learn': Colors.BRIGHT_GREEN,
            'Auto': Colors.BRIGHT_BLUE,
            'Butter': Colors.BRIGHT_YELLOW,
            'Expert': Colors.BRIGHT_MAGENTA,
        }.get(mode, Colors.WHITE)
        
        print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} Mode: {mode_color}{mode:<70}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        listener = self.status_data['listener'] or 'None'
        print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} Listener: {Colors.CYAN}{listener:<65}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        shell_type = self.status_data['shell_type'] or 'None'
        print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} Shell Type: {Colors.MAGENTA}{shell_type:<63}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        print(f"{Colors.BRIGHT_YELLOW}└{'─'*78}┘{Colors.RESET}")
    
    def _render_connection(self):
        """Render connection section"""
        print(f"{Colors.BRIGHT_YELLOW}┌─ Connection {'─'*64}┐{Colors.RESET}")
        
        status = self.status_data['connection_status']
        status_color = Colors.BRIGHT_GREEN if status == 'Connected' else Colors.BRIGHT_RED
        status_icon = '✓' if status == 'Connected' else '✗'
        
        print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} Status: {status_color}{status_icon} {status:<65}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        target_ip = self.status_data['target_ip'] or 'N/A'
        print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} Target IP: {Colors.CYAN}{target_ip:<63}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        target_port = self.status_data['target_port'] or 'N/A'
        print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} Target Port: {Colors.BLUE}{str(target_port):<61}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        stability = self.status_data['stability']
        stability_color = Colors.BRIGHT_GREEN if stability == 'Stable' else Colors.BRIGHT_YELLOW
        print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} Stability: {stability_color}{stability:<64}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        print(f"{Colors.BRIGHT_YELLOW}└{'─'*78}┘{Colors.RESET}")
    
    def _render_statistics(self):
        """Render statistics section"""
        print(f"{Colors.BRIGHT_YELLOW}┌─ Statistics {'─'*63}┐{Colors.RESET}")
        
        shells_caught = self.status_data['shells_caught']
        print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} Shells Caught: {Colors.BRIGHT_GREEN}{shells_caught:<58}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        payloads_generated = self.status_data['payloads_generated']
        print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} Payloads Generated: {Colors.BRIGHT_MAGENTA}{payloads_generated:<55}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        if self.status_data['start_time']:
            uptime = time.time() - self.status_data['start_time']
            uptime_str = self._format_uptime(uptime)
            print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} Uptime: {Colors.CYAN}{uptime_str:<66}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        print(f"{Colors.BRIGHT_YELLOW}└{'─'*78}┘{Colors.RESET}")
    
    def _render_logs(self):
        """Render logs section"""
        print(f"{Colors.BRIGHT_YELLOW}┌─ Activity Logs {'─'*60}┐{Colors.RESET}")
        
        if not self.log_buffer:
            print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} {Colors.DIM}No activity yet...{' '*58}{Colors.RESET} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        else:
            for log in self.log_buffer[-self.max_logs:]:
                # Truncate log if too long
                log_stripped = Colors.strip(log)
                if len(log_stripped) > 74:
                    log = log[:74] + "..."
                padding = 76 - len(Colors.strip(log))
                print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} {log}{' '*padding} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        print(f"{Colors.BRIGHT_YELLOW}└{'─'*78}┘{Colors.RESET}")
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human-readable format"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"
    
    def show_progress_bar(self, current: int, total: int, width: int = 50):
        """Display progress bar"""
        percent = current / total if total > 0 else 0
        filled = int(width * percent)
        bar = '█' * filled + '░' * (width - filled)
        
        print(f"\r{Colors.BRIGHT_CYAN}Progress: [{bar}] {percent*100:.1f}%{Colors.RESET}", end='', flush=True)
        
        if current >= total:
            print()  # New line when complete
    
    def show_spinner(self, message: str, duration: float = 0.5):
        """Display animated spinner"""
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        
        start = time.time()
        i = 0
        
        while time.time() - start < duration:
            print(f"\r{Colors.BRIGHT_CYAN}{spinner[i % len(spinner)]} {message}...{Colors.RESET}", end='', flush=True)
            time.sleep(0.1)
            i += 1
        
        print("\r" + " " * (len(message) + 10) + "\r", end='', flush=True)
    
    def show_table(self, headers: List[str], rows: List[List[str]], title: str = ""):
        """Display formatted table"""
        if not rows:
            print(f"{Colors.WARNING}No data to display{Colors.RESET}")
            return
        
        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Top border
        if title:
            print(f"\n{Colors.BRIGHT_CYAN}{title}{Colors.RESET}")
        
        print(f"{Colors.BRIGHT_YELLOW}┌", end='')
        for i, width in enumerate(col_widths):
            print('─' * (width + 2), end='')
            if i < len(col_widths) - 1:
                print('┬', end='')
        print(f"┐{Colors.RESET}")
        
        # Headers
        print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET}", end='')
        for i, (header, width) in enumerate(zip(headers, col_widths)):
            print(f" {Colors.BOLD}{header:<{width}}{Colors.RESET} ", end='')
            print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET}", end='')
        print()
        
        # Middle border
        print(f"{Colors.BRIGHT_YELLOW}├", end='')
        for i, width in enumerate(col_widths):
            print('─' * (width + 2), end='')
            if i < len(col_widths) - 1:
                print('┼', end='')
        print(f"┤{Colors.RESET}")
        
        # Rows
        for row in rows:
            print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET}", end='')
            for i, (cell, width) in enumerate(zip(row, col_widths)):
                print(f" {str(cell):<{width}} ", end='')
                print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET}", end='')
            print()
        
        # Bottom border
        print(f"{Colors.BRIGHT_YELLOW}└", end='')
        for i, width in enumerate(col_widths):
            print('─' * (width + 2), end='')
            if i < len(col_widths) - 1:
                print('┴', end='')
        print(f"┘{Colors.RESET}\n")
    
    def show_menu(self, title: str, options: List[str], selected: int = 0) -> int:
        """Display interactive menu (returns selected index)"""
        print(f"\n{Colors.BRIGHT_CYAN}{title}{Colors.RESET}\n")
        
        for i, option in enumerate(options):
            if i == selected:
                print(f"{Colors.BRIGHT_GREEN}▶ {option}{Colors.RESET}")
            else:
                print(f"  {option}")
        
        print(f"\n{Colors.DIM}Use arrow keys to navigate, Enter to select{Colors.RESET}")
        return selected
    
    def show_confirmation(self, message: str) -> bool:
        """Display confirmation prompt"""
        response = input(f"{Colors.BRIGHT_YELLOW}❓ {message} (y/n): {Colors.RESET}").lower()
        return response in ['y', 'yes']
    
    def show_input(self, prompt: str, default: str = "") -> str:
        """Display input prompt"""
        if default:
            prompt_text = f"{Colors.BRIGHT_CYAN}➤ {prompt} [{default}]: {Colors.RESET}"
        else:
            prompt_text = f"{Colors.BRIGHT_CYAN}➤ {prompt}: {Colors.RESET}"
        
        response = input(prompt_text)
        return response if response else default
    
    def show_multiline_box(self, title: str, content: List[str], width: int = 78):
        """Display content in a bordered box"""
        print(f"\n{Colors.BRIGHT_YELLOW}┌─ {title} {'─'*(width-len(title)-4)}┐{Colors.RESET}")
        
        for line in content:
            padding = width - len(Colors.strip(line)) - 2
            print(f"{Colors.BRIGHT_YELLOW}│{Colors.RESET} {line}{' '*padding} {Colors.BRIGHT_YELLOW}│{Colors.RESET}")
        
        print(f"{Colors.BRIGHT_YELLOW}└{'─'*width}┘{Colors.RESET}\n")
    
    def show_command_preview(self, command: str, description: str = ""):
        """Display command preview box"""
        print(f"\n{Colors.BRIGHT_MAGENTA}┌─ Command Preview {'─'*60}┐{Colors.RESET}")
        
        if description:
            print(f"{Colors.BRIGHT_MAGENTA}│{Colors.RESET} {Colors.DIM}{description}{Colors.RESET}")
            print(f"{Colors.BRIGHT_MAGENTA}│{Colors.RESET}")
        
        # Word wrap for long commands
        max_width = 76
        words = command.split()
        lines = []
        current_line = ""
        
        for word in words:
            if len(current_line) + len(word) + 1 <= max_width:
                current_line += word + " "
            else:
                lines.append(current_line.strip())
                current_line = word + " "
        
        if current_line:
            lines.append(current_line.strip())
        
        for line in lines:
            padding = 76 - len(line)
            print(f"{Colors.BRIGHT_MAGENTA}│{Colors.RESET} {Colors.CYAN}{line}{Colors.RESET}{' '*padding} {Colors.BRIGHT_MAGENTA}│{Colors.RESET}")
        
        print(f"{Colors.BRIGHT_MAGENTA}└{'─'*78}┘{Colors.RESET}\n")
    
    def animate_success(self):
        """Display success animation"""
        frames = [
            "●○○○○",
            "○●○○○",
            "○○●○○",
            "○○○●○",
            "○○○○●",
            "✓✓✓✓✓"
        ]
        
        for frame in frames:
            print(f"\r{Colors.BRIGHT_GREEN}{frame}{Colors.RESET}", end='', flush=True)
            time.sleep(0.1)
        
        print()
    
    def show_countdown(self, seconds: int, message: str = "Starting in"):
        """Display countdown timer"""
        for i in range(seconds, 0, -1):
            print(f"\r{Colors.BRIGHT_YELLOW}{message} {i}...{Colors.RESET}", end='', flush=True)
            time.sleep(1)
        
        print(f"\r{Colors.BRIGHT_GREEN}GO!{' '*20}{Colors.RESET}")
