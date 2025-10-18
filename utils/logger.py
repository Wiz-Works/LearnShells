"""
Logging utilities for LearnShells (No Icons)
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List
from learnshells.ui.colors import Colors


class Logger:
    """Custom logger with colored output, educational mode, and file logging. No icons used."""
    
    def __init__(
        self,
        name: str = "learnshells",
        log_file: Optional[str] = None,
        level: int = logging.INFO,
        verbose: bool = False,
        educational: bool = True
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if verbose else level)
        self.verbose = verbose
        self.educational = educational
        self.log_file = log_file
        
        self.logger.handlers.clear()
        
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if verbose else level)
        console_handler.setFormatter(ColoredFormatter())
        self.logger.addHandler(console_handler)
        
        if log_file:
            self._add_file_handler(log_file)
    
    def _add_file_handler(self, log_file: str):
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        self.logger.addHandler(file_handler)
    
    # ========== Basic Logging Methods ==========
    
    def success(self, message: str, explain: str = None):
        print(Colors.success(message))
        if explain and self.educational:
            self._explain(explain)
        self.logger.info(Colors.strip_colors(message))
    
    def error(self, message: str, explain: str = None):
        print(Colors.error(message))
        if explain and self.educational:
            self._explain(explain)
        self.logger.error(Colors.strip_colors(message))
    
    def warning(self, message: str, explain: str = None):
        print(Colors.warning(message))
        if explain and self.educational:
            self._explain(explain)
        self.logger.warning(Colors.strip_colors(message))
    
    def info(self, message: str, explain: str = None):
        print(Colors.info(message))
        if explain and self.educational:
            self._explain(explain)
        self.logger.info(Colors.strip_colors(message))
    
    def debug(self, message: str):
        if self.verbose:
            print(Colors.debug(message))
        self.logger.debug(Colors.strip_colors(message))
    
    # ========== Formatting Methods ==========
    
    def header(self, message: str):
        print(Colors.header(message))
    
    def subheader(self, message: str):
        print(Colors.subheader(message))
    
    def separator(self, char: str = "─", width: int = 60):
        print(f"{Colors.GRAY}{char * width}{Colors.RESET}")
    
    def banner(self, text: str):
        print(f"{Colors.BRIGHT_CYAN}{text}{Colors.RESET}")
    
    # ========== Educational Methods ==========
    
    def _explain(self, explanation: str):
        print(f"\n{Colors.CYAN}{Colors.BOLD}Why?{Colors.RESET}")
        print(f"{Colors.GRAY}{explanation}{Colors.RESET}\n")
    
    def educational_note(self, title: str, content: str):
        print(f"\n{Colors.BRIGHT_CYAN}╔══ {title} ══╗{Colors.RESET}")
        for line in content.split('\n'):
            print(f"{Colors.CYAN}║{Colors.RESET} {line}")
        print(f"{Colors.BRIGHT_CYAN}╚{'═' * (len(title) + 6)}╝{Colors.RESET}\n")
    
    def tip(self, message: str):
        print(f"{Colors.YELLOW}TIP:{Colors.RESET} {message}")
    
    def concept(self, title: str, explanation: str):
        print(f"\n{Colors.BOLD}{Colors.BRIGHT_CYAN}{title.upper()}{Colors.RESET}")
        print(f"{Colors.GRAY}{explanation}{Colors.RESET}\n")
    
    # ========== Progress and Status Methods ==========
    
    def step(self, step_num: int, total_steps: int, message: str):
        prefix = f"[{step_num}/{total_steps}]"
        print(f"{Colors.CYAN}{prefix}{Colors.RESET} {message}")
    
    def status(self, message: str, status: str = "working"):
        status_map = {
            "working": f"{Colors.YELLOW}[WORKING]{Colors.RESET}",
            "success": f"{Colors.GREEN}[SUCCESS]{Colors.RESET}",
            "error": f"{Colors.RED}[ERROR]{Colors.RESET}",
            "warning": f"{Colors.YELLOW}[WARNING]{Colors.RESET}",
            "info": f"{Colors.CYAN}[INFO]{Colors.RESET}"
        }
        tag = status_map.get(status, "")
        print(f"  {tag} {message}")
    
    def progress(self, current: int, total: int, message: str = ""):
        bar = Colors.progress_bar(current, total)
        print(f"\r{bar} {message}", end="", flush=True)
        if current == total:
            print()
    
    def loading(self, message: str):
        """Display loading message"""
        print(Colors.loading(message))
        
    # ========== List and Structure Methods ==========
    
    def list_item(self, message: str, indent: int = 0):
        spaces = "  " * indent
        print(f"{spaces}- {message}")
    
    def numbered_item(self, number: int, message: str, indent: int = 0):
        spaces = "  " * indent
        print(f"{spaces}{Colors.CYAN}{number}.{Colors.RESET} {message}")
    
    def box(self, message: str, width: int = 60):
        print(Colors.box(message, width))
    
    def table(self, headers: List[str], rows: List[List]):
        if not rows:
            return
        col_widths = [len(str(h)) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))
        header_str = " │ ".join(
            f"{str(h):<{w}}" for h, w in zip(headers, col_widths)
        )
        print(f"{Colors.BOLD}{header_str}{Colors.RESET}")
        sep = "─┼─".join("─" * w for w in col_widths)
        print(f"{Colors.GRAY}{sep}{Colors.RESET}")
        for row in rows:
            row_str = " │ ".join(
                f"{str(cell):<{w}}" for cell, w in zip(row, col_widths)
            )
            print(row_str)
    
    # ========== Code Display Methods ==========
    
    def code_block(self, code: str, language: str = ""):
        print(f"\n{Colors.GRAY}```{language}")
        print(f"{Colors.WHITE}{code}{Colors.RESET}")
        print(f"{Colors.GRAY}```{Colors.RESET}\n")
    
    def command(self, cmd: str):
        print(f"{Colors.CYAN}$ {Colors.WHITE}{cmd}{Colors.RESET}")
    
    def output(self, text: str):
        print(f"{Colors.GRAY}{text}{Colors.RESET}")
    
    # ========== Interactive Methods ==========
    
    def ask(self, question: str, choices: List[str] = None) -> str:
        print(f"\n{Colors.YELLOW}{question}{Colors.RESET}")
        if choices:
            for i, choice in enumerate(choices, 1):
                print(f"  {Colors.CYAN}{i}.{Colors.RESET} {choice}")
        response = input(f"\n{Colors.BRIGHT_CYAN}Your choice: {Colors.RESET}")
        return response.strip()
    
    def confirm(self, message: str, default: bool = True) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        response = input(f"{Colors.YELLOW}{message} {suffix}:{Colors.RESET} ").strip().lower()
        if not response:
            return default
        return response in ['y', 'yes']
    
    def prompt(self, message: str, default: str = "") -> str:
        prompt_text = f"{Colors.CYAN}{message}{Colors.RESET}"
        if default:
            prompt_text += f" {Colors.GRAY}[{default}]{Colors.RESET}"
        prompt_text += ": "
        response = input(prompt_text).strip()
        return response if response else default
    
    # ========== Special Display Methods ==========
    
    def payload_display(self, payload: str, payload_type: str):
        self.subheader(f"{payload_type.upper()} Payload")
        print(f"{Colors.GRAY}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.WHITE}{payload}{Colors.RESET}")
        print(f"{Colors.GRAY}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.GRAY}Length: {len(payload)} bytes{Colors.RESET}\n")
    
    def target_info(self, info: dict):
        self.header("Target Information")
        for key, value in info.items():
            key_formatted = key.replace('_', ' ').title()
            if isinstance(value, list):
                value_str = ', '.join(str(v) for v in value)
            else:
                value_str = str(value)
            print(f"{Colors.CYAN}{key_formatted}:{Colors.RESET} {value_str}")
        print()
    
    def listener_info(self, ip: str, port: int, listener_type: str = "netcat"):
        self.box(f"Listener Active\n\nIP: {ip}\nPort: {port}\nType: {listener_type}", width=50)
    
    def vulnerability_found(self, vuln_type: str, details: str):
        print(f"\n{Colors.BRIGHT_RED}VULNERABILITY FOUND!{Colors.RESET}")
        print(f"{Colors.RED}Type:{Colors.RESET} {vuln_type}")
        print(f"{Colors.RED}Details:{Colors.RESET} {details}\n")
    
    def shell_connected(self, target_ip: str, user: str = None):
        print(f"\n{Colors.BRIGHT_GREEN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BRIGHT_GREEN}SHELL CONNECTED!{Colors.RESET}")
        print(f"{Colors.GREEN}Target:{Colors.RESET} {target_ip}")
        if user:
            print(f"{Colors.GREEN}User:{Colors.RESET} {user}")
        print(f"{Colors.BRIGHT_GREEN}{'='*60}{Colors.RESET}\n")
    
    # ========== Summary and Report Methods ==========
    
    def summary(self, title: str, items: dict):
        self.subheader(title)
        max_key_len = max(len(k) for k in items.keys())
        for key, value in items.items():
            key_padded = key.ljust(max_key_len)
            if isinstance(value, bool):
                value_str = f"{Colors.GREEN}YES{Colors.RESET}" if value else f"{Colors.RED}NO{Colors.RESET}"
            else:
                value_str = str(value)
            print(f"  {Colors.CYAN}{key_padded}:{Colors.RESET} {value_str}")
        print()
    
    def checklist(self, items: List[tuple]):
        for item, status in items:
            tag = f"{Colors.GREEN}DONE{Colors.RESET}" if status else f"{Colors.RED}TODO{Colors.RESET}"
            print(f"  {tag} {item}")
        print()
    
    def results(self, success: bool, message: str):
        if success:
            print(f"\n{Colors.BRIGHT_GREEN}{'='*60}{Colors.RESET}")
            print(f"{Colors.BRIGHT_GREEN}SUCCESS{Colors.RESET}")
            print(f"{Colors.GREEN}{message}{Colors.RESET}")
            print(f"{Colors.BRIGHT_GREEN}{'='*60}{Colors.RESET}\n")
        else:
            print(f"\n{Colors.BRIGHT_RED}{'='*60}{Colors.RESET}")
            print(f"{Colors.BRIGHT_RED}FAILED{Colors.RESET}")
            print(f"{Colors.RED}{message}{Colors.RESET}")
            print(f"{Colors.BRIGHT_RED}{'='*60}{Colors.RESET}\n")
    
    # ========== Utility Methods ==========
    
    def clear_line(self):
        print('\r' + ' ' * 80 + '\r', end='', flush=True)
    
    def newline(self, count: int = 1):
        print('\n' * count, end='')
    
    def print(self, message: str):
        print(message)
    
    def set_educational_mode(self, enabled: bool):
        self.educational = enabled
        if enabled:
            self.info("Educational mode enabled - explanations will be shown")
        else:
            self.info("Educational mode disabled - showing concise output only")
    
    def set_verbose_mode(self, enabled: bool):
        self.verbose = enabled
        if enabled:
            self.logger.setLevel(logging.DEBUG)
            self.debug("Verbose mode enabled - showing debug output")
        else:
            self.logger.setLevel(logging.INFO)
    
    # ========== File Logging Methods ==========
    
    def log_to_file(self, message: str, level: str = "info"):
        if level == "debug":
            self.logger.debug(message)
        elif level == "info":
            self.logger.info(message)
        elif level == "warning":
            self.logger.warning(message)
        elif level == "error":
            self.logger.error(message)
    
    def get_log_file_path(self) -> Optional[str]:
        return self.log_file


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels."""
    
    FORMATS = {
        logging.DEBUG: Colors.DEBUG + "%(message)s" + Colors.RESET,
        logging.INFO: Colors.INFO + "%(message)s" + Colors.RESET,
        logging.WARNING: Colors.WARNING + "%(message)s" + Colors.RESET,
        logging.ERROR: Colors.ERROR + "%(message)s" + Colors.RESET,
        logging.CRITICAL: Colors.BRIGHT_RED + "%(message)s" + Colors.RESET,
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def get_logger(
    name: str = "learnshells",
    verbose: bool = False,
    educational: bool = True,
    log_file: Optional[str] = None
) -> Logger:
    return Logger(
        name=name,
        verbose=verbose,
        educational=educational,
        log_file=log_file
    )
