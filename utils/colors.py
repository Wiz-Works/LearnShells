"""
Color definitions and utilities for terminal output
"""

class Colors:
    """ANSI color codes for terminal output"""

    # Basic colors
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'

    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # GRAY color (bright black)
    GRAY = '\033[90m'

    # Bright foreground colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # Custom color schemes
    SUCCESS = BRIGHT_GREEN
    ERROR = BRIGHT_RED
    WARNING = BRIGHT_YELLOW
    INFO = BRIGHT_CYAN
    DEBUG = BRIGHT_BLUE

    # LearnShells theme
    LOGO = BRIGHT_CYAN
    SHELL = BRIGHT_GREEN
    COMMAND = BRIGHT_YELLOW
    IP = BRIGHT_MAGENTA
    PORT = BRIGHT_BLUE
    
    @staticmethod
    def header(text: str) -> str:
        """Format text as header"""
        return f"\n{Colors.BRIGHT_BLUE}{Colors.BOLD}{text}{Colors.RESET}\n"
    
    @staticmethod
    def subheader(text: str) -> str:
        """Format text as subheader"""
        return f"\n{Colors.BRIGHT_CYAN}{text}{Colors.RESET}\n"
    
    @staticmethod
    def loading(text: str) -> str:
        """Format text as loading message"""
        return f"{Colors.WARNING}{text}...{Colors.RESET}"

    @staticmethod
    def strip(text: str) -> str:
        """Remove all ANSI color codes from text"""
        import re
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', text)

    @staticmethod
    def colorize(text: str, color: str) -> str:
        """Wrap text in color codes"""
        return f"{color}{text}{Colors.RESET}"

    @staticmethod
    def success(text: str) -> str:
        """Format text as success message"""
        return f"{Colors.SUCCESS}✓ {text}{Colors.RESET}"

    @staticmethod
    def error(text: str) -> str:
        """Format text as error message"""
        return f"{Colors.ERROR}✗ {text}{Colors.RESET}"

    @staticmethod
    def warning(text: str) -> str:
        """Format text as warning message"""
        return f"{Colors.WARNING}⚠ {text}{Colors.RESET}"

    @staticmethod
    def info(text: str) -> str:
        """Format text as info message"""
        return f"{Colors.INFO}ℹ {text}{Colors.RESET}"

    @staticmethod
    def highlight(text: str) -> str:
        """Highlight important text"""
        return f"{Colors.BOLD}{Colors.BRIGHT_YELLOW}{text}{Colors.RESET}"

    @staticmethod
    def code(text: str) -> str:
        """Format text as code"""
        return f"{Colors.DIM}{Colors.CYAN}{text}{Colors.RESET}"

    @staticmethod
    def dim(text: str) -> str:
        """Dim text for less important info"""
        return f"{Colors.DIM}{text}{Colors.RESET}"
    
    @staticmethod
    def progress_bar(current: int, total: int, width: int = 50) -> str:
        """Create a progress bar"""
        percent = current / total if total > 0 else 0
        filled = int(width * percent)
        bar = '█' * filled + '░' * (width - filled)
        return f"{Colors.BRIGHT_CYAN}[{bar}] {percent*100:.1f}%{Colors.RESET}"
    
    @staticmethod
    def box(message: str, width: int = 60) -> str:
        """Create a box around message"""
        lines = message.split('\n')
        bordered = []
        bordered.append(f"{Colors.BRIGHT_CYAN}┌{'─' * (width - 2)}┐{Colors.RESET}")
        for line in lines:
            padding = width - len(line) - 4
            bordered.append(f"{Colors.BRIGHT_CYAN}│{Colors.RESET} {line}{' ' * padding} {Colors.BRIGHT_CYAN}│{Colors.RESET}")
        bordered.append(f"{Colors.BRIGHT_CYAN}└{'─' * (width - 2)}┘{Colors.RESET}")
        return '\n'.join(bordered)

    @classmethod
    def strip_colors(cls, text: str) -> str:
        """Strip color codes from text"""
        return cls.strip(text)


# Gradient colors for fancy output
GRADIENT_BLUE_CYAN = [
    '\033[38;5;33m',   # Blue
    '\033[38;5;39m',   # Lighter Blue
    '\033[38;5;45m',   # Cyan-Blue
    '\033[38;5;51m',   # Cyan
]

GRADIENT_GREEN_YELLOW = [
    '\033[38;5;34m',   # Green
    '\033[38;5;40m',   # Lighter Green
    '\033[38;5;46m',   # Yellow-Green
    '\033[38;5;226m',  # Yellow
]

GRADIENT_PURPLE_PINK = [
    '\033[38;5;93m',   # Purple
    '\033[38;5;99m',   # Lighter Purple
    '\033[38;5;141m',  # Pink-Purple
    '\033[38;5;213m',  # Pink
]


def apply_gradient(text: str, gradient: list) -> str:
    """Apply gradient colors to text"""
    if not text:
        return text
    result = []
    grad_len = len(gradient)
    text_len = len(text)
    for i, char in enumerate(text):
        if char == '\n':
            result.append(char)
        else:
            color_idx = int((i / text_len) * grad_len)
            color_idx = min(color_idx, grad_len - 1)
            result.append(f"{gradient[color_idx]}{char}")
    result.append(Colors.RESET)
    return ''.join(result)


def rainbow_text(text: str) -> str:
    """Apply rainbow colors to text"""
    colors = [
        '\033[38;5;196m',  # Red
        '\033[38;5;208m',  # Orange
        '\033[38;5;226m',  # Yellow
        '\033[38;5;46m',   # Green
        '\033[38;5;21m',   # Blue
        '\033[38;5;93m',   # Purple
    ]
    result = []
    for i, char in enumerate(text):
        if char == '\n':
            result.append(char)
        else:
            result.append(f"{colors[i % len(colors)]}{char}")
    result.append(Colors.RESET)
    return ''.join(result)
