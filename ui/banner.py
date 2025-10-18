"""
Banner and ASCII art for LearnShells
"""

from .colors import Colors, apply_gradient, GRADIENT_BLUE_CYAN


class Banner:
    """Display banners and ASCII art"""
    
    MAIN_LOGO = r"""
    ╦  ┌─┐┌─┐┬─┐┌┐┌╔═╗┬ ┬┌─┐┬  ┬  ┌─┐
    ║  ├┤ ├─┤├┬┘│││╚═╗├─┤├┤ │  │  └─┐
    ╩═╝└─┘┴ ┴┴└─┘└┘╚═╝┴ ┴└─┘┴─┘┴─┘└─┘
    """
    
    SMALL_LOGO = r"""
    ╦  ┌─┐┌─┐┬─┐┌┐┌╔═╗┬ ┬┌─┐┬  ┬  ┌─┐
    ║  ├┤ ├─┤├┬┘│││╚═╗├─┤├┤ │  │  └─┐
    ╩═╝└─┘┴ ┴┴└─┘└┘╚═╝┴ ┴└─┘┴─┘┴─┘└─┘
    """
    
    SHELL_ART = r"""
         _______________
        /              /|
       /              / |
      /______________/  |
      |  _________  |  |
      | |  $> _   | |  /
      | |_________| | /
      |_____________|/
    """
    
    @staticmethod
    def show_main(version: str = "1.0.0"):
        """Display main banner with version"""
        logo = apply_gradient(Banner.MAIN_LOGO, GRADIENT_BLUE_CYAN)
        print(logo)
        print(f"{Colors.DIM}    Interactive Reverse Shell Education & Automation{Colors.RESET}")
        print(f"{Colors.DIM}    Version {version} | For Educational Use Only{Colors.RESET}\n")
    
    @staticmethod
    def show_mode(mode: str):
        """Display mode banner"""
        mode_banners = {
            'learn': f"""
    {Colors.BRIGHT_GREEN}┌────────────────────────────────────┐
    │     📚  LEARN MODE ACTIVATED  📚   │
    │  Step-by-step shell education!    │
    └────────────────────────────────────┘{Colors.RESET}
            """,
            'auto': f"""
    {Colors.BRIGHT_BLUE}┌────────────────────────────────────┐
    │     ⚡  AUTO MODE ACTIVATED  ⚡    │
    │   Automated shell deployment!     │
    └────────────────────────────────────┘{Colors.RESET}
            """,
            'butter': f"""
    {Colors.BRIGHT_YELLOW}┌────────────────────────────────────┐
    │    🧈  BUTTER MODE ACTIVATED  🧈   │
    │     Smooth as butter, baby!       │
    └────────────────────────────────────┘{Colors.RESET}
            """,
            'expert': f"""
    {Colors.BRIGHT_MAGENTA}┌────────────────────────────────────┐
    │    🔧  EXPERT MODE ACTIVATED  🔧   │
    │      Full manual control!         │
    └────────────────────────────────────┘{Colors.RESET}
            """
        }
        
        print(mode_banners.get(mode.lower(), ""))
    
    @staticmethod
    def show_success(message: str):
        """Display success banner"""
        print(f"\n{Colors.SUCCESS}{'='*50}")
        print(f"{Colors.SUCCESS}  ✓ SUCCESS!")
        print(f"{Colors.SUCCESS}  {message}")
        print(f"{Colors.SUCCESS}{'='*50}{Colors.RESET}\n")
    
    @staticmethod
    def show_error(message: str):
        """Display error banner"""
        print(f"\n{Colors.ERROR}{'='*50}")
        print(f"{Colors.ERROR}  ✗ ERROR!")
        print(f"{Colors.ERROR}  {message}")
        print(f"{Colors.ERROR}{'='*50}{Colors.RESET}\n")
    
    @staticmethod
    def show_warning(message: str):
        """Display warning banner"""
        print(f"\n{Colors.WARNING}{'='*50}")
        print(f"{Colors.WARNING}  ⚠ WARNING!")
        print(f"{Colors.WARNING}  {message}")
        print(f"{Colors.WARNING}{'='*50}{Colors.RESET}\n")
    
    @staticmethod
    def show_shell_caught():
        """Display shell caught animation"""
        print(f"\n{Colors.BRIGHT_GREEN}")
        print(r"""
        ╔═══════════════════════════════════╗
        ║   🎣  SHELL CAUGHT!  🎣          ║
        ║                                   ║
        ║     Connection established!       ║
        ╚═══════════════════════════════════╝
        """)
        print(Colors.RESET)
    
    @staticmethod
    def show_listener_started(listener_type: str, port: int):
        """Display listener started banner"""
        print(f"\n{Colors.BRIGHT_CYAN}")
        print(f"┌{'─'*50}┐")
        print(f"│  🎧  Listener Started: {listener_type.upper():<25} │")
        print(f"│  📡  Port: {port:<36} │")
        print(f"│  ⏳  Waiting for connection...{' '*19}│")
        print(f"└{'─'*50}┘")
        print(Colors.RESET)
    
    @staticmethod
    def show_payload_generated(shell_type: str):
        """Display payload generated banner"""
        print(f"\n{Colors.BRIGHT_MAGENTA}")
        print(f"┌{'─'*50}┐")
        print(f"│  🔨  Payload Generated: {shell_type.upper():<24} │")
        print(f"│  📋  Copied to clipboard!{' '*23}│")
        print(f"└{'─'*50}┘")
        print(Colors.RESET)
    
    @staticmethod
    def show_stability_upgrade():
        """Display TTY stability upgrade banner"""
        print(f"\n{Colors.BRIGHT_GREEN}")
        print(r"""
        ╔═══════════════════════════════════╗
        ║   🛠️  Shell Stabilized!  🛠️       ║
        ║                                   ║
        ║   Full TTY with tab completion!   ║
        ╚═══════════════════════════════════╝
        """)
        print(Colors.RESET)
    
    @staticmethod
    def show_help_menu():
        """Display help menu"""
        print(f"\n{Colors.BRIGHT_CYAN}{'='*60}")
        print(f"{Colors.BOLD}LearnShells - Command Reference{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{'='*60}{Colors.RESET}\n")
        
        commands = [
            ("learn", "Educational mode with step-by-step guidance"),
            ("auto", "Automated mode with smart detection"),
            ("butter", "Maximum automation, zero effort"),
            ("expert", "Full manual control for experts"),
            ("generate", "Generate a reverse shell payload"),
            ("listen", "Start a reverse shell listener"),
            ("stabilize", "Upgrade shell to full TTY"),
            ("detect", "Detect target OS and environment"),
            ("--help", "Show this help message"),
        ]
        
        for cmd, desc in commands:
            print(f"  {Colors.BRIGHT_YELLOW}{cmd:<12}{Colors.RESET} {desc}")
        
        print(f"\n{Colors.DIM}For detailed usage: learnshells <command> --help{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{'='*60}{Colors.RESET}\n")
    
    @staticmethod
    def show_credits():
        """Display credits"""
        print(f"\n{Colors.BRIGHT_CYAN}")
        print(r"""
        ╔═══════════════════════════════════════════════════════╗
        ║                    LearnShells                        ║
        ║                                                       ║
        ║  Created for educational purposes                     ║
        ║  Use responsibly and legally                          ║
        ║                                                       ║
        ║  Perfect for: HTB, THM, CTFs, & Learning!            ║
        ╚═══════════════════════════════════════════════════════╝
        """)
        print(Colors.RESET)
    
    @staticmethod
    def show_quick_start():
        """Display quick start guide"""
        print(f"\n{Colors.BRIGHT_GREEN}{'='*60}")
        print(f"{Colors.BOLD}Quick Start Guide{Colors.RESET}")
        print(f"{Colors.BRIGHT_GREEN}{'='*60}{Colors.RESET}\n")
        
        print(f"{Colors.BRIGHT_YELLOW}1. First time user?{Colors.RESET}")
        print(f"   {Colors.CYAN}learnshells learn{Colors.RESET}")
        print(f"   {Colors.DIM}↳ Interactive tutorial mode{Colors.RESET}\n")
        
        print(f"{Colors.BRIGHT_YELLOW}2. Quick exploitation?{Colors.RESET}")
        print(f"   {Colors.CYAN}learnshells auto{Colors.RESET}")
        print(f"   {Colors.DIM}↳ Automated detection & deployment{Colors.RESET}\n")
        
        print(f"{Colors.BRIGHT_YELLOW}3. Feeling lazy?{Colors.RESET}")
        print(f"   {Colors.CYAN}learnshells butter{Colors.RESET}")
        print(f"   {Colors.DIM}↳ Maximum automation, zero effort{Colors.RESET}\n")
        
        print(f"{Colors.BRIGHT_YELLOW}4. Need control?{Colors.RESET}")
        print(f"   {Colors.CYAN}learnshells expert{Colors.RESET}")
        print(f"   {Colors.DIM}↳ Full manual configuration{Colors.RESET}\n")
        
        print(f"{Colors.BRIGHT_GREEN}{'='*60}{Colors.RESET}\n")
    
    @staticmethod
    def show_loading(message: str):
        """Display loading message"""
        print(f"{Colors.BRIGHT_CYAN}⏳ {message}...{Colors.RESET}", end='', flush=True)
    
    @staticmethod
    def clear_loading():
        """Clear loading message"""
        print("\r" + " " * 80 + "\r", end='', flush=True)
    
    @staticmethod
    def show_tip(tip: str):
        """Display a helpful tip"""
        print(f"\n{Colors.BRIGHT_YELLOW}💡 TIP: {Colors.RESET}{tip}\n")
    
    @staticmethod
    def show_separator(char: str = "─", length: int = 60):
        """Display separator line"""
        print(f"{Colors.DIM}{char * length}{Colors.RESET}")
