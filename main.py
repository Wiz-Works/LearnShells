#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                          🎓 LearnShells                              ║
║              Interactive Reverse Shell Education & Automation        ║
║                                                                      ║
║                    Learn Pentesting by Doing                         ║
╚══════════════════════════════════════════════════════════════════════╝

LearnShells - Educational penetration testing tool for authorized testing only.
Built for HackTheBox, TryHackMe, and CTF environments.

Author: Wiz-Works
Version: 0.1.0
License: MIT
"""

import sys
import os
import time
import logging
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.markdown import Markdown
from rich import box
import click

# Import LearnShells modules
from learnshells.modes.learn_mode import LearnMode
from learnshells.modes.auto_mode import AutoMode
from learnshells.modes.butter_mode import ButterMode
from learnshells.modes.expert_mode import ExpertMode
from learnshells.generators import get_generator
from learnshells.listeners import get_listener
from learnshells.core.detector import TargetDetector
from learnshells.core.interface_detector import InterfaceDetector
from learnshells.stabilizers.tty_upgrade import TTYUpgrader
from learnshells.evasion.obfuscator import Obfuscator
from learnshells.evasion.encoding import Encoder
from learnshells.utils.logger import Logger
from learnshells.utils.network import NetworkUtils

# Initialize Rich console for beautiful output
console = Console()

# Initialize logger
logger = Logger()

# ASCII Art Banner
BANNER = """
    __                           _____ __         ____    
   / /   ___  ____ __________ _/ ___// /_  ___  / / /____
  / /   / _ \/ __ `/ ___/ __ \\__ \/ __ \/ _ \/ / / ___/
 / /___/  __/ /_/ / /  / / / /__/ / / / /  __/ / (__  ) 
/_____/\___/\__,_/_/  /_/ /_/____/_/ /_/\___/_/_/____/  
                                                          
         🎓 Learn by Doing • 🧈 Butter Smooth • v1.0.0
"""

# Legal disclaimer
DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║                         ⚠️  LEGAL NOTICE ⚠️                          ║
╚══════════════════════════════════════════════════════════════════════╝

LearnShells is designed for AUTHORIZED SECURITY TESTING ONLY.

✅ LEGAL USE:
   • Personal lab environments you own
   • HackTheBox / TryHackMe platforms
   • CTF competitions and training
   • Bug bounty programs (with valid authorization)
   • Penetration testing (with signed contract/written permission)
   • Educational research (with proper authorization)
   • Security training in controlled environments

❌ ILLEGAL USE:
   • Unauthorized access to systems
   • Testing without explicit permission
   • Any malicious activities
   • Systems you do not own or have permission to test

⚖️  BY USING THIS TOOL, YOU AGREE TO:
   1. Only use on systems you own or have written authorization to test
   2. Follow ALL applicable local, state, federal, and international laws
   3. Use ONLY for educational and authorized testing purposes
   4. Accept FULL responsibility for your actions
   5. NOT use for malicious, illegal, or unauthorized activities

⚠️  IMPORTANT:
   • Unauthorized access to computer systems is ILLEGAL in most countries
   • Penalties may include fines and imprisonment
   • "I was just testing" is NOT a valid legal defense
   • Always get written permission before testing ANY system

THE AUTHORS AND CONTRIBUTORS ASSUME NO LIABILITY FOR MISUSE.
YOU ARE SOLELY RESPONSIBLE FOR YOUR ACTIONS.

════════════════════════════════════════════════════════════════════════

Press ENTER to acknowledge and continue (or Ctrl+C to exit)...
"""


def show_banner():
    """Display the gorgeous LearnShells banner"""
    os.system('clear' if os.name == 'posix' else 'cls')
    banner_text = Text(BANNER)
    banner_text.stylize("bold cyan")
    console.print(banner_text)
    tagline = Text("Interactive Reverse Shell Education & Automation", style="dim italic")
    console.print(tagline, justify="center")
    console.print()


def show_disclaimer():
    """Display legal disclaimer and require acknowledgment"""
    disclaimer_panel = Panel(
        DISCLAIMER,
        border_style="bold red",
        box=box.DOUBLE,
        padding=(1, 2)
    )
    console.print(disclaimer_panel)
    try:
        input()  # Wait for Enter
        console.print()
        confirmed = Confirm.ask(
            "[bold yellow]Do you confirm you will ONLY use LearnShells for legal, "
            "authorized testing?[/bold yellow]",
            default=False
        )
        if not confirmed:
            console.print("\n[bold red]❌ You must agree to use this tool legally.[/bold red]")
            console.print("[dim]Exiting...[/dim]\n")
            sys.exit(1)
        console.print("\n[bold green]✓ Legal agreement acknowledged[/bold green]")
        console.print("[dim]Proceeding with LearnShells...[/dim]\n")
        time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n\n[bold red]Exiting...[/bold red]\n")
        sys.exit(0)


def show_main_menu():
    """Display the gorgeous main menu"""
    console.print()
    menu_content = """
[bold cyan]Select a Mode:[/bold cyan]

[bold green]1.[/bold green] 🎓 [bold]Learn Mode[/bold] - [dim]Interactive teaching (perfect for beginners)[/dim]
   → Step-by-step guidance with detailed explanations
   → Understand every technique as you use it
   
[bold green]2.[/bold green] 🤖 [bold]Auto Mode[/bold] - [dim]Automated exploitation (recommended)[/dim]
   → Give URL → Get Shell (fully automated)
   → Smart detection and optimal payload selection
   
[bold green]3.[/bold green] 🧈 [bold]Butter Mode[/bold] - [dim]Zero effort required (ultimate lazy)[/dim]
   → Monitors terminal and clipboard
   → One-click shell when RCE detected
   
[bold green]4.[/bold green] ⚡ [bold]Fast Mode[/bold] - [dim]Speed over explanation (for experienced users)[/dim]
   → Minimal output, maximum speed
   → Skip the teaching, just get shells
   
[bold green]5.[/bold green] 🔧 [bold]Expert Mode[/bold] - [dim]Manual control (for professionals)[/dim]
   → Full control over every parameter
   → Custom payloads and configurations

[bold green]6.[/bold green] 📚 [bold]Lessons[/bold] - [dim]Learn pentesting concepts[/dim]
   → Interactive tutorials
   → Practice exercises

[bold green]7.[/bold green] 🛠️  [bold]Tools[/bold] - [dim]Utility commands[/dim]
   → Generate payloads
   → Start listeners
   → Diagnostics

[bold green]8.[/bold green] ❓ [bold]Help[/bold] - [dim]Documentation and examples[/dim]

[bold red]0.[/bold red] 🚪 [bold]Exit[/bold]
"""
    menu_panel = Panel(
        menu_content,
        title="[bold white]LearnShells Main Menu[/bold white]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 2)
    )
    console.print(menu_panel)
    console.print()


def show_status_bar():
    """Display current system status"""
    interface_detector = InterfaceDetector(logger=logger)
    vpn_info = interface_detector.detect_vpn_interface()
    if vpn_info:
        vpn_status = f"🟢 Connected ({vpn_info['interface']}: {vpn_info['ip']})"
    else:
        vpn_status = "🔴 Not Connected"
    status_table = Table(show_header=False, box=None, padding=(0, 1))
    status_table.add_column(style="dim")
    status_table.add_column(style="bold")
    status_table.add_row("VPN:", vpn_status)
    status_table.add_row("Active Shells:", "0")
    status_table.add_row("Mode:", "Menu")
    console.print(Panel(
        status_table,
        title="[dim]System Status[/dim]",
        border_style="dim",
        box=box.SIMPLE,
        padding=(0, 1)
    ))
    console.print()


def check_vpn():
    """Check if VPN is connected (tun0/tun1 interface)"""
    interface_detector = InterfaceDetector(logger=logger)
    vpn_info = interface_detector.detect_vpn_interface()
    return vpn_info is not None


def show_warning_box(message: str, title: str = "⚠️  Warning"):
    """Display a warning message in a prominent box"""
    warning_panel = Panel(
        message,
        title=f"[bold yellow]{title}[/bold yellow]",
        border_style="yellow",
        box=box.HEAVY,
        padding=(1, 2)
    )
    console.print(warning_panel)


def show_success_box(message: str, title: str = "✓ Success"):
    """Display a success message"""
    success_panel = Panel(
        message,
        title=f"[bold green]{title}[/bold green]",
        border_style="green",
        box=box.ROUNDED,
        padding=(1, 2)
    )
    console.print(success_panel)


def show_error_box(message: str, title: str = "✗ Error"):
    """Display an error message"""
    error_panel = Panel(
        message,
        title=f"[bold red]{title}[/bold red]",
        border_style="red",
        box=box.HEAVY,
        padding=(1, 2)
    )
    console.print(error_panel)


# ============================================================================
# CLI Commands
# ============================================================================

@click.group(invoke_without_command=True)
@click.option('--version', is_flag=True, help='Show version information')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.pass_context
def cli(ctx, version, debug):
    """
    🎓 LearnShells - Interactive Reverse Shell Education & Automation
    
    Learn pentesting by doing, not just reading.
    """
    # Enable debug logging if requested
    if debug:
        logger.set_verbose_mode(True)
        logging.basicConfig(level=logging.DEBUG, force=True)
        console.print("[bold yellow]Debug mode enabled[/bold yellow]")
    if version:
        console.print("[bold cyan]LearnShells v1.0.0[/bold cyan]")
        console.print("[dim]Educational penetration testing tool[/dim]")
        sys.exit(0)
    if ctx.invoked_subcommand is None:
        show_banner()
        show_disclaimer()
        interactive_menu()


def interactive_menu():
    """Main interactive menu loop"""
    while True:
        try:
            show_status_bar()
            show_main_menu()
            choice = Prompt.ask(
                "[bold cyan]Enter your choice[/bold cyan]",
                choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"],
                default="2"
            )
            console.print()
            if choice == "0":
                console.print("[bold]👋 Thanks for using LearnShells![/bold]")
                console.print("[dim]Happy (legal) hacking![/dim]\n")
                sys.exit(0)
            elif choice == "1":
                learn_mode()
            elif choice == "2":
                auto_mode()
            elif choice == "3":
                butter_mode()
            elif choice == "4":
                fast_mode()
            elif choice == "5":
                expert_mode()
            elif choice == "6":
                show_lessons()
            elif choice == "7":
                show_tools_menu()
            elif choice == "8":
                show_help()
        except KeyboardInterrupt:
            console.print("\n\n[bold yellow]⚠️  Interrupted by user[/bold yellow]")
            if Confirm.ask("Exit LearnShells?", default=False):
                console.print("\n[bold]👋 Goodbye![/bold]\n")
                sys.exit(0)
            console.print()


# ... continued in next chunk ...
