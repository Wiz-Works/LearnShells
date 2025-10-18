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
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.markdown import Markdown
from rich import box
import click
import logging

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
                                                          
          Reverse Shell Generator • v0.1.0
"""

# Legal disclaimer
DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║                         ⚠️  ETHICAL NOTICE ⚠️                          ║
╚══════════════════════════════════════════════════════════════════════╝

LearnShells is designed for AUTHORIZED SECURITY TESTING ONLY.

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

THE AUTHOR AND CONTRIBUTORS ASSUME NO LIABILITY FOR MISUSE.
YOU ARE SOLELY RESPONSIBLE FOR YOUR ACTIONS.

════════════════════════════════════════════════════════════════════════

Press ENTER to acknowledge and continue (or Ctrl+C to exit)...
"""


def show_banner():
    """Display the gorgeous LearnShells banner"""
    # Clear screen for dramatic effect
    os.system('clear' if os.name == 'posix' else 'cls')
    
    # Banner with gradient effect
    banner_text = Text(BANNER)
    banner_text.stylize("bold cyan")
    console.print(banner_text)
    
    # Tagline
    tagline = Text("Interactive Reverse Shell Education & Automation", style="dim italic")
    console.print(tagline, justify="center")
    console.print()


def show_disclaimer():
    """Display legal disclaimer and require acknowledgment"""
    # Show disclaimer in a prominent panel
    disclaimer_panel = Panel(
        DISCLAIMER,
        border_style="bold red",
        box=box.DOUBLE,
        padding=(1, 2)
    )
    
    console.print(disclaimer_panel)
    
    # Require explicit acknowledgment
    try:
        input()  # Wait for Enter
        
        # Double confirmation for emphasis
        console.print()
        confirmed = Confirm.ask(
            "[bold yellow]Do you confirm you will ONLY use LearnShells for legal, "
            "authorized testing?[/bold yellow]",
            default=True
        )
        
        if not confirmed:
            console.print("\n[bold red]❌ You must agree to use this tool legally.[/bold red]")
            console.print("[dim]Exiting...[/dim]\n")
            sys.exit(1)
        
        # Show acceptance message
        console.print("\n[bold green]✓ Legal agreement acknowledged[/bold green]")
        console.print("[dim]Proceeding with LearnShells...[/dim]\n")
        time.sleep(1)
        
    except KeyboardInterrupt:
        console.print("\n\n[bold red]Exiting...[/bold red]\n")
        sys.exit(0)


def show_main_menu():

    menu_content = """[bold cyan]Select a Mode:[/bold cyan]
    

 █████                                                █████████  █████               ████  ████         
░░███                                                ███░░░░░███░░███               ░░███ ░░███         
 ░███         ██████   ██████   ████████  ████████  ░███    ░░░  ░███████    ██████  ░███  ░███   █████ 
 ░███        ███░░███ ░░░░░███ ░░███░░███░░███░░███ ░░█████████  ░███░░███  ███░░███ ░███  ░███  ███░░  
 ░███       ░███████   ███████  ░███ ░░░  ░███ ░███  ░░░░░░░░███ ░███ ░███ ░███████  ░███  ░███ ░░█████ 
 ░███      █░███░░░   ███░░███  ░███      ░███ ░███  ███    ░███ ░███ ░███ ░███░░░   ░███  ░███  ░░░░███
 ███████████░░██████ ░░████████ █████     ████ █████░░█████████  ████ █████░░██████  █████ █████ ██████ 
░░░░░░░░░░░  ░░░░░░   ░░░░░░░░ ░░░░░     ░░░░ ░░░░░  ░░░░░░░░░  ░░░░ ░░░░░  ░░░░░░  ░░░░░ ░░░░░ ░░░░░░  
                                                                                                        
                                                                                                                                                                                                                
                                       ▖  ▖   ▌    ▄     ▖  ▖▘  ▖  ▖    ▌   
                                       ▛▖▞▌▀▌▛▌█▌  ▙▘▌▌  ▌▞▖▌▌▀▌▌▞▖▌▛▌▛▘▙▘▛▘
                                       ▌▝ ▌█▌▙▌▙▖  ▙▘▙▌  ▛ ▝▌▌▙▖▛ ▝▌▙▌▌ ▛▖▄▌
                                                     ▄▌                     
                                
[bold green]1.[/bold green] 🎓 [bold]Learn Mode[/bold] - [dim]Interactive teaching (W.I.P.)[/dim]
   → Step-by-step guidance with detailed explanations
   → Helps with understanding every technique as you use it

[bold green]2.[/bold green] 🤖 [bold]Auto Mode[/bold] - [dim]Automated exploitation (W.I.P.)[/dim]
   → Give URL → Set listener on another terminal → Get shell
   → Smart detection and optimal payload selection

[bold green]3.[/bold green] 🔧 [bold]Reverse Shell Generator Mode[/bold] - [dim]Manual control[/dim]
   → Select parameters to create custom payloads and configurations
   → Chose between different languages, obfuscation methods and encoders

[bold green]4.[/bold green] 🧈 [bold]Butter Mode[/bold] - [dim]Smooth exploitation (W.I.P.)[/dim]
   → File upload and command-based attacks
   → Intelligent scanning and variant testing
   → Smooth as butter

[bold green]5.[/bold green] 📚 [bold]Lessons[/bold] - [dim]Learn pentesting concepts[/dim]
   → Interactive tutorials
   → Practice exercises

[bold green]6.[/bold green] 🛠️  [bold]Tools[/bold] - [dim]Utility commands[/dim]
   → Generate payloads
   → Start listeners
   → Diagnostics

[bold green]7.[/bold green] ❓ [bold]Help[/bold] - [dim]Documentation and examples[/dim]

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
    # Check VPN connection
    interface_detector = InterfaceDetector(logger=logger)
    vpn_info = interface_detector.detect_vpn_interface()
    
    if isinstance(vpn_info, dict):
        vpn_status = f"🟢 Connected ({vpn_info['interface']}: {vpn_info['ip']})"
    elif isinstance(vpn_info, str):
        vpn_status = f"🟢 Connected ({vpn_info})"
    else:
        vpn_status = "🔴 Not Connected"
    
    # Create status table
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
@click.pass_context
def cli(ctx, version):
    """
    🎓 LearnShells - Interactive Reverse Shell Education & Automation
    
    Learn pentesting by doing, not just reading.
    """
    if version:
        console.print("[bold cyan]LearnShells v1.0.0[/bold cyan]")
        console.print("[dim]Educational penetration testing tool[/dim]")
        sys.exit(0)
    
    if ctx.invoked_subcommand is None:
        # Show interactive menu
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
                choices=["0", "1", "2", "3", "4", "5", "6", "7"],
                default="3"
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
                expert_mode()
            elif choice == "4":
                butter_mode()
            elif choice == "5":
                show_lessons()
            elif choice == "6":
                show_tools_menu()
            elif choice == "7":
                show_help()
                
        except KeyboardInterrupt:
            console.print("\n\n[bold yellow]⚠️  Interrupted by user[/bold yellow]")
            if Confirm.ask("Exit LearnShells?", default=False):
                console.print("\n[bold]👋 Goodbye![/bold]\n")
                sys.exit(0)
            console.print()
def learn_mode():
    """Interactive learning mode with full explanations"""
    console.clear()
    console.print("[bold cyan]🎓 Learn Mode - Interactive Teaching[/bold cyan]\n")
    
    intro = """
Welcome to Learn Mode! I'll guide you through getting a reverse shell
while teaching you how everything works along the way.

This mode is perfect if you're:
• New to penetration testing
• Want to understand WHY techniques work
• Learning for HackTheBox or TryHackMe
• Prefer step-by-step guidance
"""
    
    console.print(Panel(intro, border_style="cyan", box=box.ROUNDED))
    console.print()
    
    # Check VPN first
    if not check_vpn():
        show_warning_box(
            "No VPN connection detected!\n\n"
            "For HTB/THM boxes, you need to be connected via OpenVPN.\n"
            "Connect to your VPN first, then restart LearnShells.",
            title="⚠️  VPN Not Connected"
        )
        
        if not Confirm.ask("Continue anyway?", default=False):
            return
        console.print()
    
    # Initialize Learn Mode
    try:
        mode = LearnMode(logger=logger)
        
        # Get target from user
        console.print("[bold]Step 1: What are you testing?[/bold]\n")
        
        example_text = Text("Examples:\n", style="dim")
        example_text.append("  • http://10.10.10.50/search?q=test\n", style="dim green")
        example_text.append("  • http://target.com/admin/upload.php\n", style="dim green")
        example_text.append("  • http://192.168.1.100/api/cmd\n", style="dim green")
        console.print(example_text)
        
        url = Prompt.ask("[cyan]Enter the URL to test[/cyan]")
        
        if not url:
            show_error_box("URL cannot be empty")
            return
        
        console.print()
        console.print(f"[bold green]✓[/bold green] Target URL: [cyan]{url}[/cyan]")
        console.print()
        
        # Run Learn Mode
        with console.status("[bold green]Starting Learn Mode...") as status:
            mode.run()
        
        show_success_box("Learn Mode completed!")
        
    except Exception as e:
        show_error_box(f"Error in Learn Mode: {str(e)}")
        logger.error(f"Learn Mode error: {e}")
    
    console.print()
    Prompt.ask("Press Enter to return to menu")


def auto_mode():
    """Fully automated mode"""
    console.clear()
    console.print("[bold cyan]🤖 Auto Mode - Automated Exploitation[/bold cyan]\n")
    
    intro = """
Auto Mode will automatically:
✓ Detect vulnerabilities
✓ Test for command execution
✓ Enumerate the target
✓ Test egress ports
✓ Generate optimal payload
✓ Start listener
✓ Deliver payload
✓ Upgrade shell to full TTY
✓ Plant persistence
✓ Monitor health
"""
    
    console.print(Panel(intro, border_style="cyan", box=box.ROUNDED))
    console.print()
    
    url = Prompt.ask("[cyan]Enter the URL to exploit[/cyan]")
    
    if not url:
        show_error_box("URL cannot be empty")
        return
    
    # Initialize Auto Mode
    try:
        mode = AutoMode(logger=logger)
        
        console.print()
        console.print(f"[bold green]✓[/bold green] Target: [cyan]{url}[/cyan]")
        console.print()
        
        # Extract target IP from URL
        import re
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', url)
        target_ip = ip_match.group(1) if ip_match else None
        
        # Run Auto Mode
        with console.status("[bold green]Running automated exploitation...") as status:
            mode.run(target_url=url)
        
        show_success_box("Auto Mode completed! Check above for your shell.")
        
    except Exception as e:
        show_error_box(f"Error in Auto Mode: {str(e)}")
        logger.error(f"Auto Mode error: {e}")
    
    console.print()
    Prompt.ask("Press Enter to return to menu")


def butter_mode():
    """Ultimate lazy mode"""
    console.clear()
    console.print("[bold cyan]🧈 Butter Mode[/bold cyan]\n")
    
    intro = """
Can either bruteforce or work of know parameters, able to upload and execute files
"""
    
    console.print(Panel(intro, border_style="cyan", box=box.ROUNDED))
    console.print()
    
    # Get port
    port = Prompt.ask("[cyan]Listener port[/cyan]", default="4444")
    
    try:
        port = int(port)
    except ValueError:
        show_error_box("Invalid port number")
        return
    
    # Initialize Butter Mode
    try:
        mode = ButterMode(logger=logger)
        
        console.print()
        console.print("[bold green]🧈 Butter Mode Active![/bold green]")
        console.print(f"[dim]Listener on port {port}, monitoring clipboard...[/dim]")
        console.print()
        console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
        
        # Run Butter Mode
        mode.run(port=port)
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Butter Mode stopped[/bold yellow]")
    except Exception as e:
        show_error_box(f"Error in Butter Mode: {str(e)}")
        logger.error(f"Butter Mode error: {e}")
    
    console.print()
    Prompt.ask("Press Enter to return to menu")


def fast_mode():
    """Fast mode for experienced users"""
    console.clear()
    console.print("[bold cyan]⚡ Fast Mode - Maximum Speed[/bold cyan]\n")
    
    url = Prompt.ask("[cyan]Target URL[/cyan]")
    
    if not url:
        show_error_box("URL cannot be empty")
        return
    
    # Fast mode = Auto mode without explanations
    try:
        mode = AutoMode(logger=logger)
        
        console.print()
        console.print(f"[dim]Target: {url}[/dim]")
        
        # Extract target IP
        import re
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', url)
        target_ip = ip_match.group(1) if ip_match else None
        
        # Run with minimal output
        with console.status("[bold green]Exploiting...") as status:
            mode.run(target_url=url)
        
        console.print("[bold green]✓ Done[/bold green]\n")
        
    except Exception as e:
        console.print(f"[bold red]✗ Failed: {e}[/bold red]\n")
    
    Prompt.ask("Press Enter to return to menu")


def expert_mode():
    """Expert mode with manual control"""
    console.clear()
    console.print("[bold cyan]🔧 Expert Mode - Manual Control[/bold cyan]\n")
    
    # Initialize Expert Mode
    try:
        mode = ExpertMode(logger=logger)
        
        # Get configuration from user
        console.print("[bold]Configuration:[/bold]\n")
        
        # Detect and display VPN IP
        from learnshells.core.interface_detector import InterfaceDetector
        interface_detector = InterfaceDetector(logger=logger)
        vpn_interface = interface_detector.detect_vpn_interface()
        
        if vpn_interface:
            vpn_ip = interface_detector.vpn_ip
            console.print(f"[dim]Detected VPN IP: [bold green]{vpn_ip}[/bold green][/dim]")
        
        # Target IP
        target = Prompt.ask("[cyan]Your IP[/cyan]", default=vpn_ip)
        if target:
            mode.target_ip = target
        
        # Port
        port = Prompt.ask("[cyan]Listener port[/cyan]", default="4444")
        try:
            mode.listener_port = int(port)
        except ValueError:
            show_error_box("Invalid port")
            return
        
        # Shell type
        shell_type = Prompt.ask(
            "[cyan]Shell type[/cyan]",
            choices=['bash', 'python', 'php', 'powershell', 'perl', 'ruby', 'nodejs'],
            default='bash'
        )
        mode.shell_type = shell_type
        
        # Listener type
        listener_type = Prompt.ask(
            "[cyan]Listener type[/cyan]",
            choices=['netcat', 'socat', 'metasploit'],
            default='netcat'
        )
        mode.listener_type = listener_type
        
        # Obfuscation
        obfuscate = Confirm.ask("[cyan]Enable obfuscation?[/cyan]", default=False)
        mode.enable_obfuscation = obfuscate
        
        # Wrappers
        wrapper = Confirm.ask("[cyan]Apply wrapper?[/cyan]", default=False)
        mode.enable_wrapper = wrapper
        
        # Encoding
        encode = Confirm.ask("[cyan]Enable encoding?[/cyan]", default=False)
        mode.enable_encoding = encode
        
        console.print()
        
        # If multiple evasion techniques selected, ask how to display
        techniques_count = sum([obfuscate, wrapper, encode])
#here        
        if techniques_count >= 2 and (obfuscate and wrapper):
            console.print("[bold cyan]🔀 Multiple evasion techniques selected![/bold cyan]\n")
            console.print("[dim]1. Show combined variants (wrapper + obfuscation)[/dim]")
            console.print("[dim]2. Show separate variants (wrapper | obfuscation)[/dim]\n")
            
            display_choice = Prompt.ask(
                "[cyan]How would you like to view variants?[/cyan]",
                choices=["1", "2"],
                default="1"
            )
            console.print("[dim]1. Show combined variants (wrapper + obfuscation)[/dim]")
            console.print("[dim]2. Show separate variants (wrapper | obfuscation)[/dim]\n")
            
            if display_choice == "1":
                # Combined variants
                mode.display_mode = "combined"
                
                # Get available wrappers (hardcoded list for now)
                wrapper_options = [
                    "Bash -c (Web Shell)",
                    "SH -c Wrapper", 
                    "Eval Wrapper",
                    "Command Substitution",
                    "Command Chain",
                    "All wrappers"
                ]
                
                console.print("[bold]📦 Select wrapper(s) to apply:[/bold]")
                for i, opt in enumerate(wrapper_options, 1):
                    console.print(f"[cyan]{i}.[/cyan] {opt}")
                
                wrapper_selection = Prompt.ask(
                    "\n[cyan]Select (comma-separated, e.g., 1,3,6)[/cyan]",
                    default="6"
                )
                mode.selected_wrappers = wrapper_selection
                
                console.print()
                
                # Get available obfuscations
                obfuscation_options = [
                    "Using $0 Variable",
                    "Variable Split",
                    "Brace Expansion",
                    "Wildcard",
                    "Command Substitution",
                    "Double Quotes",
                    "Escape Characters",
                    "SH Variant",
                    "All obfuscations"
                ]
                
                console.print("[bold]🎭 Select obfuscation(s) to apply:[/bold]")
                for i, opt in enumerate(obfuscation_options, 1):
                    console.print(f"[cyan]{i}.[/cyan] {opt}")
                
                obfuscation_selection = Prompt.ask(
                    "\n[cyan]Select (comma-separated, e.g., 2,4,9)[/cyan]",
                    default="9"
                )
                mode.selected_obfuscations = obfuscation_selection
                
            else:
                # Separate variants
                mode.display_mode = "separate"
        else:
            mode.display_mode = "separate"
        
        console.print()
        
        # Run Expert Mode
        with console.status("[bold green]Executing manual configuration...") as status:
            mode.run()
        
    except Exception as e:
        show_error_box(f"Error in Expert Mode: {str(e)}")
        logger.error(f"Expert Mode error: {e}")
    
    console.print()
    Prompt.ask("Press Enter to return to menu")

def generate_payload_tool():
    """Generate payload tool"""
    console.clear()
    console.print("[bold cyan]🔨 Generate Payload[/bold cyan]\n")
    
    try:
        # Get parameters
        shell_type = Prompt.ask(
            "[cyan]Shell type[/cyan]",
            choices=['bash', 'python', 'php', 'powershell', 'perl', 'ruby', 'nodejs'],
            default='bash'
        )
        
        lhost = Prompt.ask("[cyan]Your IP (LHOST)[/cyan]")
        lport = Prompt.ask("[cyan]Your port (LPORT)[/cyan]", default="4444")
        
        # Generate payload
        generator = get_generator(shell_type)(logger=logger)
        payload = generator.generate(lhost, int(lport))
        
        # Ask about obfuscation
        if Confirm.ask("[cyan]Obfuscate payload?[/cyan]", default=False):
            obfuscator = Obfuscator(logger=logger)
            payload = obfuscator.obfuscate(payload, shell_type)
        
        # Ask about encoding
        if Confirm.ask("[cyan]Encode payload?[/cyan]", default=False):
            encoding = Prompt.ask(
                "[cyan]Encoding method[/cyan]",
                choices=['base64', 'hex', 'url'],
                default='base64'
            )
            encoder = Encoder(logger=logger)
            payload = encoder.encode(payload, encoding)
        
        # Display payload
        console.print()
        payload_panel = Panel(
            payload,
            title="[bold green]Generated Payload[/bold green]",
            border_style="green",
            box=box.ROUNDED
        )
        console.print(payload_panel)
        
        # Copy to clipboard
        try:
            import pyperclip
            pyperclip.copy(payload)
            console.print("\n[bold green]✓ Copied to clipboard![/bold green]\n")
        except ImportError:
            console.print("\n[yellow]⚠ Install pyperclip to enable clipboard: pip install pyperclip[/yellow]\n")
        
    except Exception as e:
        show_error_box(f"Error generating payload: {str(e)}")
    
    Prompt.ask("Press Enter to continue")


def start_listener_tool():
    """Start listener tool"""
    console.clear()
    console.print("[bold cyan]🎧 Start Listener[/bold cyan]\n")
    
    try:
        listener_type = Prompt.ask(
            "[cyan]Listener type[/cyan]",
            choices=['netcat', 'socat', 'metasploit'],
            default='netcat'
        )
        
        port = Prompt.ask("[cyan]Port to listen on[/cyan]", default="4444")
        
        # Get listener
        listener = get_listener(listener_type)(logger=logger)
        
        if not listener.check_availability():
            show_error_box(f"{listener_type} is not available on this system")
            Prompt.ask("Press Enter to continue")
            return
        
        console.print()
        console.print(f"[bold green]Starting {listener_type} listener on port {port}...[/bold green]")
        console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
        
        # Start listener
        listener.start(int(port))
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Listener stopped[/bold yellow]\n")
    except Exception as e:
        show_error_box(f"Error starting listener: {str(e)}")
    
    Prompt.ask("Press Enter to continue")


def detect_os_tool():
    """OS detection tool"""
    console.clear()
    console.print("[bold cyan]🔍 Detect Operating System[/bold cyan]\n")
    
    try:
        target = Prompt.ask("[cyan]Target IP (leave empty for local)[/cyan]", default="")
        
        detector = OSDetector(logger=logger)
        
        console.print()
        with console.status("[bold green]Detecting...") as status:
            if target:
                result = detector.detect_os(target)
            else:
                result = detector.detect_local_os()
        
        # Display results
        results_table = Table(title="Detection Results", box=box.ROUNDED)
        results_table.add_column("Property", style="cyan")
        results_table.add_column("Value", style="green")
        
        for key, value in result.items():
            if isinstance(value, list):
                value = ", ".join(value)
            results_table.add_row(key.title(), str(value))
        
        console.print(results_table)
        console.print()
        
    except Exception as e:
        show_error_box(f"Error detecting OS: {str(e)}")
    
    Prompt.ask("Press Enter to continue")


def stabilization_tool():
    """Shell stabilization tool"""
    console.clear()
    console.print("[bold cyan]🛠️  Shell Stabilization[/bold cyan]\n")
    
    try:
        method = Prompt.ask(
            "[cyan]Stabilization method[/cyan]",
            choices=['python', 'script', 'socat'],
            default='python'
        )
        
        stabilizer = TTYUpgrade(logger=logger)
        commands = stabilizer.get_upgrade_commands(method)
        
        # Display commands
        console.print()
        console.print("[bold]Run these commands in your shell:[/bold]\n")
        
        for i, cmd in enumerate(commands, 1):
            console.print(f"[bold cyan]{i}.[/bold cyan] [green]{cmd}[/green]")
        
        console.print()
        console.print("[dim]💡 Remember to adjust TERM and stty rows/cols to match your terminal![/dim]\n")
        
    except Exception as e:
        show_error_box(f"Error: {str(e)}")
    
    Prompt.ask("Press Enter to continue")


def diagnostics_tool():
    """System diagnostics tool"""
    console.clear()
    console.print("[bold cyan]🏥 System Diagnostics[/bold cyan]\n")
    
    try:
        # Check system requirements
        checks = []
        
        # Python version
        import sys
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        checks.append(("Python Version", python_version, "✓" if sys.version_info >= (3, 8) else "✗"))
        
        # VPN Connection
        vpn_connected = check_vpn()
        checks.append(("VPN Connection", "Connected" if vpn_connected else "Not Connected", "✓" if vpn_connected else "⚠"))
        
        # Check tools
        import shutil
        
        netcat_installed = shutil.which('nc') is not None
        checks.append(("Netcat", "Installed" if netcat_installed else "Not Installed", "✓" if netcat_installed else "✗"))
        
        socat_installed = shutil.which('socat') is not None
        checks.append(("Socat", "Installed" if socat_installed else "Not Installed", "✓" if socat_installed else "⚠"))
        
        msfconsole_installed = shutil.which('msfconsole') is not None
        checks.append(("Metasploit", "Installed" if msfconsole_installed else "Not Installed", "ℹ" if not msfconsole_installed else "✓"))
        
        rlwrap_installed = shutil.which('rlwrap') is not None
        checks.append(("rlwrap", "Installed" if rlwrap_installed else "Not Installed", "✓" if rlwrap_installed else "⚠"))
        
        # Display results
        results_table = Table(title="System Check", box=box.ROUNDED)
        results_table.add_column("Component", style="cyan")
        results_table.add_column("Status", style="white")
        results_table.add_column("Result", style="green")
        
        for component, status, result in checks:
            style = "green" if result == "✓" else ("yellow" if result == "⚠" else "red" if result == "✗" else "dim")
            results_table.add_row(component, status, f"[{style}]{result}[/{style}]")
        
        console.print(results_table)
        console.print("\n[dim]System check complete![/dim]\n")
        
    except Exception as e:
        show_error_box(f"Error running diagnostics: {str(e)}")
    
    Prompt.ask("Press Enter to continue")


def show_help():
    """Display help and documentation"""
    console.clear()
    console.print("[bold cyan]❓ Help & Documentation[/bold cyan]\n")
    
    help_text = """
# Quick Start

1. **Learn Mode** - Best for beginners
   ```bash
   learnshells learn
   ```

2. **Auto Mode** - Fully automated
   ```bash
   learnshells auto
   ```

3. **Butter Mode** - Zero effort
   ```bash
   learnshells butter
   ```

4. **Expert Mode** - Full control
   ```bash
   learnshells expert
   ```

# Command-Line Usage

Generate a payload:
```bash
learnshells generate bash --lhost 10.10.14.5 --lport 4444
```

Start a listener:
```bash
learnshells listen --port 4444 --type netcat
```

Detect OS:
```bash
learnshells detect --target 10.10.10.50
```

Get stabilization commands:
```bash
learnshells stabilize --method python
```

# Tips

- Always connect to VPN first for HTB/THM
- Use Learn Mode if you're new to pentesting
- Auto Mode is perfect for quick CTF challenges
- Butter Mode monitors your terminal automatically
- Expert Mode gives you complete control

# Documentation

Full documentation: https://docs.learnshells.io
GitHub: https://github.com/yourusername/learnshells

# Support

Discord: https://discord.gg/learnshells
Issues: https://github.com/yourusername/learnshells/issues
"""
    
    console.print(Markdown(help_text))
    console.print()
    
    Prompt.ask("Press Enter to return to menu")


# ============================================================================
# CLI Subcommands
# ============================================================================

@cli.command()
@click.argument('url', required=False)
@click.option('--port', default=443, help='Port to use for reverse shell')
@click.option('--explain/--no-explain', default=True, help='Show explanations')
def learn(url, port, explain):
    """🎓 Learn Mode - Interactive teaching with full explanations"""
    show_banner()
    console.print("[bold cyan]🎓 Learn Mode[/bold cyan]\n")
    
    try:
        mode = LearnMode(logger=logger)
        
        if url:
            console.print(f"[dim]Target:[/dim] [cyan]{url}[/cyan]")
            console.print(f"[dim]Port:[/dim] [cyan]{port}[/cyan]\n")
        
        mode.run()
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]\n")
        sys.exit(1)


@cli.command()
@click.argument('url', required=False)
@click.option('--port', default=443, help='Port to use for reverse shell')
@click.option('--target', help='Target IP address')
@click.option('--monitor/--no-monitor', default=True, help='Monitor shell health')
def auto(url, port, target, monitor):
    """🤖 Auto Mode - Fully automated exploitation"""
    show_banner()
    console.print("[bold cyan]🤖 Auto Mode[/bold cyan]\n")
    
    try:
        mode = AutoMode(logger=logger)
        
        # Extract IP from URL if provided
        if url and not target:
            import re
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', url)
            target = ip_match.group(1) if ip_match else None
        
        if target:
            console.print(f"[dim]Target:[/dim] [cyan]{target}[/cyan]")
            console.print(f"[dim]Port:[/dim] [cyan]{port}[/cyan]\n")
        
        mode.run(target_ip=target, port=port)
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]\n")
        sys.exit(1)


@cli.command()
@click.option('--port', default=4444, help='Port to use for reverse shell')
def butter(port):
    """🧈 Butter Mode"""
    show_banner()
    console.print("[bold cyan]🧈 Butter Mode - Ultimate Lazy Mode[/bold cyan]\n")
    
    try:
        mode = ButterMode(logger=logger)
        
        console.print(f"[dim]Port:[/dim] [cyan]{port}[/cyan]")
        console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
        
        mode.run(port=port)
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Butter Mode stopped[/bold yellow]\n")
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]\n")
        sys.exit(1)


@cli.command()
@click.argument('url', required=False)
@click.option('--port', default=443, help='Port to use')
@click.option('--target', help='Target IP address')
def fast(url, port, target):
    """⚡ Fast Mode - Maximum speed, minimal output"""
    
    try:
        mode = AutoMode(logger=logger)
        
        # Extract IP from URL if provided
        if url and not target:
            import re
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', url)
            target = ip_match.group(1) if ip_match else None
        
        if not target:
            console.print("[red]❌ Target IP required[/red]")
            sys.exit(1)
        
        mode.run(target_ip=target, port=port)
        console.print("[bold green]✓[/bold green]")
        
    except Exception as e:
        console.print(f"[red]✗ {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--target', help='Target IP or URL')
@click.option('--port', default=443, help='Reverse shell port')
@click.option('--shell-type', type=click.Choice(['bash', 'python', 'php', 'powershell', 'perl', 'ruby', 'nodejs']), help='Shell type')
@click.option('--listener', type=click.Choice(['netcat', 'socat', 'metasploit']), help='Listener type')
@click.option('--obfuscate', is_flag=True, help='Obfuscate payload')
@click.option('--encode', type=click.Choice(['base64', 'hex', 'url']), help='Encode payload')
def expert(target, port, shell_type, listener, obfuscate, encode):
    """🔧 Expert Mode - Full manual control"""
    show_banner()
    console.print("[bold cyan]🔧 Expert Mode[/bold cyan]\n")
    
    try:
        mode = ExpertMode(logger=logger)
        
        config = {
            'target_ip': target,
            'port': port,
            'shell_type': shell_type,
            'listener_type': listener,
            'obfuscate': obfuscate,
            'encoding': encode,
        }
        
        mode.run(config=config)
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]\n")
        sys.exit(1)


@cli.command()
@click.argument('payload_type', type=click.Choice(['bash', 'python', 'python3', 'php', 'powershell', 'perl', 'ruby', 'nodejs']))
@click.option('--lhost', required=True, help='Listening host (your IP)')
@click.option('--lport', default=443, help='Listening port')
@click.option('--encode', type=click.Choice(['base64', 'hex', 'url']), help='Encode the payload')
@click.option('--obfuscate', is_flag=True, help='Obfuscate the payload')
@click.option('--copy/--no-copy', default=True, help='Copy to clipboard')
def generate(payload_type, lhost, lport, encode, obfuscate, copy):
    """Generate a reverse shell payload"""
    console.print(f"\n[bold cyan]Generating {payload_type} reverse shell...[/bold cyan]\n")
    
    try:
        # Map python3 to python
        if payload_type == 'python3':
            payload_type = 'python'
        
        # Generate payload
        generator = get_generator(payload_type)(logger=logger)
        payload = generator.generate(lhost, lport)
        
        # Apply obfuscation
        if obfuscate:
            obfuscator = Obfuscator(logger=logger)
            payload = obfuscator.obfuscate(payload, payload_type)
            console.print("[dim]✓ Obfuscated[/dim]")
        
        # Apply encoding
        if encode:
            encoder = Encoder(logger=logger)
            payload = encoder.encode(payload, encode)
            console.print(f"[dim]✓ Encoded ({encode})[/dim]")
        
        console.print()
        
        # Display payload
        payload_panel = Panel(
            payload,
            title="[bold green]Generated Payload[/bold green]",
            border_style="green",
            box=box.ROUNDED
        )
        console.print(payload_panel)
        
        # Copy to clipboard
        if copy:
            try:
                import pyperclip
                pyperclip.copy(payload)
                console.print("\n[bold green]✓ Copied to clipboard![/bold green]\n")
            except ImportError:
                console.print("\n[yellow]⚠ Install pyperclip to enable clipboard: pip install pyperclip[/yellow]\n")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]\n")
        sys.exit(1)


@cli.command()
@click.option('--port', default=443, help='Port to listen on')
@click.option('--type', 'listener_type', type=click.Choice(['netcat', 'socat', 'metasploit']), default='netcat', help='Listener type')
@click.option('--background', is_flag=True, help='Run in background')
def listen(port, listener_type, background):
    """Start a listener for incoming shells"""
    console.print(f"\n[bold cyan]Starting {listener_type} listener on port {port}...[/bold cyan]\n")
    
    try:
        listener = get_listener(listener_type)(logger=logger)
        
        if not listener.check_availability():
            console.print(f"[bold red]✗ {listener_type} is not available[/bold red]\n")
            sys.exit(1)
        
        if background:
            listener.start(port, background=True)
            console.print(f"[bold green]✓ Listener started in background on port {port}[/bold green]\n")
        else:
            console.print("[yellow]Press Ctrl+C to stop[/yellow]\n")
            listener.start(port)
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Listener stopped[/bold yellow]\n")
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]\n")
        sys.exit(1)


@cli.command()
@click.option('--target', help='Target IP address')
def detect(target):
    """🔍 Detect target OS and environment"""
    console.print(f"\n[bold cyan]🔍 Detecting OS...[/bold cyan]\n")
    
    try:
        detector = OSDetector(logger=logger)
        
        if target:
            result = detector.detect_os(target)
        else:
            result = detector.detect_local_os()
        
        # Display results
        results_table = Table(title="Detection Results", box=box.ROUNDED)
        results_table.add_column("Property", style="cyan")
        results_table.add_column("Value", style="green")
        
        for key, value in result.items():
            if isinstance(value, list):
                value = ", ".join(value)
            results_table.add_row(key.title(), str(value))
        
        console.print(results_table)
        console.print()
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]\n")
        sys.exit(1)


@cli.command()
@click.option('--method', type=click.Choice(['python', 'script', 'socat']), default='python', help='Stabilization method')
def stabilize(method):
    """Get shell stabilization commands"""
    console.print(f"\n[bold cyan]🛠️  Shell Stabilization ({method})[/bold cyan]\n")
    
    try:
        stabilizer = TTYUpgrade(logger=logger)
        commands = stabilizer.get_upgrade_commands(method)
        
        console.print("[bold]Run these commands in your shell:[/bold]\n")
        
        for i, cmd in enumerate(commands, 1):
            console.print(f"[bold cyan]{i}.[/bold cyan] [green]{cmd}[/green]")
        
        console.print()
        console.print("[dim]💡 Remember to adjust TERM and stty rows/cols to match your terminal![/dim]\n")
        
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]\n")
        sys.exit(1)


@cli.command()
def lessons():
    """📚 Show available interactive lessons"""
    show_banner()
    console.print("[bold cyan]📚 Interactive Lessons[/bold cyan]\n")
    
    lessons_table = Table(title="Available Lessons", box=box.ROUNDED)
    lessons_table.add_column("ID", style="cyan", width=10)
    lessons_table.add_column("Lesson", style="green", width=30)
    lessons_table.add_column("Difficulty", style="yellow", width=15)
    
    lessons_table.add_row("1", "Reverse Shells 101", "Beginner")
    lessons_table.add_row("2", "Command Injection", "Beginner")
    lessons_table.add_row("3", "TTY Upgrade", "Intermediate")
    lessons_table.add_row("4", "Persistence Techniques", "Intermediate")
    lessons_table.add_row("5", "Windows AMSI Bypass", "Advanced")
    lessons_table.add_row("6", "Privilege Escalation", "Advanced")
    
    console.print(lessons_table)
    console.print("\n[dim]Use: learnshells lesson <ID> to start a lesson[/dim]")
    console.print("[yellow]🚧 Coming in future updates![/yellow]\n")


@cli.command()
@click.argument('lesson_id', type=int)
def lesson(lesson_id):
    """Take an interactive lesson"""
    console.print(f"\n[bold cyan]Starting Lesson {lesson_id}...[/bold cyan]\n")
    console.print("[yellow]🚧 Lessons coming soon![/yellow]\n")


@cli.command()
def diagnose():
    """🔍 Run diagnostics on failed shells"""
    show_banner()
    console.print("[bold cyan]🔍 Shell Diagnostics[/bold cyan]\n")
    console.print("[yellow]🚧 Diagnostics coming soon![/yellow]\n")


@cli.command()
def dashboard():
    """📊 Show TUI dashboard with active shells"""
    show_banner()
    console.print("[bold cyan]📊 Shell Dashboard[/bold cyan]\n")
    console.print("[yellow]🚧 Dashboard coming soon![/yellow]\n")


@cli.command()
def doctor():
    """🏥 Check system compatibility and requirements"""
    show_banner()
    diagnostics_tool()


@cli.command()
@click.argument('payload')
def explain(payload):
    """📖 Explain how a reverse shell payload works"""
    console.print(f"\n[bold cyan]📖 Payload Explanation[/bold cyan]\n")
    console.print(f"[dim]Payload:[/dim] {payload}\n")
    console.print("[yellow]🚧 Payload explainer coming soon![/yellow]\n")


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point with error handling"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]⚠️  Interrupted by user[/bold yellow]")
        console.print("[dim]Exiting...[/dim]\n")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]❌ Fatal error: {e}[/bold red]")
        console.print("[dim]Run with --debug for more information[/dim]\n")
        sys.exit(1)


if __name__ == '__main__':
    main()
