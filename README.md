# LearnShells

**Educational Reverse Shell Framework for Penetration Testing**

LearnShells is a Python-based framework designed for security professionals, CTF players, and penetration testing students to understand and automate reverse shell exploitation techniques in controlled, authorized environments.

---

## ⚠️ LEGAL DISCLAIMER

**READ THIS CAREFULLY BEFORE USING THIS TOOL**

This software is provided for **educational and authorized security testing purposes only**. Users of this tool must comply with all applicable local, state, national, and international laws. 

### Legal Use Requirements:

- **Written Authorization Required**: You must have explicit, written permission from the system owner before testing any system you do not own.
- **Authorized Environments Only**: Use only on systems you own, systems you have been contracted to test, or authorized CTF/lab environments (HackTheBox, TryHackMe, etc.).
- **No Malicious Use**: This tool must not be used for unauthorized access, data theft, system damage, or any illegal activity.

### User Responsibility:

The developers assume **NO LIABILITY** for misuse of this software. By using LearnShells, you accept full responsibility for your actions and any consequences thereof. Unauthorized access to computer systems is a crime under laws including but not limited to the Computer Fraud and Abuse Act (CFAA) in the United States and similar legislation in other jurisdictions.

**If you do not agree to these terms, do not use this software.**

---

## Overview

LearnShells provides multiple operational modes designed for different skill levels and use cases in authorized penetration testing scenarios. The framework emphasizes education through practical implementation while automating repetitive tasks in ethical hacking workflows.

---

## Features

### Operational Modes

#### Expert Mode (Stable)
- Manual payload generation with granular parameter control
- Support for multiple payload languages: Bash, Python, PHP, PowerShell, Perl, Ruby, Node.js
- Obfuscation and encoding capabilities for evasion testing
- Wrapper integration for various execution contexts
- AMSI bypass techniques for PowerShell payloads
- Display-only output for user control (no automatic execution)

#### Butter Mode (Stable)
- Automated file upload exploitation framework
- Intelligent web form detection and parsing
- Session management with cookie handling
- Automatic discovery of upload endpoints and execution paths
- Filename extension obfuscation (tests multiple variants: .php, .php5, .phtml, etc.)
- Interactive confirmation workflow for exploit verification
- Comprehensive path scanning (60+ common directories)

#### Auto Mode (Work in Progress)
- Automated target reconnaissance
- Vulnerability detection and exploitation
- Currently undergoing development and testing

#### Learn Mode (Work in Progress)
- Educational mode with step-by-step explanations
- Designed for beginners learning penetration testing concepts
- Currently in early development

### Technical Capabilities

- **Payload Generation**: Multiple scripting languages with customizable templates
- **Evasion Techniques**: Code obfuscation, encoding (Base64, URL, Hex), and wrapper functions
- **Network Detection**: Automatic VPN interface detection (tun0/tun1)
- **Session Management**: HTTP session persistence and cookie handling
- **Form Analysis**: BeautifulSoup-based HTML parsing for dynamic form detection

---

## Requirements

### System Requirements
- Python 3.8 or higher
- Linux environment (recommended for optimal functionality)
- Active VPN connection (tun0/tun1 interface) for reverse shell operations

### Python Dependencies
```
requests>=2.31.0
beautifulsoup4>=4.12.0
rich>=13.0.0
click>=8.1.0
lxml>=4.9.0
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/learnshells.git
cd learnshells

# Install dependencies
pip3 install -r requirements.txt

# Run the tool
python3 main.py
```

No installation or setup script required. The tool runs directly from the cloned directory.

---

## Usage

### Interactive Mode (Recommended)
```bash
python3 main.py
```

This launches an interactive menu where you can select operational modes and configure parameters through guided prompts.

### Expert Mode
Expert Mode provides complete manual control over payload generation:

1. Launch LearnShells and select Expert Mode from the menu
2. Configure attack parameters (shell type, obfuscation, encoding)
3. Review generated payload variants
4. Copy payload for manual execution in your testing environment
5. Start listener separately: `nc -lvnp <port>`

**Note**: Expert Mode does not automatically execute payloads. You maintain full control over exploitation timing and delivery method.

### Butter Mode
Butter Mode automates file upload exploitation:

1. Select Butter Mode from the main menu
2. Choose attack type (file upload, command execution, or auto-detect)
3. Provide target URL and credentials (if required)
4. Configure evasion options (obfuscation, wrappers, encoding)
5. The tool will scan for upload forms and execution paths
6. Select filename extensions to test
7. Confirm each exploitation attempt interactively

**Workflow**: Butter Mode establishes sessions, parses forms dynamically, and attempts uploads with user-selected extensions. All exploitation attempts require user confirmation before execution.

---

## Project Structure

```
learnshells/
├── main.py                          # Entry point
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
│
└── learnshells/                     # Main package
    ├── __init__.py
    │
    ├── core/                        # Core functionality
    │   ├── __init__.py
    │   ├── detector.py              # Target detection
    │   ├── port_tester.py           # Port testing utilities
    │   ├── payload_selector.py      # Payload selection logic
    │   ├── interface_detector.py    # Network interface detection
    │   └── connectivity_tester.py   # Connectivity testing
    │
    ├── generators/                  # Payload generators
    │   ├── __init__.py
    │   ├── base.py                  # Base classes
    │   ├── bash.py                  # Bash reverse shells
    │   ├── python.py                # Python reverse shells
    │   ├── php.py                   # PHP reverse shells
    │   ├── powershell.py            # PowerShell reverse shells
    │   ├── perl.py                  # Perl reverse shells
    │   ├── ruby.py                  # Ruby reverse shells
    │   ├── nodejs.py                # Node.js reverse shells
    │   └── monkeyphp.php            # PentestMonkey PHP shell template
    │
    ├── listeners/                   # Shell listeners
    │   ├── __init__.py
    │   ├── netcat.py                # Netcat listener
    │   ├── socat.py                 # Socat listener
    │   └── metasploit.py            # Metasploit handler
    │
    ├── stabilizers/                 # Post-exploitation
    │   ├── __init__.py
    │   ├── tty_upgrade.py           # TTY upgrade techniques
    │   ├── persistence.py           # Persistence mechanisms
    │   └── recovery.py              # Shell recovery
    │
    ├── evasion/                     # Evasion techniques
    │   ├── __init__.py
    │   ├── amsi_bypass.py           # AMSI bypass (Windows)
    │   ├── obfuscator.py            # Code obfuscation
    │   ├── wrappers.py              # Execution wrappers
    │   └── encoding.py              # Encoding methods
    │
    ├── modes/                       # Operational modes
    │   ├── __init__.py
    │   ├── learn_mode.py            # Educational mode (WIP)
    │   ├── auto_mode.py             # Automated exploitation (WIP)
    │   ├── butter_mode.py           # Automated file upload
    │   └── expert_mode.py           # Manual payload generation
    │
    ├── ui/                          # User interface components
    │   ├── __init__.py
    │   ├── tui_dashboard.py         # TUI dashboard
    │   ├── banner.py                # ASCII banners
    │   └── colors.py                # Color schemes
    │
    └── utils/                       # Utility functions
        ├── __init__.py
        ├── network.py               # Network utilities
        ├── validator.py             # Input validation
        └── logger.py                # Logging functionality
```

---

### Current Limitations

1. **Platform Support**: Optimized for Linux environments. Windows and macOS functionality may vary.
2. **Web Application Compatibility**: Butter Mode's form parser handles standard HTML forms. Complex JavaScript-based upload mechanisms may not be detected.
3. **WAF Detection**: No built-in Web Application Firewall detection or bypass capabilities.
4. **Incomplete Modes**: Auto Mode and Learn Mode are marked as work-in-progress and have limited functionality.

### Known Issues

- Session handling may fail on applications with non-standard cookie implementations
- Path scanning uses a predefined wordlist; custom paths may require manual specification
- Some obfuscation techniques may be flagged by modern endpoint detection systems

---

## Development Status

**Current Version**: 1.0 Beta

**Stable Features**:
- ✅ Expert Mode (payload generation)
- ✅ Butter Mode (file upload exploitation)
- ✅ Multi-language payload support
- ✅ Evasion module (obfuscation, encoding, wrappers)

**In Development**:
- 🚧 Auto Mode (automated reconnaissance)
- 🚧 Learn Mode (educational content)
- 🚧 WAF detection and bypass suggestions
- 🚧 ASPX and JSP payload support

---

## Contributing

Contributions are welcome from the security research community. Please ensure all contributions:

1. Maintain the educational focus of the project
2. Include appropriate documentation
3. Do not introduce functionality that encourages illegal use
4. Follow responsible disclosure practices

---

## Ethical Use Guidelines

### Authorized Testing Environments

**Recommended Platforms**:
- HackTheBox (https://hackthebox.eu)
- TryHackMe (https://tryhackme.com)
- PentesterLab (https://pentesterlab.com)
- CTF competitions with explicit permissions
- Personal lab environments
- Contracted penetration testing engagements with written authorization

### Prohibited Uses

**DO NOT USE** for:
- Unauthorized system access or testing
- Malicious activities or criminal purposes
- Testing systems without explicit written permission
- Competitive intelligence gathering
- Any activity violating local, national, or international law

---

## Technical Support

This is an educational project with no warranty or guarantee of fitness for any purpose. Users are expected to have a foundational understanding of:

- Penetration testing methodologies
- Network protocols and concepts
- Python programming basics
- Linux command line operations
- Web application security fundamentals

For bug reports or feature requests, please use the GitHub Issues tracker with detailed information about your environment and the issue encountered.

---

## References and Credits

### Inspiration and Resources

- PentestMonkey's PHP Reverse Shell (http://pentestmonkey.net/tools/web-shells/php-reverse-shell)
- OWASP Testing Guide (https://owasp.org/www-project-web-security-testing-guide/)
- CTF community best practices and techniques

### Educational Resources

For those learning penetration testing, we recommend:
- OWASP WebGoat for web application security
- OverTheWire wargames for Linux fundamentals
- Offensive Security training materials
- SANS SEC560 course materials

---

## License

[Choose appropriate license: GPL-3.0, MIT, or Apache-2.0]

This project is provided as-is for educational purposes. See LICENSE file for details.

---

## Final Notice

**Remember**: Knowledge of exploitation techniques is a powerful tool that must be used responsibly. The cybersecurity community operates on principles of responsible disclosure, ethical behavior, and respect for others' systems and data. Use this knowledge to defend systems, not to harm them.

**Always obtain proper authorization before testing any system you do not own.**

---

**Version**: 0.1.0-beta    
**Status**: Active Development
