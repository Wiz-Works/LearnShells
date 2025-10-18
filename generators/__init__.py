"""
Payload generators for different languages and platforms
"""
from learnshells.generators.base import PayloadGenerator, PayloadConfig
from learnshells.generators.bash import BashGenerator
from learnshells.generators.python import Python3Generator, Python2Generator
from learnshells.generators.php import PHPGenerator
from learnshells.generators.powershell import PowerShellGenerator
from learnshells.generators.perl import PerlGenerator
from learnshells.generators.ruby import RubyGenerator
from learnshells.generators.nodejs import NodeJSGenerator

__all__ = [
    "PayloadGenerator",
    "PayloadConfig",
    "BashGenerator",
    "Python3Generator",
    "Python2Generator",
    "PHPGenerator",
    "PowerShellGenerator",
    "PerlGenerator",
    "RubyGenerator",
    "NodeJSGenerator",
    "get_generator",
]


# Payload generator factory
def get_generator(payload_type: str):
    """
    Get appropriate payload generator for type.
    
    Args:
        payload_type: Type of payload (bash, python, php, etc.)
        
    Returns:
        PayloadGenerator class (not instance)
    """
    generators = {
        'bash': BashGenerator,
        'sh': BashGenerator,
        'python': Python3Generator,
        'python3': Python3Generator,
        'python2': Python2Generator,
        'php': PHPGenerator,
        'powershell': PowerShellGenerator,
        'ps': PowerShellGenerator,
        'pwsh': PowerShellGenerator,
        'perl': PerlGenerator,
        'ruby': RubyGenerator,
        'rb': RubyGenerator,
        'nodejs': NodeJSGenerator,
        'node': NodeJSGenerator,
        'javascript': NodeJSGenerator,
        'js': NodeJSGenerator,
    }
    
    generator_class = generators.get(payload_type.lower())
    
    if not generator_class:
        raise ValueError(f"Unknown payload type: {payload_type}")
    
    return generator_class
