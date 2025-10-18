"""
Reverse shell listeners
"""
from learnshells.listeners.netcat import NetcatListener
from learnshells.listeners.socat import SocatListener
from learnshells.listeners.metasploit import MetasploitListener

__all__ = [
    "NetcatListener",
    "SocatListener",
    "MetasploitListener",
    "get_listener",
]


def get_listener(listener_type: str):
    """
    Get appropriate listener for type.
    
    Args:
        listener_type: Type of listener (netcat, socat, metasploit)
        
    Returns:
        Listener class (not instance)
    """
    listeners = {
        'netcat': NetcatListener,
        'nc': NetcatListener,
        'ncat': NetcatListener,
        'socat': SocatListener,
        'metasploit': MetasploitListener,
        'msf': MetasploitListener,
        'msfconsole': MetasploitListener,
    }
    
    listener_class = listeners.get(listener_type.lower())
    
    if not listener_class:
        raise ValueError(f"Unknown listener type: {listener_type}")
    
    return listener_class
