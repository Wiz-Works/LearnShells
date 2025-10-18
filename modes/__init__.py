"""
Different operation modes for LearnShells
"""

from learnshells.modes.learn_mode import LearnMode
from learnshells.modes.auto_mode import AutoMode
from learnshells.modes.butter_mode import ButterMode
from learnshells.modes.expert_mode import ExpertMode

__all__ = [
    "LearnMode",
    "AutoMode",
    "ButterMode",
    "ExpertMode",
]


# Mode factory
def get_mode(mode_type: str, logger=None):
    """
    Get appropriate mode for type.
    
    Args:
        mode_type: Type of mode (learn, auto, butter, expert)
        logger: Logger instance
        
    Returns:
        Mode instance
    """
    modes = {
        'learn': LearnMode,
        'auto': AutoMode,
        'butter': ButterMode,
        'expert': ExpertMode,
    }
    
    mode_class = modes.get(mode_type.lower())
    
    if not mode_class:
        raise ValueError(f"Unknown mode type: {mode_type}")
    
    return mode_class(logger=logger)
