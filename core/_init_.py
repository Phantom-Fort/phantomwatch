"""
Core Package for PhantomWatch

This package contains essential core functionalities for PhantomWatch, including banners, SOC tips,
and output formatting.
"""

from .banner import display_banner
from .soc_tips import get_random_tips
from .output_formatter import OutputFormatter

__all__ = ["display_banner", "get_random_tips", "OutputFormatter"]
