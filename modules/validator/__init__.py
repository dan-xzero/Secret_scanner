#!/usr/bin/env python3
"""
Validator Module for Automated Secrets Scanner
Handles validation of discovered secrets
"""

from .auto_validator import AutoValidator
from .manual_review import ManualReviewInterface
from .baseline_manager import BaselineManager

__all__ = [
    'AutoValidator',
    'ManualReviewInterface',
    'BaselineManager'
]

# Module version
__version__ = '1.0.0'