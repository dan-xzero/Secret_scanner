"""
Secret Scanner Module

This module handles scanning content for secrets using various tools:
- TruffleHog
- Gitleaks
- Custom pattern matching
"""

from .scanner_wrapper import SecretScanner
from .pattern_manager import PatternManager
from .result_parser import ResultParser

__all__ = ['SecretScanner', 'PatternManager', 'ResultParser']

__version__ = '1.0.0'