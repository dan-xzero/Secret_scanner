"""
URL Discovery Module

This module handles discovering all URLs associated with target domains
using various passive reconnaissance tools.
"""

from .discovery import URLDiscovery
from .deduplicator import URLDeduplicator

__all__ = ['URLDiscovery', 'URLDeduplicator']

__version__ = '1.0.0'