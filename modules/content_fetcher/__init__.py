#!/usr/bin/env python3
"""Content Fetcher Module"""

from .fetcher import ContentFetcher
from .static_fetcher import StaticFetcher

__all__ = ['ContentFetcher', 'StaticFetcher']

def create_content_fetcher(config, db_path=None):
    """Create content fetcher with database support"""
    return ContentFetcher(config, db_path)