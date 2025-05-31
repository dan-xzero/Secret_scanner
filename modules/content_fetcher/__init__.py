"""
Content Fetcher Module

This module handles crawling websites and extracting HTML/JavaScript content
using Crawlee and Playwright for dynamic content rendering.
"""

from .fetcher import ContentFetcher
from .content_organizer import ContentOrganizer
from .static_fetcher import StaticFetcher

__all__ = ['ContentFetcher', 'ContentOrganizer', 'StaticFetcher']

__version__ = '1.0.0'