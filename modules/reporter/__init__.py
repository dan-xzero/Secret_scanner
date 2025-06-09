#!/usr/bin/env python3
"""
Reporter Module for Automated Secrets Scanner
Handles report generation and notifications with database integration
"""

from .html_generator import HTMLReportGenerator
from .slack_notifier import SlackNotifier

__all__ = [
    'HTMLReportGenerator',
    'SlackNotifier'
]

# Module version
__version__ = '2.0.0'  # Updated for database integration

# Export database-aware constructors
def create_html_generator(config, db_path=None):
    """Create HTMLReportGenerator with database support"""
    return HTMLReportGenerator(config, db_path)

def create_slack_notifier(config, db_path=None):
    """Create SlackNotifier with database support"""
    return SlackNotifier(config, db_path)