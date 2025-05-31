#!/usr/bin/env python3
"""
Reporter Module for Automated Secrets Scanner
Handles report generation and notifications
"""

from .html_generator import HTMLReportGenerator
from .slack_notifier import SlackNotifier

__all__ = [
    'HTMLReportGenerator',
    'SlackNotifier'
]

# Module version
__version__ = '1.0.0'