#!/usr/bin/env python3
"""Scanner Module"""

from .scanner_wrapper import SecretScanner

__all__ = ['SecretScanner']

def create_scanner(config, db_path=None):
    """Create scanner with database support"""
    return SecretScanner(config, db_path)