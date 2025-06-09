#!/usr/bin/env python3
"""Validator Module"""

from .auto_validator import AutoValidator
from .baseline_manager import BaselineManager

__all__ = ['AutoValidator', 'BaselineManager']

def create_validator(config, db_path=None):
    """Create validator with database support"""
    return AutoValidator(config, db_path)

def create_baseline_manager(config, db_path=None):
    """Create baseline manager with database support"""
    return BaselineManager(config, db_path)