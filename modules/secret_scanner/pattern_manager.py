#!/usr/bin/env python3
"""
Pattern Manager for Secret Scanner
Handles loading, converting, and managing regex patterns for secret detection
"""

import os
import re
import json
import yaml
import toml
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from loguru import logger

class PatternManager:
    """Manages regex patterns for secret detection across different scanning tools"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Pattern Manager
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.patterns_dir = Path(config.get('patterns_dir', './patterns'))
        self.custom_patterns_file = self.patterns_dir / 'custom_patterns.yaml'
        self.compiled_patterns_dir = self.patterns_dir / 'compiled_patterns'
        
        # Create directories if they don't exist
        self.patterns_dir.mkdir(parents=True, exist_ok=True)
        self.compiled_patterns_dir.mkdir(parents=True, exist_ok=True)
        
        # Pattern storage
        self.patterns = {
            'custom': [],
            'secrets_patterns_db': [],
            'builtin': []
        }
        
        # Pattern statistics
        self.stats = {
            'total_patterns': 0,
            'custom_patterns': 0,
            'db_patterns': 0,
            'builtin_patterns': 0,
            'conversion_errors': [],
            'validation_errors': []
        }
        
        logger.info(f"Pattern Manager initialized with patterns directory: {self.patterns_dir}")
    
    def load_all_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load patterns from all sources
        
        Returns:
            Dictionary of patterns organized by source
        """
        try:
            # Load custom patterns
            self._load_custom_patterns()
            
            # Load patterns from secrets-patterns-db
            self._load_secrets_patterns_db()
            
            # Load built-in patterns
            self._load_builtin_patterns()
            
            # Update statistics
            self._update_statistics()
            
            logger.info(f"Loaded {self.stats['total_patterns']} total patterns")
            logger.info(f"Custom: {self.stats['custom_patterns']}, "
                       f"DB: {self.stats['db_patterns']}, "
                       f"Built-in: {self.stats['builtin_patterns']}")
            
            return self.patterns
            
        except Exception as e:
            logger.error(f"Error loading patterns: {e}")
            logger.exception(e)
            return self.patterns
    
    def _load_custom_patterns(self) -> None:
        """Load custom patterns from YAML file"""
        try:
            if self.custom_patterns_file.exists():
                with open(self.custom_patterns_file, 'r') as f:
                    custom_data = yaml.safe_load(f) or {}
                
                patterns = custom_data.get('patterns', [])
                for pattern in patterns:
                    if self._validate_pattern(pattern):
                        self.patterns['custom'].append(pattern)
                
                logger.info(f"Loaded {len(self.patterns['custom'])} custom patterns")
            else:
                logger.warning(f"Custom patterns file not found: {self.custom_patterns_file}")
                
        except Exception as e:
            logger.error(f"Error loading custom patterns: {e}")
            self.stats['validation_errors'].append({
                'source': 'custom_patterns',
                'error': str(e)
            })
    
    def _load_secrets_patterns_db(self) -> None:
        """Load patterns from secrets-patterns-db repository"""
        try:
            db_path = self.patterns_dir / 'secrets-patterns-db' / 'db'
            if not db_path.exists():
                logger.warning("secrets-patterns-db not found. Clone from: "
                             "https://github.com/mazen160/secrets-patterns-db")
                return
            
            # Load rules-stable.yml
            stable_rules_file = db_path / 'rules-stable.yml'
            if stable_rules_file.exists():
                with open(stable_rules_file, 'r') as f:
                    db_data = yaml.safe_load(f) or {}
                
                patterns = db_data.get('patterns', [])
                for pattern in patterns:
                    if self._validate_pattern(pattern):
                        self.patterns['secrets_patterns_db'].append(pattern)
                
                logger.info(f"Loaded {len(self.patterns['secrets_patterns_db'])} patterns from secrets-patterns-db")
            
        except Exception as e:
            logger.error(f"Error loading secrets-patterns-db: {e}")
            self.stats['validation_errors'].append({
                'source': 'secrets_patterns_db',
                'error': str(e)
            })
    
    def _load_builtin_patterns(self) -> None:
        """Load built-in patterns for common secret types"""
        try:
            builtin_patterns = [
                {
                    'id': 'aws_access_key',
                    'name': 'AWS Access Key',
                    'pattern': r'(?i)AKIA[0-9A-Z]{16}',
                    'confidence': 'high',
                    'keywords': ['aws', 'access', 'key']
                },
                {
                    'id': 'aws_secret_key',
                    'name': 'AWS Secret Key',
                    'pattern': r'(?i)(?:aws|amazon).*(?:secret|key).*[\'\"\\s]*([A-Za-z0-9/+=]{40})[\'\"\\s]*',
                    'confidence': 'medium',
                    'keywords': ['aws', 'secret', 'key']
                },
                {
                    'id': 'github_token',
                    'name': 'GitHub Personal Access Token',
                    'pattern': r'ghp_[0-9a-zA-Z]{36}',
                    'confidence': 'high',
                    'keywords': ['github', 'token']
                },
                {
                    'id': 'slack_webhook',
                    'name': 'Slack Webhook',
                    'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9]{8,}/B[a-zA-Z0-9]{8,}/[a-zA-Z0-9]{24,}',
                    'confidence': 'high',
                    'keywords': ['slack', 'webhook']
                },
                {
                    'id': 'google_api_key',
                    'name': 'Google API Key',
                    'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
                    'confidence': 'high',
                    'keywords': ['google', 'api', 'key']
                },
                {
                    'id': 'private_key_header',
                    'name': 'Private Key Header',
                    'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
                    'confidence': 'high',
                    'keywords': ['private', 'key', 'begin']
                },
                {
                    'id': 'jwt_token',
                    'name': 'JWT Token',
                    'pattern': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
                    'confidence': 'high',
                    'keywords': ['jwt', 'token']
                }
            ]
            
            for pattern in builtin_patterns:
                if self._validate_pattern(pattern):
                    self.patterns['builtin'].append(pattern)
            
            logger.info(f"Loaded {len(self.patterns['builtin'])} built-in patterns")
            
        except Exception as e:
            logger.error(f"Error loading built-in patterns: {e}")
            self.stats['validation_errors'].append({
                'source': 'builtin_patterns',
                'error': str(e)
            })
    
    def _validate_pattern(self, pattern: Dict[str, Any]) -> bool:
        """
        Validate a pattern dictionary
        
        Args:
            pattern: Pattern dictionary to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Required fields
            required_fields = ['id', 'pattern']
            for field in required_fields:
                if field not in pattern:
                    logger.warning(f"Pattern missing required field '{field}': {pattern}")
                    return False
            
            # Validate regex
            try:
                re.compile(pattern['pattern'])
            except re.error as e:
                logger.warning(f"Invalid regex pattern for {pattern['id']}: {e}")
                self.stats['validation_errors'].append({
                    'pattern_id': pattern['id'],
                    'error': f"Invalid regex: {e}"
                })
                return False
            
            # Add defaults for optional fields
            pattern.setdefault('name', pattern['id'])
            pattern.setdefault('confidence', 'medium')
            pattern.setdefault('keywords', [])
            pattern.setdefault('entropy', 0.0)
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating pattern: {e}")
            return False
    
    def convert_to_trufflehog(self, output_file: Optional[Path] = None) -> Dict[str, Any]:
        """
        Convert patterns to TruffleHog format
        
        Args:
            output_file: Optional output file path
            
        Returns:
            TruffleHog configuration dictionary
        """
        try:
            trufflehog_config = {
                'detectors': []
            }
            
            all_patterns = self._get_all_patterns()
            
            for pattern in all_patterns:
                detector = {
                    'name': pattern['name'],
                    'keywords': pattern.get('keywords', []),
                    'regex': {
                        pattern['id']: pattern['pattern']
                    }
                }
                
                # Add verification if available
                if 'verification' in pattern:
                    detector['verify'] = pattern['verification']
                
                trufflehog_config['detectors'].append(detector)
            
            # Save to file if specified
            if output_file:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w') as f:
                    yaml.dump(trufflehog_config, f, default_flow_style=False)
                logger.info(f"Saved TruffleHog config to {output_file}")
            
            return trufflehog_config
            
        except Exception as e:
            logger.error(f"Error converting to TruffleHog format: {e}")
            self.stats['conversion_errors'].append({
                'format': 'trufflehog',
                'error': str(e)
            })
            return {}
    
    def convert_to_gitleaks(self, output_file: Optional[Path] = None) -> Dict[str, Any]:
        """
        Convert patterns to Gitleaks format
        
        Args:
            output_file: Optional output file path
            
        Returns:
            Gitleaks configuration dictionary
        """
        try:
            gitleaks_config = {
                'title': 'Custom Gitleaks Config',
                'rules': []
            }
            
            all_patterns = self._get_all_patterns()
            
            for pattern in all_patterns:
                rule = {
                    'id': pattern['id'],
                    'description': pattern['name'],
                    'regex': pattern['pattern'],
                    'keywords': pattern.get('keywords', [])
                }
                
                # Add entropy if specified
                if pattern.get('entropy', 0) > 0:
                    rule['entropy'] = pattern['entropy']
                
                # Add allowlist if available
                if 'allowlist' in pattern:
                    rule['allowlist'] = pattern['allowlist']
                
                gitleaks_config['rules'].append(rule)
            
            # Save to file if specified
            if output_file:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, 'w') as f:
                    toml.dump(gitleaks_config, f)
                logger.info(f"Saved Gitleaks config to {output_file}")
            
            return gitleaks_config
            
        except Exception as e:
            logger.error(f"Error converting to Gitleaks format: {e}")
            self.stats['conversion_errors'].append({
                'format': 'gitleaks',
                'error': str(e)
            })
            return {}
    
    def _get_all_patterns(self) -> List[Dict[str, Any]]:
        """
        Get all patterns combined and deduplicated
        
        Returns:
            List of unique patterns
        """
        try:
            all_patterns = []
            seen_ids = set()
            
            # Combine patterns in priority order
            for source in ['custom', 'secrets_patterns_db', 'builtin']:
                for pattern in self.patterns[source]:
                    if pattern['id'] not in seen_ids:
                        all_patterns.append(pattern)
                        seen_ids.add(pattern['id'])
            
            return all_patterns
            
        except Exception as e:
            logger.error(f"Error getting all patterns: {e}")
            return []
    
    def has_custom_patterns(self) -> bool:
        """
        Check if custom patterns are available
        
        Returns:
            True if custom patterns exist, False otherwise
        """
        return bool(self.patterns.get('custom', []))
    
    def add_custom_pattern(self, pattern: Dict[str, Any]) -> bool:
        """
        Add a new custom pattern
        
        Args:
            pattern: Pattern dictionary
            
        Returns:
            True if added successfully
        """
        try:
            if not self._validate_pattern(pattern):
                return False
            
            # Check for duplicates
            for existing in self.patterns['custom']:
                if existing['id'] == pattern['id']:
                    logger.warning(f"Pattern with ID '{pattern['id']}' already exists")
                    return False
            
            # Add to custom patterns
            self.patterns['custom'].append(pattern)
            
            # Save to file
            self._save_custom_patterns()
            
            logger.info(f"Added custom pattern: {pattern['id']}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding custom pattern: {e}")
            return False
    
    def _save_custom_patterns(self) -> None:
        """Save custom patterns to file"""
        try:
            custom_data = {
                'patterns': self.patterns['custom']
            }
            
            with open(self.custom_patterns_file, 'w') as f:
                yaml.dump(custom_data, f, default_flow_style=False)
            
            logger.info("Saved custom patterns to file")
            
        except Exception as e:
            logger.error(f"Error saving custom patterns: {e}")
    
    def _update_statistics(self) -> None:
        """Update pattern statistics"""
        self.stats['custom_patterns'] = len(self.patterns['custom'])
        self.stats['db_patterns'] = len(self.patterns['secrets_patterns_db'])
        self.stats['builtin_patterns'] = len(self.patterns['builtin'])
        self.stats['total_patterns'] = len(self._get_all_patterns())
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get pattern statistics
        
        Returns:
            Statistics dictionary
        """
        self._update_statistics()
        return self.stats
    
    def search_patterns(self, query: str) -> List[Dict[str, Any]]:
        """
        Search patterns by keyword or ID
        
        Args:
            query: Search query
            
        Returns:
            List of matching patterns
        """
        try:
            query_lower = query.lower()
            results = []
            
            for pattern in self._get_all_patterns():
                # Search in ID, name, and keywords
                if (query_lower in pattern['id'].lower() or
                    query_lower in pattern['name'].lower() or
                    any(query_lower in k.lower() for k in pattern.get('keywords', []))):
                    results.append(pattern)
            
            logger.info(f"Found {len(results)} patterns matching '{query}'")
            return results
            
        except Exception as e:
            logger.error(f"Error searching patterns: {e}")
            return []
    
    def generate_pattern_report(self) -> Dict[str, Any]:
        """
        Generate a report of all loaded patterns
        
        Returns:
            Pattern report dictionary
        """
        try:
            report = {
                'statistics': self.get_statistics(),
                'patterns_by_source': {
                    'custom': len(self.patterns['custom']),
                    'secrets_patterns_db': len(self.patterns['secrets_patterns_db']),
                    'builtin': len(self.patterns['builtin'])
                },
                'patterns_by_confidence': {},
                'top_keywords': {},
                'errors': {
                    'validation': self.stats['validation_errors'],
                    'conversion': self.stats['conversion_errors']
                }
            }
            
            # Count by confidence level
            confidence_counts = {}
            keyword_counts = {}
            
            for pattern in self._get_all_patterns():
                # Confidence
                confidence = pattern.get('confidence', 'unknown')
                confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
                
                # Keywords
                for keyword in pattern.get('keywords', []):
                    keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1
            
            report['patterns_by_confidence'] = confidence_counts
            report['top_keywords'] = dict(sorted(keyword_counts.items(), 
                                               key=lambda x: x[1], 
                                               reverse=True)[:20])
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating pattern report: {e}")
            return {}