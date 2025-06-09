"""
Enhanced Secret Scanner Wrapper with Database Integration

Key improvements:
1. Database-centric architecture for findings storage
2. Better tool coordination and parallel execution
3. Enhanced pattern matching with context
4. Improved false positive filtering
5. Better error handling and recovery
6. Detailed finding metadata with URL mapping from database
"""

import os
import subprocess
import json
import tempfile
import time
import concurrent.futures
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
import logging
import re
from collections import defaultdict
import hashlib
import math
import sqlite3
from datetime import datetime

from loguru import logger


class SecretScanner:
    """Enhanced secret scanner orchestrating multiple tools with database integration."""
    
    def __init__(self, config: Dict, db_manager=None, logger=None):
        """
        Initialize Secret Scanner.
        
        Args:
            config: Configuration dictionary
            db_manager: DatabaseManager instance
            logger: Logger instance (loguru logger)
        """
        self.config = config
        self.logger = logger
        self.db = db_manager
        
        # Tool configurations
        self.enable_trufflehog = config.get('enable_trufflehog', True)
        self.enable_gitleaks = config.get('enable_gitleaks', True)
        self.enable_custom_patterns = config.get('enable_custom_patterns', True)

            
        # Configuration paths
        self.trufflehog_config = config.get('trufflehog_config_path')
        self.gitleaks_config = config.get('gitleaks_config_path')
        self.custom_patterns_path = config.get('custom_patterns_path')
        
        # Scanning settings
        self.scan_timeout = min(config.get('scan_timeout', 36000), 86400)
        if self.scan_timeout > 86400:  # More than 24 hours
            self.logger.warning(f"Scan timeout {self.scan_timeout}s is too large, setting to 24 hours")
            self.scan_timeout = 86400
        self.max_file_size = config.get('scan_file_size_limit', 10 * 1024 * 1024)
        self.entropy_threshold = config.get('entropy_threshold', 4.0)
        self.min_secret_length = config.get('min_secret_length', 8)
        self.max_secret_length = config.get('max_secret_length', 1000)
        self.scan_file_extensions = set(config.get('scan_file_extensions', [
            '.js', '.json', '.html', '.xml', '.yml', '.yaml', '.env', '.config',
            '.properties', '.ini', '.conf', '.cfg', '.txt', '.md'
        ]))
        
        # False positive filters
        self.false_positive_patterns = self._compile_false_positive_patterns()
        self.common_false_positives = self._load_common_false_positives()
        
        # Custom patterns
        self.custom_patterns = self._load_custom_patterns()
        
        # Validate tools
        self._validate_tools()
        
        # Current scan run ID (set during scan)
        self.current_scan_run_id = None
        
        # Statistics (will be stored in database)
        self.stats = {
            'files_scanned': 0,
            'files_skipped': 0,
            'secrets_found': 0,
            'false_positives_filtered': 0,
            'scan_duration': 0,
            'tool_results': defaultdict(int),
            'secret_types': defaultdict(int),
            'errors': []
        }
    
    def _validate_tools(self):
        """Validate that required scanning tools are installed."""
        missing_tools = []
        
        if self.enable_trufflehog and not self._check_tool_exists('trufflehog'):
            missing_tools.append('trufflehog')
            self.enable_trufflehog = False
        
        if self.enable_gitleaks and not self._check_tool_exists('gitleaks'):
            missing_tools.append('gitleaks')
            self.enable_gitleaks = False
        
        if missing_tools:
            self.logger.warning(f"Missing scanning tools: {', '.join(missing_tools)}")
            self.logger.warning("Some scanning methods will be disabled")
        
        if not self.enable_trufflehog and not self.enable_gitleaks and not self.enable_custom_patterns:
            raise RuntimeError("No scanning methods available. Please install TruffleHog or Gitleaks.")
    
    def _check_tool_exists(self, tool: str) -> bool:
        """Check if a tool exists in PATH."""
        try:
            result = subprocess.run(
                ['which', tool],
                capture_output=True,
                check=False
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _compile_false_positive_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for false positive detection."""
        patterns = [
            # All same character
            r'^(.)\1+$',
            # Common placeholders
            r'^(example|test|demo|sample|dummy|fake|mock|placeholder)',
            r'^xxx+$',
            r'^<[^>]+>$',
            r'^\$\{[^}]+\}$',
            r'^%\([^)]+\)s$',
            # Common non-secret patterns
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',  # UUID
            r'^[0-9]{4}-[0-9]{2}-[0-9]{2}',  # Dates
            r'^(true|false|null|undefined)$',
            # Base64 encoded common strings
            r'^(ZXhhbXBsZQ==|dGVzdA==|cGFzc3dvcmQ=|YWRtaW4=)$',
            # Version strings
            r'^\d+\.\d+\.\d+',
            # Common hashes that aren't secrets
            r'^[a-f0-9]{32}$',  # MD5 of common strings
            r'^da39a3ee5e6b4b0d3255bfef95601890afd80709$',  # SHA1 of empty string
        ]
        
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                self.logger.warning(f"Invalid false positive pattern '{pattern}': {e}")
        
        return compiled
    
    def _load_common_false_positives(self) -> Set[str]:
        """Load common false positive strings."""
        return {
            # Common example API keys
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'your-api-key-here',
            'your_api_key',
            'YOUR_API_KEY',
            'api_key_here',
            'insert_your_api_key',
            # Common passwords
            'password',
            'password123',
            'admin',
            'administrator',
            'changeme',
            'default',
            # Encoded common strings
            'dGVzdA==',  # 'test' in base64
            'cGFzc3dvcmQ=',  # 'password' in base64
            # Common tokens
            'xxxxxxxxxxxxxxxxxxxxxx',
            '0000000000000000000000',
            '1111111111111111111111',
            'aaaaaaaaaaaaaaaaaaaaaa',
        }
    
    def _load_custom_patterns(self) -> Dict[str, Dict]:
        """Load custom regex patterns."""
        patterns = {}
        
        # Default custom patterns
        default_patterns = {
            'generic_api_key': {
                'pattern': r'(?i)(?:api[_\-\s]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                'confidence': 'medium',
                'severity': 'high'
            },
            'generic_secret': {
                'pattern': r'(?i)(?:secret|token|password|passwd|pwd)["\']?\s*[:=]\s*["\']([^\s"\']{8,})["\']',
                'confidence': 'low',
                'severity': 'high'
            },
            'aws_access_key': {
                'pattern': r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
                'confidence': 'high',
                'severity': 'critical'
            },
            'private_key_header': {
                'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
                'confidence': 'high',
                'severity': 'critical'
            },
            'jwt_token': {
                'pattern': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                'confidence': 'high',
                'severity': 'high'
            },
            'slack_webhook': {
                'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
                'confidence': 'high',
                'severity': 'medium'
            },
            'google_api_key': {
                'pattern': r'AIza[0-9A-Za-z\-_]{35}',
                'confidence': 'high',
                'severity': 'high'
            },
            'github_token': {
                'pattern': r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}',
                'confidence': 'high',
                'severity': 'critical'
            }
        }
        
        # Load from file if specified
        if self.custom_patterns_path and Path(self.custom_patterns_path).exists():
            try:
                with open(self.custom_patterns_path, 'r') as f:
                    loaded_patterns = json.load(f)
                    patterns.update(loaded_patterns)
            except Exception as e:
                self.logger.error(f"Failed to load custom patterns: {e}")
        
        # Compile patterns
        for name, config in default_patterns.items():
            if name not in patterns:
                patterns[name] = config
            
            # Compile regex
            try:
                patterns[name]['compiled'] = re.compile(config['pattern'])
            except re.error as e:
                self.logger.error(f"Invalid pattern '{name}': {e}")
                del patterns[name]
        
        return patterns
    
    def _get_url_for_file(self, file_path: str, base_directory: str) -> Optional[str]:
        """Get URL for a file from the database with improved JS chunk mapping."""
        if not self.db:
            return None

        try:
            # Get the scan_id from the base directory or use the current scan run ID
            if self.current_scan_run_id:
                scan_id = self.current_scan_run_id
            else:
                # base_directory is like: data/content/scan_20250608_192410_46045
                scan_id = Path(base_directory).name

            # Get just the filename
            filename = Path(file_path).name
            
            # Skip metadata files - they don't have corresponding URLs
            if filename.endswith('_meta.json'):
                logger.debug(f"Skipping metadata file: {filename}")
                return None

            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Method 1: Direct filename match
            cursor.execute("""
                SELECT url FROM urls 
                WHERE scan_id = ? AND file_name = ?
                LIMIT 1
            """, (scan_id, filename))
            
            result = cursor.fetchone()
            if result:
                logger.debug(f"✓ Direct filename match: {filename} -> {result[0]}")
                return result[0]
            
            # Method 2: File path contains filename
            cursor.execute("""
                SELECT url FROM urls 
                WHERE scan_id = ? AND file_path LIKE ?
                LIMIT 1
            """, (scan_id, f'%/{filename}'))
            
            result = cursor.fetchone()
            if result:
                logger.debug(f"✓ File path match: {filename} -> {result[0]}")
                return result[0]
            
            # Method 3: AGGRESSIVE MAPPING FOR JS CHUNKS
            # For files like: 6436-337f484bdaef3a28_f173daa2.js
            if '.js' in filename or filename.endswith('.js'):
                logger.debug(f"🔍 Attempting JS chunk mapping for: {filename}")
                
                # Strategy A: Find the most likely parent page based on domain patterns
                
                # First, try to find checkout.quince.com URLs since many JS chunks seem related to checkout
                if any(term in filename.lower() for term in ['checkout', 'session', 'payment', 'pay']):
                    cursor.execute("""
                        SELECT url FROM urls 
                        WHERE scan_id = ? 
                        AND (
                            url LIKE '%checkout.quince.com%' OR
                            url LIKE '%checkout%' OR
                            url LIKE '%payment%'
                        )
                        ORDER BY CASE 
                            WHEN url LIKE '%checkout.quince.com%' THEN 1
                            WHEN url LIKE '%checkout%' THEN 2
                            ELSE 3
                        END
                        LIMIT 1
                    """, (scan_id,))
                    
                    result = cursor.fetchone()
                    if result:
                        logger.info(f"✓ JS chunk mapped to checkout domain: {filename} -> {result[0]}")
                        return result[0]
                
                # Strategy B: Find main domain pages (like quince.com)
                cursor.execute("""
                    SELECT url FROM urls 
                    WHERE scan_id = ? 
                    AND (
                        url LIKE '%quince.com%' OR
                        url LIKE '%www.quince.com%'
                    )
                    AND url NOT LIKE '%.js%'
                    AND url NOT LIKE '%/js/%'
                    ORDER BY CASE 
                        WHEN url = 'https://www.quince.com/' THEN 1
                        WHEN url = 'http://quince.com/' THEN 2
                        WHEN url LIKE 'https://www.quince.com/%' THEN 3
                        WHEN url LIKE '%quince.com/%' THEN 4
                        ELSE 5 
                    END,
                    LENGTH(url)  -- Prefer shorter URLs (likely main pages)
                    LIMIT 1
                """, (scan_id,))
                
                result = cursor.fetchone()
                if result:
                    logger.info(f"✓ JS chunk mapped to main domain: {filename} -> {result[0]}")
                    return result[0]
                
                # Strategy C: Map to any HTML page as final fallback
                cursor.execute("""
                    SELECT url FROM urls 
                    WHERE scan_id = ? 
                    AND (
                        url LIKE '%.html' OR 
                        (url NOT LIKE '%.%' AND url LIKE '%://%')  -- URLs without extensions
                    )
                    AND url IS NOT NULL
                    AND url != ''
                    ORDER BY CASE 
                        WHEN url LIKE '%index%' THEN 1
                        WHEN url LIKE '%www.%' THEN 2
                        WHEN url LIKE '%checkout%' THEN 3
                        ELSE 4 
                    END,
                    LENGTH(url)
                    LIMIT 1
                """, (scan_id,))
                
                result = cursor.fetchone()
                if result:
                    logger.warning(f"⚠️ JS chunk mapped to fallback HTML: {filename} -> {result[0]}")
                    return result[0]
                
                # Strategy D: ABSOLUTE LAST RESORT - use ANY URL from this scan
                cursor.execute("""
                    SELECT url FROM urls 
                    WHERE scan_id = ? 
                    AND url IS NOT NULL 
                    AND url != ''
                    ORDER BY CASE 
                        WHEN url LIKE '%www.%' THEN 1
                        WHEN url LIKE '%.com/%' THEN 2
                        ELSE 3
                    END
                    LIMIT 1
                """, (scan_id,))
                
                result = cursor.fetchone()
                if result:
                    logger.error(f"🚨 JS chunk mapped to LAST RESORT URL: {filename} -> {result[0]}")
                    return result[0]
            
            # Method 4: For non-JS files, try pattern matching
            else:
                # Extract meaningful parts of filename for search
                base_name = Path(filename).stem
                # Remove common suffixes and prefixes
                clean_name = re.sub(r'[_-][a-f0-9]{8,}$', '', base_name)  # Remove hash suffixes
                clean_name = re.sub(r'^[0-9]+-', '', clean_name)  # Remove number prefixes
                
                if len(clean_name) > 3:  # Only search if we have a meaningful name
                    cursor.execute("""
                        SELECT url FROM urls 
                        WHERE scan_id = ? AND (
                            url LIKE ? OR
                            file_name LIKE ? OR
                            file_path LIKE ?
                        )
                        LIMIT 1
                    """, (scan_id, f'%{clean_name}%', f'%{clean_name}%', f'%{clean_name}%'))
                    
                    result = cursor.fetchone()
                    if result:
                        logger.debug(f"✓ Pattern match for non-JS: {filename} -> {result[0]}")
                        return result[0]
            
            # If we still haven't found a URL, log detailed info for debugging
            logger.warning(f"❌ NO URL MAPPING FOUND for file: {filename}")
            
            # Debug: Show what URLs we DO have in this scan
            cursor.execute("""
                SELECT COUNT(*), MIN(url) as sample_url, MAX(url) as max_url 
                FROM urls 
                WHERE scan_id = ? AND url IS NOT NULL
            """, (scan_id,))
            debug_result = cursor.fetchone()
            if debug_result and debug_result[0] > 0:
                logger.warning(f"Debug: Scan {scan_id} has {debug_result[0]} URLs. Sample: {debug_result[1]}")
            else:
                logger.error(f"Debug: Scan {scan_id} has NO URLs in database!")
            
            return None
                    
        except Exception as e:
            logger.error(f"Failed to get URL for file {file_path}: {e}")
            return None
    
    def scan_directory(self, directory: str, scan_type: str = 'full', scan_run_id: str = None) -> int:
        """
        Scan a directory for secrets using all enabled tools.
        
        Args:
            directory: Path to directory to scan
            scan_type: Type of scan ('full', 'quick', 'custom')
            scan_run_id: Database scan run ID (string)
            
        Returns:
            Number of secrets found
        """
        self.logger.info(f"Starting {scan_type} secret scan of directory: {directory}")
        start_time = time.time()
        
        dir_path = Path(directory)
        if not dir_path.exists():
            raise ValueError(f"Directory does not exist: {directory}")
        
        # Set current scan run ID
        self.current_scan_run_id = scan_run_id
        
        # Count and filter files to scan
        files_to_scan = self._get_files_to_scan(dir_path, scan_type)
        self.stats['files_scanned'] = len(files_to_scan)
        
        self.logger.info(f"Found {len(files_to_scan)} files to scan")
        
        all_findings = []
        
        # Run scanners based on scan type
        if scan_type == 'quick':
            # Quick scan - only custom patterns on priority files
            if self.enable_custom_patterns:
                findings = self._apply_custom_patterns_to_files(files_to_scan[:100])  # Limit files
                all_findings.extend(findings)
        
        elif scan_type == 'custom':
            # Custom patterns only
            if self.enable_custom_patterns:
                findings = self._apply_custom_patterns_to_files(files_to_scan)
                all_findings.extend(findings)
        
        else:  # full scan
            # Run all enabled scanners in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = []
                
                if self.enable_trufflehog:
                    futures.append(
                        executor.submit(self._run_trufflehog, directory)
                    )
                
                if self.enable_gitleaks:
                    futures.append(
                        executor.submit(self._run_gitleaks, directory)
                    )
                
                if self.enable_custom_patterns:
                    futures.append(
                        executor.submit(self._apply_custom_patterns_to_files, files_to_scan)
                    )
                
                # Collect results
                for future in concurrent.futures.as_completed(futures):
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                    except Exception as e:
                        self.logger.error(f"Scanner execution failed: {e}")
                        self.stats['errors'].append({
                            'error': str(e),
                            'timestamp': time.time()
                        })
        
        # Post-process findings
        unique_findings = self._deduplicate_findings(all_findings)
        filtered_findings = self._filter_false_positives(unique_findings)
        
        # Store findings in database
        stored_count = self._store_findings_in_database(filtered_findings, directory)
        
        self.stats['secrets_found'] = stored_count
        self.stats['scan_duration'] = time.time() - start_time
        self.stats['false_positives_filtered'] = len(unique_findings) - len(filtered_findings)
        
        # Update scan statistics in database
        self._update_scan_statistics()
        
        self.logger.info(
            f"Scan completed in {self.stats['scan_duration']:.2f}s. "
            f"Found {stored_count} secrets "
            f"({self.stats['false_positives_filtered']} false positives filtered)"
        )
        
        return stored_count
    
    def _store_findings_in_database(self, findings: List[Dict], base_directory: str) -> int:
        """Store findings in database with deduplication."""
        if not self.db or not findings:
            return 0
        
        stored_count = 0
        
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            for finding in findings:
                try:
                    # Get URL for the file
                    url = self._get_url_for_file(finding['file'], base_directory)
                    
                    # Log URL mapping for debugging
                    if not url:
                        self.logger.debug(f"No URL found for file: {finding['file']}")
                    
                    # Calculate secret hash
                    secret_value = finding.get('raw', '')
                    secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()
                    
                    # Check if secret already exists
                    cursor.execute("""
                        SELECT id FROM secrets WHERE secret_hash = ?
                    """, (secret_hash,))
                    
                    secret_result = cursor.fetchone()
                    
                    if secret_result:
                        secret_id = secret_result[0]
                        # Update last_seen
                        cursor.execute("""
                            UPDATE secrets 
                            SET last_seen = CURRENT_TIMESTAMP 
                            WHERE id = ?
                        """, (secret_id,))
                    else:
                        # Insert new secret with actual value
                        cursor.execute("""
                            INSERT INTO secrets (
                                secret_hash, secret_value, secret_type, detector_name,
                                first_seen, last_seen, is_verified, is_active,
                                severity, confidence
                            ) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?, ?, ?)
                        """, (
                            secret_hash,
                            secret_value,  # Store the actual secret value
                            finding.get('type', 'unknown'),
                            finding.get('detector', 'unknown'),
                            finding.get('verified', False),
                            True,  # is_active
                            finding.get('severity', 'medium'),
                            finding.get('confidence', 'medium')
                        ))
                        secret_id = cursor.lastrowid
                    
                    # Get URL ID if URL exists
                    url_id = None
                    if url:
                        cursor.execute("""
                            SELECT id FROM urls WHERE url = ?
                        """, (url,))
                        url_result = cursor.fetchone()
                        if url_result:
                            url_id = url_result[0]
                    
                    # Check if this specific finding already exists
                    cursor.execute("""
                        SELECT id FROM findings 
                        WHERE secret_id = ? 
                        AND (url_id = ? OR (url_id IS NULL AND ? IS NULL))
                        AND file_path = ?
                        AND line_number = ?
                    """, (secret_id, url_id, url_id, finding.get('file', ''), finding.get('line', 0)))
                    
                    if not cursor.fetchone():
                        # Insert finding
                        cursor.execute("""
                            INSERT INTO findings (
                                secret_id, url_id, line_number, snippet,
                                found_at, scan_run_id, file_path,
                                validation_status, validation_result
                            ) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?)
                        """, (
                            secret_id,
                            url_id,
                            finding.get('line', 0),
                            finding.get('context', '')[:500],  # Limit snippet length
                            self.current_scan_run_id,
                            finding.get('file', ''),
                            'pending',
                            json.dumps({
                                'confidence': finding.get('confidence', 'medium'),
                                'metadata': finding.get('metadata', {})
                            })
                        ))
                        stored_count += 1
                    
                    # Update statistics
                    self.stats['secret_types'][finding.get('type', 'unknown')] += 1
                    
                except Exception as e:
                    self.logger.error(f"Failed to store finding: {e}")
                    conn.rollback()
                    continue
            
            conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store findings in database: {e}")
        
        return stored_count
    
    def _update_scan_statistics(self):
        """Update scan run statistics in database."""
        if not self.db or not self.current_scan_run_id:
            return
        
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Convert tool results and secret types to JSON
            tool_results_json = json.dumps(dict(self.stats['tool_results']))
            secret_types_json = json.dumps(dict(self.stats['secret_types']))
            errors_json = json.dumps(self.stats['errors'])
            
            # Update scan run with additional statistics
            cursor.execute("""
                UPDATE scan_runs 
                SET total_secrets_found = ?,
                    tool_results = ?,
                    secret_types = ?,
                    errors = ?,
                    files_scanned = ?,
                    files_skipped = ?,
                    false_positives_filtered = ?
                WHERE id = ?
            """, (
                self.stats['secrets_found'],
                tool_results_json,
                secret_types_json,
                errors_json,
                self.stats['files_scanned'],
                self.stats['files_skipped'],
                self.stats['false_positives_filtered'],
                self.current_scan_run_id
            ))
            
            conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to update scan statistics: {e}")
    
    def _get_files_to_scan(self, directory: Path, scan_type: str) -> List[Path]:
        """Get list of files to scan based on scan type."""
        files_to_scan = []
        priority_files = []
        normal_files = []
        
        # Priority patterns
        priority_patterns = [
            re.compile(r'\.js$', re.IGNORECASE),
            re.compile(r'\.json$', re.IGNORECASE),
            re.compile(r'config', re.IGNORECASE),
            re.compile(r'\.env', re.IGNORECASE),
            re.compile(r'secret', re.IGNORECASE),
            re.compile(r'key', re.IGNORECASE),
            re.compile(r'token', re.IGNORECASE),
            re.compile(r'auth', re.IGNORECASE),
            re.compile(r'api', re.IGNORECASE)
        ]
        
        for file_path in directory.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Skip metadata files
            if file_path.name.endswith('_meta.json'):
                self.stats['files_skipped'] += 1
                continue
            
            # Skip files that are too large
            try:
                if file_path.stat().st_size > self.max_file_size:
                    self.stats['files_skipped'] += 1
                    continue
            except:
                continue
            
            # Check file extension
            if self.scan_file_extensions:
                if not any(str(file_path).endswith(ext) for ext in self.scan_file_extensions):
                    # Check if file name suggests it might contain secrets
                    filename = file_path.name.lower()
                    if not any(pattern in filename for pattern in ['config', 'secret', 'key', 'env']):
                        self.stats['files_skipped'] += 1
                        continue
            
            # Categorize files
            is_priority = any(pattern.search(str(file_path)) for pattern in priority_patterns)
            
            if is_priority:
                priority_files.append(file_path)
            else:
                normal_files.append(file_path)
        
        # Order files based on scan type
        if scan_type == 'quick':
            # Only scan priority files in quick mode
            files_to_scan = priority_files[:200]  # Limit to 200 files
        else:
            # Scan priority files first, then normal files
            files_to_scan = priority_files + normal_files
        
        return files_to_scan
    
    def _run_trufflehog(self, directory: str) -> List[Dict]:
        """Run TruffleHog scanner."""
        self.logger.info("Running TruffleHog scanner...")
        
        findings = []
        
        try:
            # Prepare command
            cmd = [
                'trufflehog',
                'filesystem',
                directory,
                '--json',
                '--no-update',
                '--concurrency', str(self.config.get('concurrent_requests', 5))
            ]
            
            # Add config file if exists
            if self.trufflehog_config and Path(self.trufflehog_config).exists():
                cmd.extend(['--config', self.trufflehog_config])
            
            # Add verification if enabled
            if self.config.get('verify_secrets', False):
                cmd.append('--only-verified')
            
            # Run TruffleHog
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Process output line by line
            for line in process.stdout:
                if line.strip():
                    try:
                        finding = json.loads(line)
                        parsed = self._parse_trufflehog_finding(finding)
                        if parsed:
                            findings.append(parsed)
                            self.stats['tool_results']['trufflehog'] += 1
                    except json.JSONDecodeError:
                        pass
            
            # Wait for completion
            process.wait(timeout=self.scan_timeout)
            
            if process.returncode != 0:
                stderr = process.stderr.read()
                if stderr and 'warn' not in stderr.lower():
                    self.logger.warning(f"TruffleHog stderr: {stderr}")
            
            self.logger.info(f"TruffleHog found {len(findings)} potential secrets")
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"TruffleHog timed out after {self.scan_timeout}s")
            process.kill()
        except Exception as e:
            self.logger.error(f"TruffleHog execution failed: {e}")
            self.stats['errors'].append({
                'tool': 'trufflehog',
                'error': str(e)
            })
        
        return findings
    
    def _run_gitleaks(self, directory: str) -> List[Dict]:
        """Run Gitleaks scanner."""
        self.logger.info("Running Gitleaks scanner...")
        
        findings = []
        
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name
            
            # Prepare command
            cmd = [
                'gitleaks',
                'detect',
                '--source', directory,
                '--no-git',
                '--report-format', 'json',
                '--report-path', output_file,
                '--verbose'
            ]
            
            # Add config file if exists
            if self.gitleaks_config and Path(self.gitleaks_config).exists():
                cmd.extend(['--config', self.gitleaks_config])
            
            # Run Gitleaks
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.scan_timeout
            )
            
            # Gitleaks returns non-zero if secrets found
            if Path(output_file).exists():
                with open(output_file, 'r') as f:
                    try:
                        gitleaks_results = json.load(f)
                        
                        # Handle both array and object formats
                        if isinstance(gitleaks_results, list):
                            results_list = gitleaks_results
                        elif isinstance(gitleaks_results, dict) and 'findings' in gitleaks_results:
                            results_list = gitleaks_results['findings']
                        else:
                            results_list = []
                        
                        for finding in results_list:
                            parsed = self._parse_gitleaks_finding(finding)
                            if parsed:
                                findings.append(parsed)
                                self.stats['tool_results']['gitleaks'] += 1
                                
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Failed to parse Gitleaks output: {e}")
                
                # Clean up
                os.unlink(output_file)
            
            self.logger.info(f"Gitleaks found {len(findings)} potential secrets")
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Gitleaks timed out after {self.scan_timeout}s")
        except Exception as e:
            self.logger.error(f"Gitleaks execution failed: {e}")
            self.stats['errors'].append({
                'tool': 'gitleaks',
                'error': str(e)
            })
        finally:
            # Ensure cleanup
            if 'output_file' in locals() and Path(output_file).exists():
                try:
                    os.unlink(output_file)
                except:
                    pass
        
        return findings
    
    def _apply_custom_patterns_to_files(self, files: List[Path]) -> List[Dict]:
        """Apply custom patterns to specific files."""
        self.logger.info(f"Applying custom patterns to {len(files)} files...")
        
        findings = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.get('concurrent_requests', 5)) as executor:
            future_to_file = {
                executor.submit(self._scan_file_with_patterns, file): file
                for file in files
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_findings = future.result()
                    findings.extend(file_findings)
                    if file_findings:
                        self.stats['tool_results']['custom_patterns'] += len(file_findings)
                except Exception as e:
                    self.logger.debug(f"Failed to scan {file_path}: {e}")
        
        self.logger.info(f"Custom patterns found {len(findings)} potential secrets")
        return findings
    
    def _scan_file_with_patterns(self, file_path: Path) -> List[Dict]:
        """Scan a single file with custom patterns."""
        findings = []
        
        try:
            # Read file content
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Apply each pattern
            for pattern_name, pattern_config in self.custom_patterns.items():
                if 'compiled' not in pattern_config:
                    continue
                
                regex = pattern_config['compiled']
                
                # Find all matches with context
                for match in regex.finditer(content):
                    # Get line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Extract secret (use first group if available)
                    if match.groups():
                        secret = match.group(1)
                    else:
                        secret = match.group(0)
                    
                    # Get context
                    lines = content.splitlines()
                    line_idx = line_num - 1
                    context_start = max(0, line_idx - 2)
                    context_end = min(len(lines), line_idx + 3)
                    context_lines = lines[context_start:context_end]
                    
                    # Create finding
                    finding = {
                        'detector': 'custom_pattern',
                        'type': pattern_name,
                        'file': str(file_path),
                        'line': line_num,
                        'column': match.start() - content.rfind('\n', 0, match.start()),
                        'raw': secret,
                        'redacted': self._redact_secret(secret),
                        'verified': False,
                        'confidence': pattern_config.get('confidence', 'medium'),
                        'severity': pattern_config.get('severity', 'medium'),
                        'context': '\n'.join(context_lines),
                        'metadata': {
                            'pattern_name': pattern_name,
                            'match_full': match.group(0),
                            'match_start': match.start(),
                            'match_end': match.end()
                        },
                        'timestamp': time.time()
                    }
                    
                    findings.append(finding)
                    
        except Exception as e:
            self.logger.debug(f"Error scanning file {file_path}: {e}")
        
        return findings
    
    def _parse_trufflehog_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse TruffleHog finding into standard format."""
        try:
            # Extract relevant information
            source_metadata = finding.get('SourceMetadata', {})
            data = source_metadata.get('Data', {})
            
            # Get file information
            file_path = data.get('Filesystem', {}).get('file', '')
            if not file_path:
                return None
            
            # Build standardized finding
            parsed = {
                'detector': 'trufflehog',
                'type': finding.get('DetectorName', 'unknown'),
                'file': file_path,
                'line': data.get('Filesystem', {}).get('line', 0),
                'column': 0,
                'raw': finding.get('Raw', ''),
                'redacted': finding.get('Redacted', ''),
                'verified': finding.get('Verified', False),
                'confidence': 'high' if finding.get('Verified') else 'medium',
                'severity': self._calculate_severity(finding),
                'context': '',
                'metadata': {
                    'detector_type': finding.get('DetectorType', ''),
                    'decoder_name': finding.get('DecoderName', ''),
                    'extra_data': finding.get('ExtraData', {}),
                    'source_id': finding.get('SourceID', ''),
                    'source_type': finding.get('SourceType', ''),
                    'source_name': finding.get('SourceName', '')
                },
                'timestamp': time.time()
            }
            
            return parsed
            
        except Exception as e:
            self.logger.debug(f"Failed to parse TruffleHog finding: {e}")
            return None
    
    def _parse_gitleaks_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse Gitleaks finding into standard format."""
        try:
            # Build standardized finding
            parsed = {
                'detector': 'gitleaks',
                'type': finding.get('RuleID', 'unknown'),
                'file': finding.get('File', ''),
                'line': finding.get('StartLine', 0),
                'column': finding.get('StartColumn', 0),
                'raw': finding.get('Secret', ''),
                'redacted': self._redact_secret(finding.get('Secret', '')),
                'verified': False,
                'confidence': self._calculate_confidence(finding),
                'severity': self._calculate_severity_from_rule(finding.get('RuleID', '')),
                'context': finding.get('Match', ''),
                'metadata': {
                    'rule_id': finding.get('RuleID', ''),
                    'description': finding.get('Description', ''),
                    'start_line': finding.get('StartLine', 0),
                    'end_line': finding.get('EndLine', 0),
                    'start_column': finding.get('StartColumn', 0),
                    'end_column': finding.get('EndColumn', 0),
                    'match': finding.get('Match', ''),
                    'commit': finding.get('Commit', ''),
                    'author': finding.get('Author', ''),
                    'email': finding.get('Email', ''),
                    'date': finding.get('Date', ''),
                    'message': finding.get('Message', ''),
                    'tags': finding.get('Tags', []),
                    'fingerprint': finding.get('Fingerprint', '')
                },
                'timestamp': time.time()
            }
            
            return parsed
            
        except Exception as e:
            self.logger.debug(f"Failed to parse Gitleaks finding: {e}")
            return None
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings."""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            # Create unique identifier
            finding_id = (
                finding.get('type', ''),
                finding.get('file', ''),
                finding.get('line', 0),
                finding.get('raw', '')[:50],  # First 50 chars of secret
                finding.get('detector', '')
            )
            
            if finding_id not in seen:
                seen.add(finding_id)
                unique_findings.append(finding)
        
        duplicate_count = len(findings) - len(unique_findings)
        if duplicate_count > 0:
            self.logger.info(f"Removed {duplicate_count} duplicate findings")
        
        return unique_findings
    
    def _filter_false_positives(self, findings: List[Dict]) -> List[Dict]:
        """Filter out false positives."""
        filtered_findings = []
        
        for finding in findings:
            secret = finding.get('raw', '')
            
            # Check against common false positives
            if secret in self.common_false_positives:
                continue
            
            # Check false positive patterns
            if any(pattern.match(secret) for pattern in self.false_positive_patterns):
                continue
            
            # Check length
            if len(secret) < self.min_secret_length or len(secret) > self.max_secret_length:
                continue
            
            # Check entropy (skip for certain types)
            skip_entropy_check = finding.get('type', '').lower() in [
                'private_key', 'certificate', 'jwt', 'url'
            ]
            
            if not skip_entropy_check and self.entropy_threshold > 0:
                entropy = self._calculate_entropy(secret)
                if entropy < self.entropy_threshold:
                    continue
            
            # Additional context-based filtering
            if self._is_likely_false_positive_from_context(finding):
                continue
            
            filtered_findings.append(finding)
        
        return filtered_findings
    
    def _is_likely_false_positive_from_context(self, finding: Dict) -> bool:
        """Check if finding is likely false positive based on context."""
        context = finding.get('context', '').lower()
        file_path = finding.get('file', '').lower()
        
        # Check for test/example files
        if any(indicator in file_path for indicator in ['test', 'example', 'sample', 'mock', 'demo']):
            # Be more strict with test files
            secret = finding.get('raw', '')
            if any(fp in secret.lower() for fp in ['example', 'test', 'demo', 'sample']):
                return True
        
        # Check context for indicators
        false_positive_context = [
            'example', 'sample', 'test', 'demo', 'mock',
            'placeholder', 'your-', 'insert-', 'put-your-',
            'documentation', 'readme'
        ]
        
        if any(indicator in context for indicator in false_positive_context):
            return True
        
        return False
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_count = {}
        for char in text:
            char_count[char] = char_count.get(char, 0) + 1
        
        # Calculate entropy
        length = len(text)
        entropy = 0.0
        
        for count in char_count.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_confidence(self, finding: Dict) -> str:
        """Calculate confidence level for a finding."""
        # Base confidence on various factors
        confidence_score = 0
        
        # Check rule/type
        rule_id = finding.get('RuleID', '').lower()
        high_confidence_rules = ['private-key', 'api-key', 'password', 'token', 'secret', 'aws', 'gcp']
        
        for rule in high_confidence_rules:
            if rule in rule_id:
                confidence_score += 3
                break
        
        # Check secret characteristics
        secret = finding.get('Secret', '')
        
        # Length
        if 20 <= len(secret) <= 100:
            confidence_score += 2
        elif 10 <= len(secret) < 20:
            confidence_score += 1
        
        # Entropy
        entropy = self._calculate_entropy(secret)
        if entropy > 4.5:
            confidence_score += 2
        elif entropy > 3.5:
            confidence_score += 1
        
        # Pattern complexity
        if re.search(r'[a-z]', secret) and re.search(r'[A-Z]', secret) and re.search(r'\d', secret):
            confidence_score += 1
        
        # Determine confidence level
        if confidence_score >= 6:
            return 'high'
        elif confidence_score >= 3:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_severity(self, finding: Dict) -> str:
        """Calculate severity based on secret type and verification status."""
        detector_name = finding.get('DetectorName', '').lower()
        verified = finding.get('Verified', False)
        
        # Critical severity
        critical_types = ['private_key', 'aws', 'gcp', 'azure', 'github', 'gitlab']
        if any(t in detector_name for t in critical_types):
            return 'critical' if verified else 'high'
        
        # High severity
        high_types = ['api_key', 'token', 'password', 'secret']
        if any(t in detector_name for t in high_types):
            return 'high' if verified else 'medium'
        
        # Default
        return 'medium' if verified else 'low'
    
    def _calculate_severity_from_rule(self, rule_id: str) -> str:
        """Calculate severity from rule ID."""
        rule_lower = rule_id.lower()
        
        if any(t in rule_lower for t in ['private-key', 'private_key', 'aws', 'gcp', 'azure']):
            return 'critical'
        elif any(t in rule_lower for t in ['api-key', 'api_key', 'token', 'password']):
            return 'high'
        elif any(t in rule_lower for t in ['secret', 'credential']):
            return 'medium'
        else:
            return 'low'
    
    def _redact_secret(self, secret: str) -> str:
        """Redact a secret for safe display."""
        if not secret:
            return ''
        
        length = len(secret)
        if length <= 8:
            return '*' * length
        elif length <= 20:
            return secret[:3] + '*' * (length - 6) + secret[-3:]
        else:
            return secret[:4] + '*' * 12 + secret[-4:]
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics."""
        return {
            **self.stats,
            'scan_rate': f"{self.stats['files_scanned'] / max(self.stats['scan_duration'], 1):.2f} files/sec"
        }