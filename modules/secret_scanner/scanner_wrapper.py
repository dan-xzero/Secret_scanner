"""
Enhanced Secret Scanner Wrapper

Key improvements:
1. Better tool coordination and parallel execution
2. Enhanced pattern matching with context
3. Improved false positive filtering
4. Better error handling and recovery
5. Detailed finding metadata
6. Enhanced URL mapping from crawler output
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

from loguru import logger


class SecretScanner:
    """Enhanced secret scanner orchestrating multiple tools."""
    
    def __init__(self, config: Dict, logger=None):
        """
        Initialize Secret Scanner.
        
        Args:
        config: Configuration dictionary
        logger: Logger instance (loguru logger)
        """
        self.config = config
        self.logger = logger
        
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
        
        # Statistics
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
    
    def _load_url_mappings(self, content_dir: str) -> Dict[str, str]:
        """Load URL mappings from metadata files created by crawler."""
        url_mappings = {}
        content_path = Path(content_dir)
        
        self.logger.info(f"Loading URL mappings from {content_path}")
        
        # First, check if the crawler created a file_to_url_mappings.json
        mappings_file = content_path / 'file_to_url_mappings.json'
        if mappings_file.exists():
            try:
                with open(mappings_file, 'r') as f:
                    crawler_mappings = json.load(f)
                
                # Add mappings with both relative and absolute paths
                for relative_path, url in crawler_mappings.items():
                    # Store with relative path as-is
                    url_mappings[relative_path] = url
                    
                    # Also store with absolute path
                    absolute_path = str(content_path / relative_path)
                    url_mappings[absolute_path] = url
                    
                    # Also store with just the path relative to content dir
                    # This handles cases where the scanner might have slightly different paths
                    url_mappings[str(Path(relative_path))] = url
                
                self.logger.info(f"Loaded {len(crawler_mappings)} URL mappings from crawler output")
                
            except Exception as e:
                self.logger.error(f"Failed to load crawler mappings: {e}")
        
        # Also check url_mappings.json if it exists
        url_mappings_file = content_path / 'url_mappings.json'
        if url_mappings_file.exists():
            try:
                with open(url_mappings_file, 'r') as f:
                    additional_mappings = json.load(f)
                
                # Extract URL to file mappings and reverse them
                if 'urlToFile' in additional_mappings:
                    for url, file_info in additional_mappings['urlToFile'].items():
                        if isinstance(file_info, dict) and 'path' in file_info:
                            file_path = file_info['path']
                            # Store multiple path variations
                            url_mappings[file_path] = url
                            url_mappings[str(Path(file_path))] = url
                            
                            # Also store with absolute path
                            if not file_path.startswith('/'):
                                absolute_path = str(content_path / file_path)
                                url_mappings[absolute_path] = url
                
                self.logger.debug(f"Loaded additional mappings from url_mappings.json")
                
            except Exception as e:
                self.logger.debug(f"Failed to load additional mappings: {e}")
        
        # Fallback: Process individual metadata files if needed
        metadata_dir = content_path / 'metadata'
        if metadata_dir.exists() and len(url_mappings) == 0:
            self.logger.info("No crawler mappings found, falling back to metadata files")
            try:
                for meta_file in metadata_dir.glob('*.json'):
                    try:
                        with open(meta_file, 'r') as f:
                            metadata = json.load(f)
                        
                        url = metadata.get('url', '')
                        if not url:
                            continue
                        
                        # Get base name from metadata file
                        base_name = meta_file.stem
                        
                        # Map HTML files
                        html_file = content_path / 'html' / f"{base_name}.html"
                        if html_file.exists():
                            rel_path = str(html_file.relative_to(content_path))
                            url_mappings[rel_path] = url
                            url_mappings[str(html_file)] = url
                        
                        # Map JS files
                        js_file = content_path / 'js' / f"{base_name}.js"
                        if js_file.exists():
                            rel_path = str(js_file.relative_to(content_path))
                            url_mappings[rel_path] = url
                            url_mappings[str(js_file)] = url
                        
                        # Map JSON files
                        json_file = content_path / 'json' / f"{base_name}.json"
                        if json_file.exists():
                            rel_path = str(json_file.relative_to(content_path))
                            url_mappings[rel_path] = url
                            url_mappings[str(json_file)] = url
                            
                    except Exception as e:
                        self.logger.debug(f"Failed to process metadata file {meta_file}: {e}")
            
            except Exception as e:
                self.logger.error(f"Error processing metadata directory: {e}")
        
        # Process inline scripts metadata files (these might have different naming)
        inline_scripts_dir = content_path / 'inline-scripts'
        if inline_scripts_dir.exists():
            try:
                # Check if inline script mappings are already in the main mappings
                inline_mapped = any('inline-scripts/' in path for path in url_mappings)
                
                if not inline_mapped:
                    # Try to find inline script metadata files
                    for meta_file in metadata_dir.glob('*_inline.json'):
                        try:
                            with open(meta_file, 'r') as f:
                                metadata = json.load(f)
                            
                            source_url = metadata.get('url', '')
                            if source_url:
                                # Look for corresponding inline script files
                                base_name = meta_file.stem.replace('_inline', '')
                                for js_file in inline_scripts_dir.glob(f"{base_name}_inline_*.js"):
                                    rel_path = str(js_file.relative_to(content_path))
                                    # Extract index from filename
                                    index_match = re.search(r'_inline_(\d+)\.js$', js_file.name)
                                    if index_match:
                                        index = index_match.group(1)
                                        inline_url = f"{source_url}#inline-script-{index}"
                                        url_mappings[rel_path] = inline_url
                                        url_mappings[str(js_file)] = inline_url
                        
                        except Exception as e:
                            self.logger.debug(f"Failed to process inline metadata {meta_file}: {e}")
                            
            except Exception as e:
                self.logger.debug(f"Error processing inline scripts: {e}")
        
        self.logger.info(f"Total URL mappings loaded: {len(url_mappings)}")
        
        # Debug: log a few sample mappings
        if url_mappings:
            samples = list(url_mappings.items())[:5]
            for file_path, url in samples:
                self.logger.debug(f"Sample mapping: {file_path} -> {url}")
        
        return url_mappings
    
    def scan_directory(self, directory: str, scan_type: str = 'full') -> List[Dict]:
        """
        Scan a directory for secrets using all enabled tools.
        
        Args:
            directory: Path to directory to scan
            scan_type: Type of scan ('full', 'quick', 'custom')
            
        Returns:
            List of found secrets
        """
        self.logger.info(f"Starting {scan_type} secret scan of directory: {directory}")
        start_time = time.time()
        
        dir_path = Path(directory)
        if not dir_path.exists():
            raise ValueError(f"Directory does not exist: {directory}")
        
        # Load URL mappings first
        url_mappings = self._load_url_mappings(directory)
        
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
        enriched_findings = self._enrich_findings(filtered_findings, directory, url_mappings)
        
        self.stats['secrets_found'] = len(enriched_findings)
        self.stats['scan_duration'] = time.time() - start_time
        self.stats['false_positives_filtered'] = len(unique_findings) - len(filtered_findings)
        
        self.logger.info(
            f"Scan completed in {self.stats['scan_duration']:.2f}s. "
            f"Found {len(enriched_findings)} secrets "
            f"({self.stats['false_positives_filtered']} false positives filtered)"
        )
        
        return enriched_findings
    
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
            
            # Update stats
            self.stats['secret_types'][parsed['type']] += 1
            
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
            
            # Update stats
            self.stats['secret_types'][parsed['type']] += 1
            
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
    
    def _enrich_findings(self, findings: List[Dict], base_directory: str, url_mappings: Dict[str, str] = None) -> List[Dict]:
        """Enhanced enrichment with better URL mapping."""
        enriched = []
        base_path = Path(base_directory)
        
        for finding in findings:
            enriched_finding = finding.copy()
            
            # Add relative path
            try:
                file_path = Path(finding['file'])
                if file_path.is_absolute():
                    enriched_finding['relative_path'] = str(file_path.relative_to(base_path))
                else:
                    enriched_finding['relative_path'] = str(file_path)
            except:
                enriched_finding['relative_path'] = finding['file']
            
            # Enhanced URL mapping
            url = None
            if url_mappings:
                # Try different path variations
                file_str = finding['file']
                relative_path = enriched_finding.get('relative_path', '')
                
                # Normalize paths for comparison
                normalized_paths = [
                    file_str,
                    relative_path,
                    str(Path(file_str)),
                    str(Path(relative_path))
                ]
                
                # Also try without leading directory components
                if '/' in relative_path:
                    parts = relative_path.split('/')
                    for i in range(len(parts)):
                        normalized_paths.append('/'.join(parts[i:]))
                
                # Check each normalized path
                for path in normalized_paths:
                    if path in url_mappings:
                        url = url_mappings[path]
                        self.logger.debug(f"Found URL mapping for {path}: {url}")
                        break
                
                # If still no URL, try filename matching
                if not url:
                    file_name = Path(file_str).name
                    for mapped_path, mapped_url in url_mappings.items():
                        if Path(mapped_path).name == file_name:
                            url = mapped_url
                            self.logger.debug(f"Found URL by filename {file_name}: {url}")
                            break
            
            # Set URL and source type
            if url:
                enriched_finding['url'] = url
                # Determine if it's an inline script
                if '#inline-script-' in url:
                    enriched_finding['source_type'] = 'inline_script'
                    enriched_finding['parent_url'] = url.split('#')[0]
                else:
                    enriched_finding['source_type'] = 'external_file'
            else:
                self.logger.debug(f"No URL mapping found for: {finding['file']}")
                enriched_finding['url'] = ''
                enriched_finding['source_type'] = 'unknown'
            
            # Add file type
            enriched_finding['file_type'] = Path(finding['file']).suffix.lower()
            
            # Generate unique ID
            enriched_finding['id'] = self._generate_finding_id(enriched_finding)
            
            # Add risk score
            enriched_finding['risk_score'] = self._calculate_risk_score(enriched_finding)
            
            # Ensure metadata includes URL info
            enriched_finding['metadata'] = enriched_finding.get('metadata', {})
            enriched_finding['metadata']['url'] = enriched_finding.get('url', '')
            enriched_finding['metadata']['source_type'] = enriched_finding.get('source_type', 'unknown')
            
            enriched.append(enriched_finding)
        
        # Sort by risk score
        enriched.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return enriched
    
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
    
    def _calculate_risk_score(self, finding: Dict) -> int:
        """Calculate risk score for prioritization."""
        score = 0
        
        # Severity
        severity_scores = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25
        }
        score += severity_scores.get(finding.get('severity', 'low'), 25)
        
        # Confidence
        confidence_scores = {
            'high': 30,
            'medium': 20,
            'low': 10
        }
        score += confidence_scores.get(finding.get('confidence', 'low'), 10)
        
        # Verification
        if finding.get('verified'):
            score += 50
        
        # File type
        high_risk_extensions = ['.js', '.json', '.env', '.config', '.yml', '.yaml']
        if finding.get('file_type') in high_risk_extensions:
            score += 20
        
        # Entropy
        secret = finding.get('raw', '')
        entropy = self._calculate_entropy(secret)
        if entropy > 4.5:
            score += 10
        
        return min(score, 200)  # Cap at 200
    
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
    
    def _generate_finding_id(self, finding: Dict) -> str:
        """Generate unique ID for a finding."""
        # Create stable ID from finding properties
        id_string = f"{finding.get('type')}:{finding.get('file')}:{finding.get('line')}:{finding.get('raw', '')[:20]}"
        return hashlib.sha256(id_string.encode()).hexdigest()[:16]
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics."""
        return {
            **self.stats,
            'scan_rate': f"{self.stats['files_scanned'] / max(self.stats['scan_duration'], 1):.2f} files/sec"
        }