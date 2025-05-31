#!/usr/bin/env python3
"""
Result Parser for Secret Scanner
Parses and normalizes output from different secret scanning tools
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from loguru import logger

class ResultParser:
    """Parses and normalizes results from various secret scanning tools"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Result Parser
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.raw_secrets_path = Path(config.get('data_storage_path', './data')) / 'scans' / 'raw'
        self.raw_secrets_path.mkdir(parents=True, exist_ok=True)
        
        # Supported parsers
        self.parsers = {
            'trufflehog': self._parse_trufflehog,
            'gitleaks': self._parse_gitleaks,
            'generic': self._parse_generic
        }
        
        # Statistics
        self.stats = {
            'total_parsed': 0,
            'parse_errors': [],
            'tools_processed': {},
            'findings_by_type': {},
            'findings_by_severity': {}
        }
        
        logger.info(f"Result Parser initialized with raw secrets path: {self.raw_secrets_path}")
    
    def parse_results(self, results_file: Union[str, Path], tool: str) -> List[Dict[str, Any]]:
        """
        Parse results from a scanning tool
        
        Args:
            results_file: Path to results file
            tool: Name of the scanning tool
            
        Returns:
            List of normalized findings
        """
        try:
            results_file = Path(results_file)
            if not results_file.exists():
                logger.error(f"Results file not found: {results_file}")
                return []
            
            logger.info(f"Parsing {tool} results from {results_file}")
            
            # Read results file
            with open(results_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse based on tool
            if tool.lower() in self.parsers:
                findings = self.parsers[tool.lower()](content)
            else:
                logger.warning(f"Unknown tool '{tool}', using generic parser")
                findings = self.parsers['generic'](content)
            
            # Add metadata to each finding
            for finding in findings:
                finding['tool'] = tool
                finding['parsed_at'] = datetime.utcnow().isoformat()
                finding['source_file'] = str(results_file)
            
            # Update statistics
            self._update_statistics(tool, findings)
            
            # Save raw findings
            self._save_raw_findings(findings, tool)
            
            logger.info(f"Parsed {len(findings)} findings from {tool}")
            return findings
            
        except Exception as e:
            logger.error(f"Error parsing results from {tool}: {e}")
            logger.exception(e)
            self.stats['parse_errors'].append({
                'tool': tool,
                'file': str(results_file),
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
            return []
    
    def _parse_trufflehog(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse TruffleHog JSON output
        
        Args:
            content: Raw JSON content
            
        Returns:
            List of normalized findings
        """
        findings = []
        
        try:
            # TruffleHog outputs one JSON object per line
            for line in content.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    result = json.loads(line)
                    
                    # Extract relevant fields
                    finding = {
                        'type': result.get('DetectorName', 'unknown'),
                        'secret': result.get('Raw', ''),
                        'redacted': result.get('Redacted', ''),
                        'verified': result.get('Verified', False),
                        'file_path': None,
                        'line_number': None,
                        'url': None,
                        'confidence': 'high' if result.get('Verified') else 'medium',
                        'severity': self._calculate_severity(result),
                        'metadata': {}
                    }
                    
                    # Extract source metadata
                    source_metadata = result.get('SourceMetadata', {})
                    if source_metadata:
                        data = source_metadata.get('Data', {})
                        
                        # Git source
                        if 'Git' in data:
                            git_data = data['Git']
                            finding['file_path'] = git_data.get('file')
                            finding['line_number'] = git_data.get('line')
                            finding['metadata']['commit'] = git_data.get('commit')
                            finding['metadata']['repository'] = git_data.get('repository')
                        
                        # Filesystem source
                        elif 'Filesystem' in data:
                            fs_data = data['Filesystem']
                            finding['file_path'] = fs_data.get('file')
                            finding['line_number'] = fs_data.get('line')
                        
                        # Web source
                        elif 'Web' in data:
                            web_data = data['Web']
                            finding['url'] = web_data.get('url')
                            finding['metadata']['response_code'] = web_data.get('status_code')
                    
                    # Add extra metadata
                    finding['metadata']['detector_type'] = result.get('DetectorType')
                    finding['metadata']['decoder_name'] = result.get('DecoderName')
                    finding['metadata']['extra_data'] = result.get('ExtraData', {})
                    
                    findings.append(finding)
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse TruffleHog JSON line: {e}")
                    continue
                except Exception as e:
                    logger.warning(f"Error processing TruffleHog result: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Error parsing TruffleHog results: {e}")
            self.stats['parse_errors'].append({
                'tool': 'trufflehog',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return findings
    
    def _parse_gitleaks(self, content: str) -> List[Dict[str, Any]]:
        """
        Parse Gitleaks JSON output
        
        Args:
            content: Raw JSON content
            
        Returns:
            List of normalized findings
        """
        findings = []
        
        try:
            # Gitleaks outputs a JSON array
            results = json.loads(content)
            
            if not isinstance(results, list):
                logger.warning("Gitleaks output is not a list")
                return findings
            
            for result in results:
                finding = {
                    'type': result.get('RuleID', 'unknown'),
                    'secret': result.get('Secret', ''),
                    'redacted': self._redact_secret(result.get('Secret', '')),
                    'verified': False,  # Gitleaks doesn't verify by default
                    'file_path': result.get('File'),
                    'line_number': result.get('Line'),
                    'url': None,
                    'confidence': self._map_gitleaks_confidence(result),
                    'severity': result.get('Severity', 'medium').lower(),
                    'metadata': {
                        'description': result.get('Description'),
                        'match': result.get('Match'),
                        'start_line': result.get('StartLine'),
                        'end_line': result.get('EndLine'),
                        'start_column': result.get('StartColumn'),
                        'end_column': result.get('EndColumn'),
                        'author': result.get('Author'),
                        'email': result.get('Email'),
                        'date': result.get('Date'),
                        'message': result.get('Message'),
                        'tags': result.get('Tags', [])
                    }
                }
                
                # Handle commit information
                if result.get('Commit'):
                    finding['metadata']['commit'] = result['Commit']
                
                findings.append(finding)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gitleaks JSON: {e}")
            self.stats['parse_errors'].append({
                'tool': 'gitleaks',
                'error': f"JSON decode error: {e}",
                'timestamp': datetime.utcnow().isoformat()
            })
        except Exception as e:
            logger.error(f"Error parsing Gitleaks results: {e}")
            self.stats['parse_errors'].append({
                'tool': 'gitleaks',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return findings
    
    def _parse_generic(self, content: str) -> List[Dict[str, Any]]:
        """
        Generic parser for unknown formats
        
        Args:
            content: Raw content
            
        Returns:
            List of normalized findings
        """
        findings = []
        
        try:
            # Try to parse as JSON first
            try:
                data = json.loads(content)
                
                # If it's a list, process each item
                if isinstance(data, list):
                    for item in data:
                        finding = self._normalize_generic_finding(item)
                        if finding:
                            findings.append(finding)
                
                # If it's a dict, process as single finding
                elif isinstance(data, dict):
                    finding = self._normalize_generic_finding(data)
                    if finding:
                        findings.append(finding)
                
            except json.JSONDecodeError:
                # Fall back to line-based parsing
                logger.info("Content is not JSON, attempting line-based parsing")
                
                # Look for common patterns
                patterns = {
                    'aws_key': re.compile(r'(AKIA[0-9A-Z]{16})'),
                    'github_token': re.compile(r'(ghp_[0-9a-zA-Z]{36})'),
                    'api_key': re.compile(r'(?i)api[_-]?key[\'"\s:=]+([\'"]?)([a-zA-Z0-9_\-]{20,})\\1'),
                    'secret': re.compile(r'(?i)secret[\'"\s:=]+([\'"]?)([a-zA-Z0-9_\-]{20,})\\1')
                }
                
                for line_num, line in enumerate(content.split('\n'), 1):
                    for pattern_name, pattern in patterns.items():
                        matches = pattern.findall(line)
                        for match in matches:
                            # Extract the actual secret from the match
                            secret = match[-1] if isinstance(match, tuple) else match
                            
                            finding = {
                                'type': pattern_name,
                                'secret': secret,
                                'redacted': self._redact_secret(secret),
                                'verified': False,
                                'file_path': 'unknown',
                                'line_number': line_num,
                                'url': None,
                                'confidence': 'low',
                                'severity': 'medium',
                                'metadata': {
                                    'pattern': pattern_name,
                                    'line_content': line.strip()[:200]  # First 200 chars
                                }
                            }
                            findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error in generic parser: {e}")
            self.stats['parse_errors'].append({
                'tool': 'generic',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return findings
    
    def _normalize_generic_finding(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a generic finding dictionary
        
        Args:
            data: Raw finding data
            
        Returns:
            Normalized finding or None
        """
        try:
            # Look for common field names
            secret_fields = ['secret', 'value', 'key', 'token', 'password', 'credential']
            type_fields = ['type', 'rule', 'detector', 'pattern', 'name']
            path_fields = ['file', 'filepath', 'path', 'filename']
            line_fields = ['line', 'linenumber', 'line_number']
            
            finding = {
                'type': 'unknown',
                'secret': '',
                'redacted': '',
                'verified': False,
                'file_path': None,
                'line_number': None,
                'url': data.get('url'),
                'confidence': 'low',
                'severity': 'medium',
                'metadata': {}
            }
            
            # Extract secret
            for field in secret_fields:
                if field in data:
                    finding['secret'] = str(data[field])
                    finding['redacted'] = self._redact_secret(finding['secret'])
                    break
            
            # Extract type
            for field in type_fields:
                if field in data:
                    finding['type'] = str(data[field])
                    break
            
            # Extract file path
            for field in path_fields:
                if field in data:
                    finding['file_path'] = str(data[field])
                    break
            
            # Extract line number
            for field in line_fields:
                if field in data:
                    try:
                        finding['line_number'] = int(data[field])
                    except (ValueError, TypeError):
                        pass
                    break
            
            # Store any extra fields in metadata
            standard_fields = set(secret_fields + type_fields + path_fields + line_fields + ['url'])
            for key, value in data.items():
                if key not in standard_fields:
                    finding['metadata'][key] = value
            
            # Only return if we found a secret
            if finding['secret']:
                return finding
            
        except Exception as e:
            logger.warning(f"Error normalizing generic finding: {e}")
        
        return None
    
    def _calculate_severity(self, result: Dict[str, Any]) -> str:
        """
        Calculate severity based on various factors
        
        Args:
            result: TruffleHog result
            
        Returns:
            Severity level (critical, high, medium, low)
        """
        try:
            # Verified secrets are always high/critical
            if result.get('Verified'):
                # Certain types are critical
                detector_name = result.get('DetectorName', '').lower()
                critical_types = ['aws', 'gcp', 'azure', 'private_key', 'database']
                
                if any(ct in detector_name for ct in critical_types):
                    return 'critical'
                return 'high'
            
            # Check detector type
            detector_type = result.get('DetectorType', 0)
            if detector_type > 5:  # Assuming higher numbers = more critical
                return 'high'
            
            return 'medium'
            
        except Exception as e:
            logger.warning(f"Error calculating severity: {e}")
            return 'medium'
    
    def _map_gitleaks_confidence(self, result: Dict[str, Any]) -> str:
        """
        Map Gitleaks result to confidence level
        
        Args:
            result: Gitleaks result
            
        Returns:
            Confidence level
        """
        try:
            # Check entropy if available
            entropy = result.get('Entropy', 0)
            if entropy > 7:
                return 'high'
            elif entropy > 5:
                return 'medium'
            
            # Check rule ID for known high-confidence patterns
            rule_id = result.get('RuleID', '').lower()
            high_confidence_rules = ['aws', 'github', 'google', 'slack']
            
            if any(hc in rule_id for hc in high_confidence_rules):
                return 'high'
            
            return 'medium'
            
        except Exception as e:
            logger.warning(f"Error mapping confidence: {e}")
            return 'medium'
    
    def _redact_secret(self, secret: str) -> str:
        """
        Redact a secret for safe display
        
        Args:
            secret: Secret to redact
            
        Returns:
            Redacted secret
        """
        try:
            if not secret:
                return ''
            
            length = len(secret)
            if length <= 8:
                return '*' * length
            elif length <= 20:
                return secret[:3] + '*' * (length - 6) + secret[-3:]
            else:
                return secret[:5] + '*' * 10 + secret[-5:]
                
        except Exception as e:
            logger.warning(f"Error redacting secret: {e}")
            return '***REDACTED***'
    
    def _save_raw_findings(self, findings: List[Dict[str, Any]], tool: str) -> None:
        """
        Save raw findings to file
        
        Args:
            findings: List of findings
            tool: Tool name
        """
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"{tool}_{timestamp}_raw.json"
            filepath = self.raw_secrets_path / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=2, default=str)
            
            logger.info(f"Saved {len(findings)} raw findings to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving raw findings: {e}")
    
    def _update_statistics(self, tool: str, findings: List[Dict[str, Any]]) -> None:
        """
        Update parsing statistics
        
        Args:
            tool: Tool name
            findings: List of findings
        """
        try:
            # Update tool count
            self.stats['tools_processed'][tool] = self.stats['tools_processed'].get(tool, 0) + 1
            self.stats['total_parsed'] += len(findings)
            
            # Update findings by type
            for finding in findings:
                finding_type = finding.get('type', 'unknown')
                self.stats['findings_by_type'][finding_type] = \
                    self.stats['findings_by_type'].get(finding_type, 0) + 1
                
                # Update findings by severity
                severity = finding.get('severity', 'unknown')
                self.stats['findings_by_severity'][severity] = \
                    self.stats['findings_by_severity'].get(severity, 0) + 1
            
        except Exception as e:
            logger.warning(f"Error updating statistics: {e}")
    
    def combine_results(self, results_files: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Combine results from multiple tools
        
        Args:
            results_files: List of dicts with 'file' and 'tool' keys
            
        Returns:
            Combined list of findings
        """
        all_findings = []
        
        try:
            for file_info in results_files:
                results_file = file_info.get('file')
                tool = file_info.get('tool')
                
                if not results_file or not tool:
                    logger.warning(f"Invalid file info: {file_info}")
                    continue
                
                findings = self.parse_results(results_file, tool)
                all_findings.extend(findings)
            
            # Save combined results
            if all_findings:
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                combined_file = self.raw_secrets_path / f"combined_{timestamp}_raw.json"
                
                with open(combined_file, 'w', encoding='utf-8') as f:
                    json.dump(all_findings, f, indent=2, default=str)
                
                logger.info(f"Saved {len(all_findings)} combined findings to {combined_file}")
            
            return all_findings
            
        except Exception as e:
            logger.error(f"Error combining results: {e}")
            return all_findings
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get parsing statistics
        
        Returns:
            Statistics dictionary
        """
        return self.stats
    
    def generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of findings
        
        Args:
            findings: List of findings
            
        Returns:
            Summary dictionary
        """
        try:
            summary = {
                'total_findings': len(findings),
                'verified_findings': sum(1 for f in findings if f.get('verified')),
                'by_type': {},
                'by_severity': {},
                'by_confidence': {},
                'by_tool': {},
                'unique_files': set(),
                'unique_urls': set()
            }
            
            for finding in findings:
                # By type
                ftype = finding.get('type', 'unknown')
                summary['by_type'][ftype] = summary['by_type'].get(ftype, 0) + 1
                
                # By severity
                severity = finding.get('severity', 'unknown')
                summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
                
                # By confidence
                confidence = finding.get('confidence', 'unknown')
                summary['by_confidence'][confidence] = summary['by_confidence'].get(confidence, 0) + 1
                
                # By tool
                tool = finding.get('tool', 'unknown')
                summary['by_tool'][tool] = summary['by_tool'].get(tool, 0) + 1
                
                # Unique files
                if finding.get('file_path'):
                    summary['unique_files'].add(finding['file_path'])
                
                # Unique URLs
                if finding.get('url'):
                    summary['unique_urls'].add(finding['url'])
            
            # Convert sets to counts
            summary['unique_files'] = len(summary['unique_files'])
            summary['unique_urls'] = len(summary['unique_urls'])
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
            return {}