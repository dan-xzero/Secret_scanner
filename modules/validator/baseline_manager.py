#!/usr/bin/env python3
"""
Baseline Manager for Secret Scanner
Manages baselines to track and identify new secrets over time
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
from loguru import logger

class BaselineManager:
    """Manages baseline tracking for secret findings"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Baseline Manager
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.baseline_path = Path(config.get('data_storage_path', './data')) / 'baselines'
        self.baseline_path.mkdir(parents=True, exist_ok=True)
        
        # Current baseline
        self.current_baseline = None
        self.baseline_file = None
        
        # Baseline settings
        self.max_baseline_history = config.get('baseline', {}).get('max_history', 10)
        self.track_false_positives = config.get('baseline', {}).get('track_false_positives', True)
        
        # Statistics
        self.stats = {
            'total_in_baseline': 0,
            'new_findings': 0,
            'recurring_findings': 0,
            'resolved_findings': 0,
            'false_positives': 0,
            'baseline_updates': 0
        }
        
        logger.info(f"Baseline Manager initialized with path: {self.baseline_path}")
    
    def load_baseline(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Load the current baseline for a domain
        
        Args:
            domain: Target domain (optional)
            
        Returns:
            Baseline data
        """
        try:
            # Determine baseline file
            if domain:
                self.baseline_file = self.baseline_path / f"baseline_{self._sanitize_filename(domain)}.json"
            else:
                self.baseline_file = self.baseline_path / "baseline_default.json"
            
            if self.baseline_file.exists():
                with open(self.baseline_file, 'r', encoding='utf-8') as f:
                    self.current_baseline = json.load(f)
                
                logger.info(f"Loaded baseline with {len(self.current_baseline.get('findings', {}))} findings")
                
                # Update statistics
                self.stats['total_in_baseline'] = len(self.current_baseline.get('findings', {}))
                self.stats['false_positives'] = len(self.current_baseline.get('false_positives', {}))
            else:
                logger.info("No existing baseline found, creating new one")
                self.current_baseline = self._create_new_baseline(domain)
            
            return self.current_baseline
            
        except Exception as e:
            logger.error(f"Error loading baseline: {e}")
            logger.exception(e)
            self.current_baseline = self._create_new_baseline(domain)
            return self.current_baseline
    
    def compare_findings(self, new_findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Compare new findings against baseline
        
        Args:
            new_findings: List of new findings
            
        Returns:
            Dictionary with 'new', 'recurring', and 'resolved' findings
        """
        try:
            if not self.current_baseline:
                logger.warning("No baseline loaded, treating all findings as new")
                return {
                    'new': new_findings,
                    'recurring': [],
                    'resolved': []
                }
            
            # Generate hashes for all new findings
            new_hashes = {}
            for finding in new_findings:
                finding_hash = self._generate_finding_hash(finding)
                new_hashes[finding_hash] = finding
            
            # Get baseline findings
            baseline_findings = self.current_baseline.get('findings', {})
            baseline_hashes = set(baseline_findings.keys())
            new_hash_set = set(new_hashes.keys())
            
            # Check false positives
            false_positive_hashes = set()
            if self.track_false_positives:
                false_positive_hashes = set(self.current_baseline.get('false_positives', {}).keys())
            
            # Categorize findings
            results = {
                'new': [],
                'recurring': [],
                'resolved': [],
                'false_positives': []
            }
            
            # New findings (not in baseline)
            for hash_val in new_hash_set - baseline_hashes:
                if hash_val in false_positive_hashes:
                    # Known false positive
                    finding = new_hashes[hash_val]
                    finding['baseline_status'] = 'false_positive'
                    results['false_positives'].append(finding)
                else:
                    # Truly new finding
                    finding = new_hashes[hash_val]
                    finding['baseline_status'] = 'new'
                    finding['first_seen'] = datetime.utcnow().isoformat()
                    results['new'].append(finding)
            
            # Recurring findings (in both)
            for hash_val in new_hash_set & baseline_hashes:
                finding = new_hashes[hash_val]
                finding['baseline_status'] = 'recurring'
                finding['first_seen'] = baseline_findings[hash_val].get('first_seen')
                finding['occurrences'] = baseline_findings[hash_val].get('occurrences', 1) + 1
                results['recurring'].append(finding)
            
            # Resolved findings (in baseline but not new)
            for hash_val in baseline_hashes - new_hash_set:
                baseline_finding = baseline_findings[hash_val]
                baseline_finding['baseline_status'] = 'resolved'
                baseline_finding['resolved_at'] = datetime.utcnow().isoformat()
                results['resolved'].append(baseline_finding)
            
            # Update statistics
            self.stats['new_findings'] = len(results['new'])
            self.stats['recurring_findings'] = len(results['recurring'])
            self.stats['resolved_findings'] = len(results['resolved'])
            
            logger.info(f"Baseline comparison: {self.stats['new_findings']} new, "
                       f"{self.stats['recurring_findings']} recurring, "
                       f"{self.stats['resolved_findings']} resolved")
            
            return results
            
        except Exception as e:
            logger.error(f"Error comparing findings: {e}")
            logger.exception(e)
            return {
                'new': new_findings,
                'recurring': [],
                'resolved': []
            }
    
    def update_baseline(self, findings: List[Dict[str, Any]], 
                       false_positives: Optional[List[Dict[str, Any]]] = None) -> None:
        """
        Update baseline with new findings
        
        Args:
            findings: List of validated findings to add to baseline
            false_positives: List of confirmed false positives
        """
        try:
            if not self.current_baseline:
                logger.error("No baseline loaded")
                return
            
            # Archive current baseline
            self._archive_baseline()
            
            # Update findings
            new_baseline_findings = {}
            
            # Process each finding
            for finding in findings:
                finding_hash = self._generate_finding_hash(finding)
                
                # Preserve metadata from existing baseline if recurring
                if finding_hash in self.current_baseline.get('findings', {}):
                    existing = self.current_baseline['findings'][finding_hash]
                    finding['first_seen'] = existing.get('first_seen')
                    finding['occurrences'] = existing.get('occurrences', 1) + 1
                    finding['last_seen'] = datetime.utcnow().isoformat()
                else:
                    finding['first_seen'] = finding.get('first_seen', datetime.utcnow().isoformat())
                    finding['occurrences'] = 1
                    finding['last_seen'] = datetime.utcnow().isoformat()
                
                new_baseline_findings[finding_hash] = self._clean_finding_for_baseline(finding)
            
            # Update false positives
            new_false_positives = self.current_baseline.get('false_positives', {}).copy()
            if false_positives and self.track_false_positives:
                for fp in false_positives:
                    fp_hash = self._generate_finding_hash(fp)
                    new_false_positives[fp_hash] = {
                        'finding': self._clean_finding_for_baseline(fp),
                        'marked_at': datetime.utcnow().isoformat()
                    }
            
            # Update baseline
            self.current_baseline.update({
                'findings': new_baseline_findings,
                'false_positives': new_false_positives,
                'last_updated': datetime.utcnow().isoformat(),
                'update_count': self.current_baseline.get('update_count', 0) + 1
            })
            
            # Save baseline
            self._save_baseline()
            
            # Update statistics
            self.stats['baseline_updates'] += 1
            self.stats['total_in_baseline'] = len(new_baseline_findings)
            self.stats['false_positives'] = len(new_false_positives)
            
            logger.info(f"Updated baseline with {len(new_baseline_findings)} findings")
            
        except Exception as e:
            logger.error(f"Error updating baseline: {e}")
            logger.exception(e)
    
    def mark_false_positives(self, findings: List[Dict[str, Any]]) -> None:
        """
        Mark findings as false positives in baseline
        
        Args:
            findings: List of findings to mark as false positives
        """
        try:
            if not self.current_baseline:
                logger.error("No baseline loaded")
                return
            
            false_positives = self.current_baseline.get('false_positives', {})
            
            for finding in findings:
                finding_hash = self._generate_finding_hash(finding)
                false_positives[finding_hash] = {
                    'finding': self._clean_finding_for_baseline(finding),
                    'marked_at': datetime.utcnow().isoformat()
                }
                
                # Remove from active findings if present
                if finding_hash in self.current_baseline.get('findings', {}):
                    del self.current_baseline['findings'][finding_hash]
            
            self.current_baseline['false_positives'] = false_positives
            self._save_baseline()
            
            logger.info(f"Marked {len(findings)} findings as false positives")
            
        except Exception as e:
            logger.error(f"Error marking false positives: {e}")
            logger.exception(e)
    
    def get_trending_findings(self, min_occurrences: int = 3) -> List[Dict[str, Any]]:
        """
        Get findings that appear frequently
        
        Args:
            min_occurrences: Minimum number of occurrences
            
        Returns:
            List of trending findings
        """
        try:
            if not self.current_baseline:
                return []
            
            trending = []
            for finding_hash, finding in self.current_baseline.get('findings', {}).items():
                if finding.get('occurrences', 1) >= min_occurrences:
                    trending.append(finding)
            
            # Sort by occurrences
            trending.sort(key=lambda x: x.get('occurrences', 1), reverse=True)
            
            logger.info(f"Found {len(trending)} trending findings")
            return trending
            
        except Exception as e:
            logger.error(f"Error getting trending findings: {e}")
            return []
    
    def get_baseline_summary(self) -> Dict[str, Any]:
        """
        Get summary of current baseline
        
        Returns:
            Baseline summary
        """
        try:
            if not self.current_baseline:
                return {}
            
            findings = self.current_baseline.get('findings', {})
            false_positives = self.current_baseline.get('false_positives', {})
            
            # Count by type
            by_type = {}
            by_severity = {}
            
            for finding in findings.values():
                # By type
                ftype = finding.get('type', 'unknown')
                by_type[ftype] = by_type.get(ftype, 0) + 1
                
                # By severity
                severity = finding.get('severity', 'unknown')
                by_severity[severity] = by_severity.get(severity, 0) + 1
            
            summary = {
                'domain': self.current_baseline.get('domain'),
                'created_at': self.current_baseline.get('created_at'),
                'last_updated': self.current_baseline.get('last_updated'),
                'update_count': self.current_baseline.get('update_count', 0),
                'total_findings': len(findings),
                'false_positives': len(false_positives),
                'by_type': by_type,
                'by_severity': by_severity,
                'trending_count': len(self.get_trending_findings())
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting baseline summary: {e}")
            return {}
    
    def _generate_finding_hash(self, finding: Dict[str, Any]) -> str:
        """
        Generate unique hash for a finding
        
        Args:
            finding: Finding data
            
        Returns:
            Hash string
        """
        try:
            # Normalize field names
            file_path = finding.get('file_path') or finding.get('file') or finding.get('filepath', '')
            line_number = finding.get('line_number') or finding.get('line')
            secret = finding.get('secret') or finding.get('raw', '')
            url = finding.get('url', '')
            
            # Normalize file path by removing scan-specific directory
            normalized_file_path = self._normalize_file_path(file_path)
            
            # Prefer URL as primary location identifier if available
            if url:
                # For inline scripts, use the parent URL without the fragment
                if '#inline-script-' in url:
                    location = url.split('#')[0] + '#inline-script'
                else:
                    location = url
            else:
                # Fall back to normalized file path
                location = normalized_file_path
            
            # Create hash from key fields
            hash_data = {
                'type': finding.get('type', ''),
                'secret_pattern': self._extract_secret_pattern(secret),
                'location': location,
                'line': line_number
            }
            
            # Create stable JSON string
            hash_string = json.dumps(hash_data, sort_keys=True)
            
            # Generate hash
            return hashlib.sha256(hash_string.encode()).hexdigest()[:16]
            
        except Exception as e:
            logger.error(f"Error generating finding hash: {e}")
            # Fallback to simple hash
            return hashlib.md5(str(finding).encode()).hexdigest()[:16]
    
    def _normalize_file_path(self, file_path: str) -> str:
        """
        Normalize file path by removing scan-specific directories
        
        Args:
            file_path: Original file path
            
        Returns:
            Normalized file path
        """
        if not file_path:
            return ''
        
        # Convert to Path for easier manipulation
        path = Path(file_path)
        parts = path.parts
        
        # Look for scan-specific directory patterns
        normalized_parts = []
        skip_next = False
        
        for i, part in enumerate(parts):
            # Skip scan-specific directories
            if part == 'content' and i + 1 < len(parts):
                # Check if next part is a scan-specific directory
                next_part = parts[i + 1]
                if next_part.startswith('scan_') and '_' in next_part:
                    # This looks like a scan ID, skip it
                    skip_next = True
                    normalized_parts.append(part)
                    continue
            
            if skip_next:
                skip_next = False
                continue
            
            # Also handle data/content/scan_* pattern
            if part.startswith('scan_') and i > 0 and parts[i-1] == 'content':
                continue
            
            normalized_parts.append(part)
        
        # Reconstruct path
        if normalized_parts:
            normalized_path = str(Path(*normalized_parts))
        else:
            normalized_path = file_path
        
        # Further normalization: extract just the meaningful part
        # For example: data/content/html/example.html -> html/example.html
        if 'content' in normalized_parts:
            content_idx = normalized_parts.index('content')
            if content_idx + 1 < len(normalized_parts):
                # Return everything after 'content'
                return str(Path(*normalized_parts[content_idx + 1:]))
        
        return normalized_path
    
    def _extract_secret_pattern(self, secret: str) -> str:
        """
        Extract pattern from secret for consistent hashing
        
        Args:
            secret: Secret string
            
        Returns:
            Pattern string
        """
        if not secret:
            return ''
        
        # For short secrets, use the whole thing
        if len(secret) <= 20:
            return secret
        
        # For longer secrets, use prefix and suffix
        return f"{secret[:10]}...{secret[-10:]}"
    
    def _clean_finding_for_baseline(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Clean finding data for baseline storage
        
        Args:
            finding: Finding data
            
        Returns:
            Cleaned finding
        """
        # Get original file path
        original_file_path = finding.get('file_path') or finding.get('file') or finding.get('filepath', '')
        
        # Normalize field names first
        normalized = {
            'type': finding.get('type', 'unknown'),
            'severity': finding.get('severity', 'medium'),
            'file_path': self._normalize_file_path(original_file_path),  # Store normalized path
            'original_file_path': original_file_path,  # Keep original for reference
            'url': finding.get('url', ''),
            'line_number': finding.get('line_number') or finding.get('line'),
            'verified': finding.get('verified', False),
            'confidence': finding.get('confidence', 'medium'),
            'tool': finding.get('tool') or finding.get('detector', 'unknown')
        }
        
        # Add temporal fields if they exist
        if 'first_seen' in finding:
            normalized['first_seen'] = finding['first_seen']
        if 'last_seen' in finding:
            normalized['last_seen'] = finding['last_seen']
        if 'occurrences' in finding:
            normalized['occurrences'] = finding['occurrences']
        
        # Add validation result if exists
        if 'validation_result' in finding:
            normalized['validation_result'] = finding['validation_result']
        
        # Add redacted secret pattern
        secret = finding.get('secret') or finding.get('raw', '')
        if secret:
            normalized['secret_pattern'] = self._extract_secret_pattern(secret)
        
        return normalized
    
    def _create_new_baseline(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new baseline
        
        Args:
            domain: Target domain
            
        Returns:
            New baseline data
        """
        return {
            'version': '1.0',
            'domain': domain,
            'created_at': datetime.utcnow().isoformat(),
            'last_updated': datetime.utcnow().isoformat(),
            'update_count': 0,
            'findings': {},
            'false_positives': {}
        }
    
    def _save_baseline(self) -> None:
        """Save current baseline to file"""
        try:
            if not self.baseline_file:
                logger.error("No baseline file specified")
                return
            
            with open(self.baseline_file, 'w', encoding='utf-8') as f:
                json.dump(self.current_baseline, f, indent=2, default=str)
            
            logger.debug(f"Saved baseline to {self.baseline_file}")
            
        except Exception as e:
            logger.error(f"Error saving baseline: {e}")
    
    def _archive_baseline(self) -> None:
        """Archive current baseline before updating"""
        try:
            if not self.baseline_file or not self.baseline_file.exists():
                return
            
            # Create archive filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            archive_dir = self.baseline_path / 'archive'
            archive_dir.mkdir(exist_ok=True)
            
            archive_file = archive_dir / f"{self.baseline_file.stem}_{timestamp}.json"
            
            # Copy current baseline to archive
            import shutil
            shutil.copy2(self.baseline_file, archive_file)
            
            logger.debug(f"Archived baseline to {archive_file}")
            
            # Clean up old archives
            self._cleanup_old_archives(archive_dir)
            
        except Exception as e:
            logger.error(f"Error archiving baseline: {e}")
    
    def _cleanup_old_archives(self, archive_dir: Path) -> None:
        """
        Clean up old baseline archives
        
        Args:
            archive_dir: Archive directory
        """
        try:
            archives = sorted(archive_dir.glob("*.json"), key=lambda x: x.stat().st_mtime)
            
            # Keep only the most recent archives
            if len(archives) > self.max_baseline_history:
                for archive in archives[:-self.max_baseline_history]:
                    archive.unlink()
                    logger.debug(f"Deleted old archive: {archive}")
            
        except Exception as e:
            logger.error(f"Error cleaning up archives: {e}")
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename for safe file system usage
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized filename
        """
        # Replace problematic characters
        sanitized = filename.replace('/', '_').replace('\\', '_').replace(':', '_')
        sanitized = sanitized.replace(' ', '_').replace('.', '_')
        
        # Limit length
        if len(sanitized) > 50:
            sanitized = sanitized[:50]
        
        return sanitized
    
    def export_baseline_report(self, output_file: Optional[Path] = None) -> Path:
        """
        Export detailed baseline report
        
        Args:
            output_file: Output file path (optional)
            
        Returns:
            Path to report file
        """
        try:
            if not output_file:
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                output_file = self.baseline_path / f"baseline_report_{timestamp}.json"
            
            report = {
                'generated_at': datetime.utcnow().isoformat(),
                'summary': self.get_baseline_summary(),
                'statistics': self.stats,
                'trending_findings': self.get_trending_findings(),
                'baseline_metadata': {
                    'file': str(self.baseline_file),
                    'size': len(self.current_baseline.get('findings', {}))
                }
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Exported baseline report to {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error exporting baseline report: {e}")
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get baseline statistics
        
        Returns:
            Statistics dictionary
        """
        return self.stats
    
    def migrate_baseline(self) -> None:
        """
        Migrate existing baseline to use normalized file paths
        
        This method updates an existing baseline file to use normalized paths,
        allowing it to work correctly with the updated comparison logic.
        """
        if not self.current_baseline:
            logger.warning("No baseline loaded to migrate")
            return
        
        try:
            logger.info("Migrating baseline to use normalized paths...")
            
            # Update findings with normalized paths
            migrated_findings = {}
            for hash_key, finding in self.current_baseline.get('findings', {}).items():
                # Regenerate hash with normalized path
                new_hash = self._generate_finding_hash(finding)
                
                # Update the finding with normalized path
                migrated_finding = finding.copy()
                original_path = finding.get('file_path', '')
                migrated_finding['file_path'] = self._normalize_file_path(original_path)
                migrated_finding['original_file_path'] = original_path
                
                migrated_findings[new_hash] = migrated_finding
            
            # Update false positives similarly
            migrated_false_positives = {}
            for hash_key, fp_data in self.current_baseline.get('false_positives', {}).items():
                if 'finding' in fp_data:
                    # Regenerate hash with normalized path
                    new_hash = self._generate_finding_hash(fp_data['finding'])
                    
                    # Update the finding with normalized path
                    migrated_fp = fp_data.copy()
                    migrated_fp['finding'] = self._clean_finding_for_baseline(fp_data['finding'])
                    
                    migrated_false_positives[new_hash] = migrated_fp
            
            # Update baseline
            self.current_baseline['findings'] = migrated_findings
            self.current_baseline['false_positives'] = migrated_false_positives
            self.current_baseline['migrated_at'] = datetime.utcnow().isoformat()
            self.current_baseline['version'] = '2.0'  # Update version to indicate migration
            
            # Save migrated baseline
            self._save_baseline()
            
            logger.info(f"Successfully migrated {len(migrated_findings)} findings and "
                       f"{len(migrated_false_positives)} false positives")
            
        except Exception as e:
            logger.error(f"Error migrating baseline: {e}")
            logger.exception(e)