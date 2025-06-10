#!/usr/bin/env python3
"""
Baseline Manager for Secret Scanner - Database Integrated Version
Manages baselines to track and identify new secrets over time
"""

import os
import json
import sqlite3
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
from loguru import logger


class BaselineManager:
    """Manages baseline tracking for secret findings with database integration"""
    
    def __init__(self, config: Dict[str, Any], db_path: Optional[str] = None):
        """
        Initialize Baseline Manager
        
        Args:
            config: Configuration dictionary
            db_path: Path to database file
        """
        self.config = config
        
        # Database path
        self.db_path = db_path or Path(config.get('data_storage_path', './data')) / 'secrets_scanner.db'
        
        # Baseline settings
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
        
        # Initialize database tables if needed
        self._init_database_tables()
        
        logger.info(f"Baseline Manager initialized with database: {self.db_path}")
    
    def _init_database_tables(self):
        """Initialize baseline-related tables in database"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Baselines table is already created in main scanner
                # Add any additional indexes if needed
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_baselines_secret_domain 
                    ON baselines(secret_id, domain)
                ''')
                
                # Create false positives table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS false_positives (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        secret_id INTEGER,
                        domain TEXT,
                        marked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        marked_by TEXT,
                        reason TEXT,
                        FOREIGN KEY (secret_id) REFERENCES secrets(id),
                        UNIQUE(secret_id, domain)
                    )
                ''')
                
                conn.commit()
                logger.debug("Baseline database tables initialized")
                
        except Exception as e:
            logger.error(f"Error initializing baseline tables: {e}")
    
    def load_baseline_from_db(self, domain: Optional[str] = None) -> Dict[str, int]:
        """
        Load current baseline from database
        
        Args:
            domain: Target domain (optional)
            
        Returns:
            Dictionary of secret_id -> baseline_id mappings
        """
        try:
            baseline_secrets = {}
            
            with sqlite3.connect(str(self.db_path)) as conn:
                if domain:
                    rows = conn.execute('''
                        SELECT id, secret_id 
                        FROM baselines 
                        WHERE domain = ?
                    ''', (domain,)).fetchall()
                else:
                    rows = conn.execute('''
                        SELECT id, secret_id 
                        FROM baselines
                    ''').fetchall()
                
                for row in rows:
                    baseline_secrets[row[1]] = row[0]  # secret_id -> baseline_id
                
                self.stats['total_in_baseline'] = len(baseline_secrets)
                logger.info(f"Loaded {len(baseline_secrets)} secrets from baseline")
                
            return baseline_secrets
            
        except Exception as e:
            logger.error(f"Error loading baseline from DB: {e}")
            return {}
    
    def compare_findings_with_db(self, scan_run_id: int, 
                               domain: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Compare findings from a scan run against baseline
        
        Args:
            scan_run_id: Scan run ID
            domain: Target domain (optional)
            
        Returns:
            Dictionary with 'new', 'recurring', and 'resolved' findings
        """
        try:
            results = {
                'new': [],
                'recurring': [],
                'resolved': [],
                'false_positives': []
            }
            
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get all unique secrets from current scan
                current_query = '''
                    SELECT DISTINCT
                        s.id as secret_id,
                        s.secret_hash,
                        s.secret_type,
                        s.severity,
                        s.detector_name,
                        s.first_seen,
                        s.is_verified,
                        s.is_active
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    WHERE f.scan_run_id = ?
                '''
                current_rows = conn.execute(current_query, (scan_run_id,)).fetchall()
                current_secrets = {row['secret_id']: dict(row) for row in current_rows}
                
                # Get baseline secrets
                baseline_query = '''
                    SELECT 
                        b.id as baseline_id,
                        b.secret_id,
                        s.secret_hash,
                        s.secret_type,
                        s.severity,
                        s.first_seen,
                        b.marked_as_baseline_at
                    FROM baselines b
                    JOIN secrets s ON b.secret_id = s.id
                '''
                if domain:
                    baseline_query += ' WHERE b.domain = ?'
                    baseline_rows = conn.execute(baseline_query, (domain,)).fetchall()
                else:
                    baseline_rows = conn.execute(baseline_query).fetchall()
                
                baseline_secrets = {row['secret_id']: dict(row) for row in baseline_rows}
                
                # Get false positives
                fp_query = '''
                    SELECT secret_id 
                    FROM false_positives
                '''
                if domain:
                    fp_query += ' WHERE domain = ?'
                    fp_rows = conn.execute(fp_query, (domain,)).fetchall()
                else:
                    fp_rows = conn.execute(fp_query).fetchall()
                
                false_positive_ids = {row[0] for row in fp_rows}
                
                # Categorize findings
                current_ids = set(current_secrets.keys())
                baseline_ids = set(baseline_secrets.keys())
                
                # New findings (not in baseline)
                for secret_id in current_ids - baseline_ids:
                    if secret_id in false_positive_ids:
                        # Known false positive
                        secret = current_secrets[secret_id]
                        secret['baseline_status'] = 'false_positive'
                        results['false_positives'].append(secret)
                    else:
                        # Truly new finding
                        secret = current_secrets[secret_id]
                        secret['baseline_status'] = 'new'
                        results['new'].append(secret)
                
                # Recurring findings (in both)
                for secret_id in current_ids & baseline_ids:
                    secret = current_secrets[secret_id]
                    secret['baseline_status'] = 'recurring'
                    secret['first_seen'] = baseline_secrets[secret_id]['first_seen']
                    results['recurring'].append(secret)
                
                # Resolved findings (in baseline but not current)
                for secret_id in baseline_ids - current_ids:
                    secret = baseline_secrets[secret_id]
                    secret['baseline_status'] = 'resolved'
                    secret['resolved_at'] = datetime.utcnow().isoformat()
                    results['resolved'].append(secret)
                
                # Update statistics
                self.stats['new_findings'] = len(results['new'])
                self.stats['recurring_findings'] = len(results['recurring'])
                self.stats['resolved_findings'] = len(results['resolved'])
                self.stats['false_positives'] = len(results['false_positives'])
                
                logger.info(f"Baseline comparison: {self.stats['new_findings']} new, "
                           f"{self.stats['recurring_findings']} recurring, "
                           f"{self.stats['resolved_findings']} resolved")
                
            return results
            
        except Exception as e:
            logger.error(f"Error comparing findings with DB: {e}")
            logger.exception(e)
            return {
                'new': [],
                'recurring': [],
                'resolved': [],
                'false_positives': []
            }
    
    def update_baseline_in_db(self, scan_run_id: int, domain: str,
                            include_all: bool = False) -> None:
        """
        Update baseline with findings from a scan run
        
        Args:
            scan_run_id: Scan run ID
            domain: Target domain
            include_all: Include all findings or only new ones
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                if include_all:
                    # Add all unique secrets from scan to baseline
                    query = '''
                        INSERT OR IGNORE INTO baselines (secret_id, domain, marked_by)
                        SELECT DISTINCT 
                            s.id,
                            ?,
                            'scan_' || ?
                        FROM findings f
                        JOIN secrets s ON f.secret_id = s.id
                        WHERE f.scan_run_id = ?
                    '''
                    conn.execute(query, (domain, scan_run_id, scan_run_id))
                else:
                    # Add only new findings (not already in baseline)
                    query = '''
                        INSERT OR IGNORE INTO baselines (secret_id, domain, marked_by)
                        SELECT DISTINCT 
                            s.id,
                            ?,
                            'scan_' || ?
                        FROM findings f
                        JOIN secrets s ON f.secret_id = s.id
                        LEFT JOIN baselines b ON s.id = b.secret_id AND b.domain = ?
                        WHERE f.scan_run_id = ?
                        AND b.id IS NULL
                    '''
                    conn.execute(query, (domain, scan_run_id, domain, scan_run_id))
                
                # Update statistics
                count = conn.total_changes
                self.stats['baseline_updates'] += 1
                
                conn.commit()
                logger.info(f"Added {count} secrets to baseline for domain {domain}")
                
        except Exception as e:
            logger.error(f"Error updating baseline in DB: {e}")
            logger.exception(e)
    
    def mark_false_positives_in_db(self, secret_ids: List[int], domain: str,
                                  reason: Optional[str] = None) -> None:
        """
        Mark secrets as false positives
        
        Args:
            secret_ids: List of secret IDs to mark
            domain: Domain context
            reason: Reason for marking as false positive
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                for secret_id in secret_ids:
                    # Add to false positives table
                    conn.execute('''
                        INSERT OR REPLACE INTO false_positives 
                        (secret_id, domain, reason, marked_by)
                        VALUES (?, ?, ?, ?)
                    ''', (secret_id, domain, reason or 'Manual', 'user'))
                    
                    # Remove from baseline if present
                    conn.execute('''
                        DELETE FROM baselines 
                        WHERE secret_id = ? AND domain = ?
                    ''', (secret_id, domain))
                
                conn.commit()
                logger.info(f"Marked {len(secret_ids)} secrets as false positives")
                
        except Exception as e:
            logger.error(f"Error marking false positives: {e}")
            logger.exception(e)
    
    def get_trending_findings_from_db(self, min_occurrences: int = 3, 
                                    days: int = 30) -> List[Dict[str, Any]]:
        """
        Get findings that appear frequently across scans
        
        Args:
            min_occurrences: Minimum number of occurrences
            days: Look back period in days
            
        Returns:
            List of trending findings
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                
                query = '''
                    SELECT 
                        s.id,
                        s.secret_type,
                        s.severity,
                        s.detector_name,
                        s.first_seen,
                        s.last_seen,
                        COUNT(DISTINCT f.scan_run_id) as occurrence_count,
                        COUNT(DISTINCT u.domain) as domain_count
                    FROM secrets s
                    JOIN findings f ON s.id = f.secret_id
                    JOIN urls u ON f.url_id = u.id
                    JOIN scan_runs sr ON f.scan_run_id = sr.id
                    WHERE sr.started_at >= datetime('now', '-' || ? || ' days')
                    GROUP BY s.id
                    HAVING occurrence_count >= ?
                    ORDER BY occurrence_count DESC, s.severity DESC
                '''
                
                rows = conn.execute(query, (days, min_occurrences)).fetchall()
                
                trending = []
                for row in rows:
                    trending.append(dict(row))
                
                logger.info(f"Found {len(trending)} trending findings")
                return trending
                
        except Exception as e:
            logger.error(f"Error getting trending findings: {e}")
            return []
    
    def get_baseline_summary_from_db(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Get summary of current baseline from database
        
        Args:
            domain: Target domain (optional)
            
        Returns:
            Baseline summary
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Count baseline entries
                if domain:
                    count_query = '''
                        SELECT COUNT(*) as total,
                               COUNT(DISTINCT s.secret_type) as unique_types
                        FROM baselines b
                        JOIN secrets s ON b.secret_id = s.id
                        WHERE b.domain = ?
                    '''
                    count_result = conn.execute(count_query, (domain,)).fetchone()
                else:
                    count_query = '''
                        SELECT COUNT(*) as total,
                               COUNT(DISTINCT s.secret_type) as unique_types
                        FROM baselines b
                        JOIN secrets s ON b.secret_id = s.id
                    '''
                    count_result = conn.execute(count_query).fetchone()
                
                # Count by type
                type_query = '''
                    SELECT s.secret_type, COUNT(*) as count
                    FROM baselines b
                    JOIN secrets s ON b.secret_id = s.id
                '''
                if domain:
                    type_query += ' WHERE b.domain = ?'
                    type_query += ' GROUP BY s.secret_type ORDER BY count DESC'
                    type_rows = conn.execute(type_query, (domain,)).fetchall()
                else:
                    type_query += ' GROUP BY s.secret_type ORDER BY count DESC'
                    type_rows = conn.execute(type_query).fetchall()
                
                by_type = {row[0]: row[1] for row in type_rows}
                
                # Count by severity
                severity_query = '''
                    SELECT s.severity, COUNT(*) as count
                    FROM baselines b
                    JOIN secrets s ON b.secret_id = s.id
                '''
                if domain:
                    severity_query += ' WHERE b.domain = ?'
                    severity_query += ' GROUP BY s.severity'
                    severity_rows = conn.execute(severity_query, (domain,)).fetchall()
                else:
                    severity_query += ' GROUP BY s.severity'
                    severity_rows = conn.execute(severity_query).fetchall()
                
                by_severity = {row[0]: row[1] for row in severity_rows}
                
                # Get false positive count
                if domain:
                    fp_count = conn.execute('''
                        SELECT COUNT(*) FROM false_positives WHERE domain = ?
                    ''', (domain,)).fetchone()[0]
                else:
                    fp_count = conn.execute('''
                        SELECT COUNT(*) FROM false_positives
                    ''').fetchone()[0]
                
                summary = {
                    'domain': domain,
                    'total_findings': count_result[0] if count_result else 0,
                    'unique_types': count_result[1] if count_result else 0,
                    'false_positives': fp_count,
                    'by_type': by_type,
                    'by_severity': by_severity,
                    'last_updated': datetime.utcnow().isoformat()
                }
                
                return summary
                
        except Exception as e:
            logger.error(f"Error getting baseline summary: {e}")
            return {}
    
    def remove_from_baseline(self, secret_ids: List[int], domain: Optional[str] = None) -> int:
        """
        Remove secrets from baseline
        
        Args:
            secret_ids: List of secret IDs to remove
            domain: Domain context (optional)
            
        Returns:
            Number of secrets removed
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                if domain:
                    placeholders = ','.join('?' * len(secret_ids))
                    query = f'''
                        DELETE FROM baselines 
                        WHERE secret_id IN ({placeholders}) 
                        AND domain = ?
                    '''
                    cursor = conn.execute(query, secret_ids + [domain])
                else:
                    placeholders = ','.join('?' * len(secret_ids))
                    query = f'''
                        DELETE FROM baselines 
                        WHERE secret_id IN ({placeholders})
                    '''
                    cursor = conn.execute(query, secret_ids)
                
                removed_count = cursor.rowcount
                conn.commit()
                
                logger.info(f"Removed {removed_count} secrets from baseline")
                return removed_count
                
        except Exception as e:
            logger.error(f"Error removing from baseline: {e}")
            return 0
    
    def clear_baseline(self, domain: Optional[str] = None) -> int:
        """
        Clear all entries from baseline
        
        Args:
            domain: Domain to clear (optional, clears all if not specified)
            
        Returns:
            Number of entries cleared
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                if domain:
                    cursor = conn.execute('''
                        DELETE FROM baselines WHERE domain = ?
                    ''', (domain,))
                else:
                    cursor = conn.execute('DELETE FROM baselines')
                
                cleared_count = cursor.rowcount
                conn.commit()
                
                logger.info(f"Cleared {cleared_count} entries from baseline")
                return cleared_count
                
        except Exception as e:
            logger.error(f"Error clearing baseline: {e}")
            return 0
    
    def export_baseline_report(self, output_file: Optional[Path] = None,
                             domain: Optional[str] = None) -> Path:
        """
        Export detailed baseline report
        
        Args:
            output_file: Output file path (optional)
            domain: Domain filter (optional)
            
        Returns:
            Path to report file
        """
        try:
            if not output_file:
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                reports_dir = self.db_path.parent / 'reports'
                reports_dir.mkdir(exist_ok=True)
                output_file = reports_dir / f"baseline_report_{timestamp}.json"
            
            report = {
                'generated_at': datetime.utcnow().isoformat(),
                'summary': self.get_baseline_summary_from_db(domain),
                'statistics': self.stats,
                'trending_findings': self.get_trending_findings_from_db(),
                'database': str(self.db_path)
            }
            
            # Add detailed baseline entries if requested
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                
                query = '''
                    SELECT 
                        b.id,
                        b.secret_id,
                        b.domain,
                        b.marked_as_baseline_at,
                        b.reason,
                        s.secret_type,
                        s.severity,
                        s.detector_name,
                        s.first_seen,
                        s.last_seen
                    FROM baselines b
                    JOIN secrets s ON b.secret_id = s.id
                '''
                if domain:
                    query += ' WHERE b.domain = ?'
                    rows = conn.execute(query, (domain,)).fetchall()
                else:
                    rows = conn.execute(query).fetchall()
                
                baseline_entries = [dict(row) for row in rows]
                report['baseline_entries'] = baseline_entries
            
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
    
    def sync_with_legacy_baseline(self, legacy_file: Path, domain: str) -> int:
        """
        Import legacy JSON baseline file into database
        
        Args:
            legacy_file: Path to legacy baseline JSON file
            domain: Domain to associate with imported entries
            
        Returns:
            Number of entries imported
        """
        try:
            if not legacy_file.exists():
                logger.warning(f"Legacy baseline file not found: {legacy_file}")
                return 0
            
            with open(legacy_file, 'r', encoding='utf-8') as f:
                legacy_data = json.load(f)
            
            imported_count = 0
            
            with sqlite3.connect(str(self.db_path)) as conn:
                # Process each finding in legacy baseline
                for finding_hash, finding_data in legacy_data.get('findings', {}).items():
                    # Try to find matching secret in database by type and pattern
                    secret_type = finding_data.get('type', 'unknown')
                    secret_pattern = finding_data.get('secret_pattern', '')
                    
                    # Search for existing secret
                    secret_row = conn.execute('''
                        SELECT id FROM secrets 
                        WHERE secret_type = ? 
                        LIMIT 1
                    ''', (secret_type,)).fetchone()
                    
                    if secret_row:
                        secret_id = secret_row[0]
                        
                        # Add to baseline
                        conn.execute('''
                            INSERT OR IGNORE INTO baselines 
                            (secret_id, domain, reason, marked_by)
                            VALUES (?, ?, ?, ?)
                        ''', (secret_id, domain, 'Imported from legacy', 'import'))
                        
                        imported_count += 1
                
                conn.commit()
                
            logger.info(f"Imported {imported_count} entries from legacy baseline")
            return imported_count
            
        except Exception as e:
            logger.error(f"Error importing legacy baseline: {e}")
            return 0