#!/usr/bin/env python3
"""
Enhanced Slack Notifier for Secret Scanner - Database Integrated Version
Focuses on unique findings with cleaner, more consistent formatting
"""

import os
import json
import time
import sqlite3
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
from collections import defaultdict
from loguru import logger


class SlackNotifier:
    """Handles Slack notifications for secret findings with database integration"""
    
    def __init__(self, config: Dict[str, Any], db_path: Optional[str] = None):
        """
        Initialize Slack Notifier
        
        Args:
            config: Configuration dictionary
            db_path: Path to database file
        """
        self.config = config
        self.slack_config = self._load_slack_config()
        
        # Database path
        self.db_path = db_path or Path(config.get('data_storage_path', './data')) / 'scanner.db'
        
        # Webhook URL (can be overridden by environment variable)
        self.webhook_url = os.environ.get('SLACK_WEBHOOK_URL') or self.slack_config.get('webhook_url')
        
        # Notification settings
        self.channel = self.slack_config.get('channel', '#security-alerts')
        self.username = self.slack_config.get('username', 'Secret Scanner Bot')
        self.icon_emoji = self.slack_config.get('icon_emoji', ':lock:')
        self.mention_users = self.slack_config.get('mention_users', [])
        self.mention_on_critical = self.slack_config.get('mention_on_critical', True)
        
        # Rate limiting
        self.rate_limit_delay = self.slack_config.get('rate_limit_delay', 1)
        self.max_findings_per_message = self.slack_config.get('max_findings_per_message', 10)
        
        # Message templates
        self.templates = self.slack_config.get('templates', {})
        
        # Statistics
        self.stats = {
            'notifications_sent': 0,
            'notification_errors': [],
            'last_notification': None
        }
        
        # Initialize notification tracking table
        self._init_notification_tracking()
        
        if not self.webhook_url:
            logger.warning("No Slack webhook URL configured")
        else:
            logger.info(f"Slack Notifier initialized for channel: {self.channel}")
    
    def _init_notification_tracking(self):
        """Initialize notification tracking table in database"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS notification_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_run_id INTEGER,
                        secret_id INTEGER,
                        notification_type TEXT,
                        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT,
                        message_id TEXT,
                        FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id),
                        FOREIGN KEY (secret_id) REFERENCES secrets(id)
                    )
                ''')
                
                # Create indexes
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_notification_scan_run 
                    ON notification_history(scan_run_id)
                ''')
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_notification_secret 
                    ON notification_history(secret_id)
                ''')
                
                conn.commit()
                logger.debug("Notification tracking table initialized")
                
        except Exception as e:
            logger.error(f"Error initializing notification tracking: {e}")
    
    def _load_slack_config(self) -> Dict[str, Any]:
        """Load Slack configuration"""
        try:
            config_file = Path(self.config.get('config_dir', './config')) / 'slack_config.json'
            
            if config_file.exists():
                with open(config_file, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Slack config file not found: {config_file}")
                return {}
                
        except Exception as e:
            logger.error(f"Error loading Slack config: {e}")
            return {}
    
    def send_findings_notification_from_db(self, scan_run_id: int, 
                                         notification_type: str = 'new') -> bool:
        """
        Send notification for findings from database
        
        Args:
            scan_run_id: Scan run ID
            notification_type: Type of notification ('new', 'summary', 'critical')
            
        Returns:
            True if successful
        """
        try:
            if not self.webhook_url:
                logger.warning("Cannot send notification: No webhook URL configured")
                return False
            
            # Get findings from database
            findings = self._get_findings_from_db(scan_run_id, notification_type)
            summary_data = self._get_scan_summary_from_db(scan_run_id)
            
            if not findings and notification_type != 'summary':
                logger.info("No findings to notify")
                return True
            
            # Send notification using existing method
            success = self.send_findings_notification(findings, notification_type, summary_data)
            
            # Track notification in database
            if success:
                self._track_notification(scan_run_id, findings, notification_type)
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending notification from DB: {e}")
            logger.exception(e)
            return False
    
    def _get_findings_from_db(self, scan_run_id: int, notification_type: str) -> List[Dict[str, Any]]:
        """
        Get findings from database for notification
        
        Args:
            scan_run_id: Scan run ID
            notification_type: Type of notification
            
        Returns:
            List of findings
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                
                if notification_type == 'critical':
                    # Get critical findings only
                    query = '''
                        SELECT DISTINCT
                            s.id as secret_id,
                            s.secret_type as type,
                            s.detector_name,
                            s.severity,
                            s.is_verified as verified,
                            s.is_active,
                            u.url,
                            f.line_number,
                            f.snippet,
                            f.validation_status,
                            f.validation_result,
                            CASE 
                                WHEN b.id IS NULL THEN 'new'
                                ELSE 'existing'
                            END as baseline_status
                        FROM findings f
                        JOIN secrets s ON f.secret_id = s.id
                        JOIN urls u ON f.url_id = u.id
                        LEFT JOIN baselines b ON s.id = b.secret_id
                        WHERE f.scan_run_id = ?
                        AND s.severity = 'critical'
                        AND s.is_active = 1
                        ORDER BY s.severity DESC, s.secret_type
                    '''
                    rows = conn.execute(query, (scan_run_id,)).fetchall()
                    
                elif notification_type == 'new':
                    # Get new findings not in baseline
                    query = '''
                        SELECT DISTINCT
                            s.id as secret_id,
                            s.secret_type as type,
                            s.detector_name,
                            s.severity,
                            s.is_verified as verified,
                            s.is_active,
                            u.url,
                            f.line_number,
                            f.snippet,
                            f.validation_status,
                            f.validation_result,
                            'new' as baseline_status
                        FROM findings f
                        JOIN secrets s ON f.secret_id = s.id
                        JOIN urls u ON f.url_id = u.id
                        LEFT JOIN baselines b ON s.id = b.secret_id
                        WHERE f.scan_run_id = ?
                        AND b.id IS NULL
                        ORDER BY s.severity DESC, s.secret_type
                    '''
                    rows = conn.execute(query, (scan_run_id,)).fetchall()
                    
                else:
                    # Get all findings for summary
                    query = '''
                        SELECT DISTINCT
                            s.id as secret_id,
                            s.secret_type as type,
                            s.detector_name,
                            s.severity,
                            s.is_verified as verified,
                            s.is_active,
                            u.url,
                            f.line_number,
                            f.snippet,
                            f.validation_status,
                            f.validation_result,
                            CASE 
                                WHEN b.id IS NULL THEN 'new'
                                ELSE 'existing'
                            END as baseline_status
                        FROM findings f
                        JOIN secrets s ON f.secret_id = s.id
                        JOIN urls u ON f.url_id = u.id
                        LEFT JOIN baselines b ON s.id = b.secret_id
                        WHERE f.scan_run_id = ?
                        ORDER BY s.severity DESC, s.secret_type
                        LIMIT 100
                    '''
                    rows = conn.execute(query, (scan_run_id,)).fetchall()
                
                # Convert rows to dictionaries
                findings = []
                for row in rows:
                    finding = dict(row)
                    
                    # Parse JSON fields
                    if finding.get('validation_result'):
                        try:
                            finding['validation_result'] = json.loads(finding['validation_result'])
                        except:
                            finding['validation_result'] = {}
                    
                    # For deduplication purposes, add a dummy 'raw' field
                    # (The actual secret value is not stored in findings for security)
                    finding['raw'] = f"secret_{finding['secret_id']}"
                    
                    findings.append(finding)
                
                return findings
                
        except Exception as e:
            logger.error(f"Error getting findings from DB: {e}")
            logger.exception(e)
            return []
    
    def _get_scan_summary_from_db(self, scan_run_id: int) -> Dict[str, Any]:
        """
        Get scan summary from database
        
        Args:
            scan_run_id: Scan run ID
            
        Returns:
            Summary data
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get scan run details
                scan_row = conn.execute('''
                    SELECT * FROM scan_runs WHERE id = ?
                ''', (scan_run_id,)).fetchone()
                
                if not scan_row:
                    return {}
                
                scan_data = dict(scan_row)
                
                # Calculate duration
                if scan_data.get('started_at') and scan_data.get('completed_at'):
                    start = datetime.fromisoformat(scan_data['started_at'])
                    end = datetime.fromisoformat(scan_data['completed_at'])
                    duration = end - start
                    scan_data['duration'] = str(duration).split('.')[0]  # Remove microseconds
                
                # Get unique secret count
                unique_count = conn.execute('''
                    SELECT COUNT(DISTINCT secret_id) as count
                    FROM findings
                    WHERE scan_run_id = ?
                ''', (scan_run_id,)).fetchone()
                scan_data['total_unique_secrets'] = unique_count['count'] if unique_count else 0
                
                # Get verified active count
                verified_count = conn.execute('''
                    SELECT COUNT(DISTINCT s.id) as count
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    WHERE f.scan_run_id = ?
                    AND s.is_verified = 1
                    AND s.is_active = 1
                ''', (scan_run_id,)).fetchone()
                scan_data['verified_active'] = verified_count['count'] if verified_count else 0
                
                # Parse domains JSON
                if scan_data.get('domains'):
                    try:
                        domains = json.loads(scan_data['domains'])
                        scan_data['domain'] = domains[0] if domains else 'Unknown'
                    except:
                        scan_data['domain'] = 'Unknown'
                
                # Add scan_id
                scan_data['scan_id'] = f"scan_{scan_run_id}_{scan_data.get('started_at', '').replace(':', '-').replace(' ', '_')}"
                scan_data['urls_scanned'] = scan_data.get('total_urls_scanned', 0)
                
                return scan_data
                
        except Exception as e:
            logger.error(f"Error getting scan summary from DB: {e}")
            return {}
    
    def _track_notification(self, scan_run_id: int, findings: List[Dict[str, Any]], 
                          notification_type: str):
        """
        Track sent notifications in database
        
        Args:
            scan_run_id: Scan run ID
            findings: List of findings
            notification_type: Type of notification
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Track overall notification
                conn.execute('''
                    INSERT INTO notification_history 
                    (scan_run_id, notification_type, status)
                    VALUES (?, ?, ?)
                ''', (scan_run_id, notification_type, 'sent'))
                
                # Track individual secrets if needed
                for finding in findings[:10]:  # Limit to prevent too many records
                    if 'secret_id' in finding:
                        conn.execute('''
                            INSERT INTO notification_history 
                            (scan_run_id, secret_id, notification_type, status)
                            VALUES (?, ?, ?, ?)
                        ''', (scan_run_id, finding['secret_id'], notification_type, 'sent'))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error tracking notification: {e}")
    
    def get_last_notification_time(self, scan_type: Optional[str] = None) -> Optional[datetime]:
        """
        Get the last notification time from database
        
        Args:
            scan_type: Optional scan type filter
            
        Returns:
            Last notification datetime or None
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                query = '''
                    SELECT MAX(sent_at) as last_sent
                    FROM notification_history
                    WHERE status = 'sent'
                '''
                
                if scan_type:
                    query += " AND notification_type = ?"
                    result = conn.execute(query, (scan_type,)).fetchone()
                else:
                    result = conn.execute(query).fetchone()
                
                if result and result[0]:
                    return datetime.fromisoformat(result[0])
                
                return None
                
        except Exception as e:
            logger.error(f"Error getting last notification time: {e}")
            return None
    
    def check_rate_limit(self) -> bool:
        """
        Check if we should wait before sending another notification
        
        Returns:
            True if OK to send, False if should wait
        """
        last_time = self.get_last_notification_time()
        if not last_time:
            return True
        
        time_since_last = (datetime.utcnow() - last_time).total_seconds()
        return time_since_last >= self.rate_limit_delay
    
    def send_findings_notification(self, findings: List[Dict[str, Any]], 
                                 notification_type: str = 'new',
                                 summary_data: Optional[Dict[str, Any]] = None) -> bool:
        """
        Send notification for findings with improved formatting
        
        Args:
            findings: List of findings
            notification_type: Type of notification ('new', 'summary', 'critical')
            summary_data: Additional summary data including scan_id
            
        Returns:
            True if successful
        """
        try:
            if not self.webhook_url:
                logger.warning("Cannot send notification: No webhook URL configured")
                return False
            
            if not findings and notification_type != 'summary':
                logger.info("No findings to notify")
                return True
            
            # Check rate limit
            if not self.check_rate_limit():
                logger.warning("Rate limit hit, skipping notification")
                return False
            
            # Prepare message based on type
            if notification_type == 'critical':
                message = self._prepare_critical_message(findings)
            elif notification_type == 'summary':
                message = self._prepare_summary_message(findings, summary_data)
            else:
                message = self._prepare_improved_findings_message(findings, notification_type, summary_data)
            
            # Send message
            success = self._send_slack_message(message)
            
            if success:
                self.stats['notifications_sent'] += 1
                self.stats['last_notification'] = datetime.utcnow().isoformat()
                logger.info(f"Sent {notification_type} notification for {len(findings)} findings")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            logger.exception(e)
            self.stats['notification_errors'].append({
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat(),
                'type': notification_type
            })
            return False
    
    def _prepare_improved_findings_message(self, findings: List[Dict[str, Any]], 
                                         notification_type: str,
                                         summary_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Prepare improved message focusing on unique findings
        
        Args:
            findings: List of findings
            notification_type: Type of notification
            summary_data: Additional summary data including scan_id
            
        Returns:
            Slack message payload
        """
        # Extract scan_id and domain for report URL
        scan_id = None
        domain = 'Unknown'
        if summary_data:
            scan_id = summary_data.get('scan_id')
            domain = summary_data.get('domain', 'Unknown')
        
        # Analyze findings
        analysis = self._analyze_findings_improved(findings)
    
        # If summary_data is provided and has total_unique_secrets, use that for consistency
        if summary_data and 'total_unique_secrets' in summary_data:
            analysis['total_unique'] = summary_data['total_unique_secrets']
        
        # Build message blocks
        blocks = []
        
        # Header with unique and new count
        if notification_type == 'new' or analysis['total_new'] > 0:
            header_text = f"🆕 {analysis['total_new']} New Secrets Detected ({analysis['total_unique']} Total)"
        else:
            header_text = f"🔍 {analysis['total_unique']} Secrets Detected"
        
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": header_text,
                "emoji": True
            }
        })
        
        # Scan metadata section
        if scan_id:
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"},
                    {"type": "mrkdwn", "text": f"*Domain:*\n{domain}"},
                    {"type": "mrkdwn", "text": f"*Date:*\n{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"},
                    {"type": "mrkdwn", "text": f"*URLs Scanned:*\n{summary_data.get('urls_scanned', 'N/A')}"}
                ]
            })
        
        # Report button
        report_url = self._get_report_url(scan_id)
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"📊 *Full Report:* View detailed findings with all occurrences"
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Open Report",
                    "emoji": True
                },
                "style": "primary",
                "url": report_url,
                "action_id": "open_report"
            }
        })
        
        blocks.append({"type": "divider"})
        
        # Summary section with unique counts only
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*📊 Summary*"
            }
        })
        
        # Add summary metrics
        summary_text = f"*Total Secrets Found:* {analysis['total_unique']}\n"
        summary_text += f"*New Secrets:* {analysis['total_new']}\n"
        if summary_data:
            summary_text += f"*URLs Scanned:* {summary_data.get('urls_scanned', 'N/A')}\n"
            if 'duration' in summary_data:
                summary_text += f"*Scan Duration:* {summary_data.get('duration', 'N/A')}"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": summary_text
            }
        })
        
        # Severity breakdown - cleaner format
        severity_text = self._format_severity_summary(analysis['by_severity_unique'])
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Severity Breakdown (Unique Only):*\n{severity_text}"
            }
        })
        
        blocks.append({"type": "divider"})
        
        # Secret findings section - organized by severity
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🔐 Findings by Type (Unique Only)*"
            }
        })
        
        # Sort findings by priority first (FIX: Added this line)
        sorted_findings = self._sort_findings_by_priority(analysis['groups'])
        
        # Group findings by severity for better organization
        findings_by_severity = defaultdict(list)
        for (secret_type, severity), group_data in sorted_findings:
            findings_by_severity[severity].append((secret_type, group_data))
        
        # Display findings organized by severity level
        finding_number = 1
        findings_shown = 0  # FIX: Initialize counter
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity not in findings_by_severity:
                continue
                
            # Add severity header
            severity_header = f"*{severity.capitalize()} Severity*"
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": severity_header
                }
            })
            
            # Add findings for this severity
            for secret_type, group_data in findings_by_severity[severity]:
                if findings_shown >= self.max_findings_per_message:
                    break
                
                formatted_type = secret_type.replace('_', ' ').replace('-', ' ').title()
                
                # Build finding text
                finding_text = [f"*{finding_number}. {formatted_type}*"]
                
                # Add count with new indicator
                count_line = f"• *Unique Count:* {group_data['unique_count']}"
                if group_data['new_count'] > 0:
                    count_line += f" ({group_data['new_count']} new)"
                finding_text.append(count_line)
                
                # Add status
                status_icon = self._get_status_icon(group_data['status'])
                finding_text.append(f"• *Status:* {status_icon} {group_data['status']}")
                
                # Add sample locations
                if group_data['urls']:
                    finding_text.append("• *Sample Locations:*")
                    for url_info in group_data['urls'][:2]:
                        finding_text.append(f"   • `{url_info['display']}`")
                    if len(group_data['urls']) > 2:
                        finding_text.append(f"   • [View all {len(group_data['urls'])} locations →]")
                
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "\n".join(finding_text)
                    }
                })
                
                finding_number += 1
                findings_shown += 1
        
        # Add "more findings" note if needed
        total_groups = len(analysis['groups'])
        if total_groups > self.max_findings_per_message:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"_... and {total_groups - self.max_findings_per_message} more secret types. <{report_url}|View full report> for details._"
                }]
            })
        
        # Footer with actions
        blocks.append({"type": "divider"})
        
        # Actions section
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*📎 Actions*"
            }
        })
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"• <{report_url}|🔗 View Detailed Findings>"
            }
        })
        
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"_Automated scan by DirHunterAI | Next scan: {summary_data.get('next_scan', '2025-05-30 01:55 UTC') if summary_data else '2025-05-30 01:55 UTC'}_"
            }]
        })
        
        # Build message
        message = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "blocks": blocks
        }
        
        # Add text fallback
        message["text"] = f"Secret Scan Alert: {analysis['total_unique']} unique secrets found"
        
        # Add mentions if needed
        if self._should_mention(findings):
            mention_text = self._get_mention_text(findings)
            message["text"] = f"{mention_text} - {message['text']}"
        
        return message
    
    def _analyze_findings_improved(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Improved analysis focusing on unique findings and new discoveries
        Fixed to work with redacted secrets from database
        
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'groups': {},  # Grouped by (type, severity)
            'by_severity_unique': defaultdict(int),
            'by_severity_new': defaultdict(int),
            'total_unique': 0,
            'total_new': 0,
            'total_verified': 0,
            'total_active': 0,
            'global_unique_secrets': set()  # Track ALL unique secrets globally by secret_id
        }
        
        # First pass: collect all unique secrets globally using secret_id instead of raw value
        for finding in findings:
            # Use secret_id or secret_hash for uniqueness since raw values are redacted
            secret_identifier = finding.get('secret_id') or finding.get('secret_hash', '')
            if secret_identifier:
                analysis['global_unique_secrets'].add(str(secret_identifier))
        
        # Set the correct total unique count
        analysis['total_unique'] = len(analysis['global_unique_secrets'])
        
        # Process each finding
        processed_secrets = set()  # Track processed secret_ids to avoid double counting
        
        for finding in findings:
            secret_type = finding.get('type', 'unknown')
            severity = finding.get('severity', 'unknown')
            secret_identifier = finding.get('secret_id') or finding.get('secret_hash', '')
            url = finding.get('url', '')
            baseline_status = finding.get('baseline_status', 'new')
            
            # Create group key
            group_key = (secret_type, severity)
            
            # Initialize group if needed
            if group_key not in analysis['groups']:
                analysis['groups'][group_key] = {
                    'unique_secrets': set(),
                    'unique_count': 0,
                    'new_count': 0,
                    'urls': [],
                    'verified_count': 0,
                    'status': 'Unknown',
                    'sample_findings': []
                }
            
            group = analysis['groups'][group_key]
            
            # Track unique secrets within this group using secret_id
            if secret_identifier and str(secret_identifier) not in group['unique_secrets']:
                group['unique_secrets'].add(str(secret_identifier))
                group['unique_count'] += 1
                
                # Only count for severity breakdown if this is the first time we see this secret
                # across ALL groups (to avoid double counting in severity stats)
                if str(secret_identifier) not in processed_secrets:
                    analysis['by_severity_unique'][severity] += 1
                    processed_secrets.add(str(secret_identifier))
                    
                    # Track if this unique secret is new
                    if baseline_status == 'new':
                        group['new_count'] += 1
                        analysis['by_severity_new'][severity] += 1
                        analysis['total_new'] += 1
                    
                    # Track verification status
                    if finding.get('verified') or finding.get('validation_result', {}).get('valid'):
                        group['verified_count'] += 1
                        analysis['total_verified'] += 1
                        if finding.get('validation_result', {}).get('active'):
                            analysis['total_active'] += 1
            
            # Track URLs (keep all occurrences but deduplicate)
            if url and url not in [u['url'] for u in group['urls']]:
                group['urls'].append({
                    'url': url,
                    'display': self._format_url_for_display(url)
                })
            
            # Keep sample findings (first 3 unique by secret_id)
            if len(group['sample_findings']) < 3:
                existing_ids = [f.get('secret_id') or f.get('secret_hash', '') for f in group['sample_findings']]
                if secret_identifier not in existing_ids:
                    group['sample_findings'].append(finding)
        
        # Determine status for each group
        for group_key, group in analysis['groups'].items():
            if group['verified_count'] > 0:
                group['status'] = "Active/Verified"
            elif any(f.get('validation_result', {}).get('valid') is False for f in group['sample_findings']):
                group['status'] = "Invalid/Inactive"
            else:
                group['status'] = "Not Verified"
        
        # Debug logging
        logger.debug(f"Analysis results: {analysis['total_unique']} unique, {analysis['total_new']} new")
        logger.debug(f"Groups: {list(analysis['groups'].keys())}")
        for (secret_type, severity), group in analysis['groups'].items():
            logger.debug(f"  {secret_type} ({severity}): {group['unique_count']} unique, {group['new_count']} new")
        
        return analysis
    
    def _create_clean_finding_block(self, secret_type: str, severity: str, 
                                   group_data: Dict) -> Dict[str, Any]:
        """
        Create clean Slack block focusing on unique counts
        
        Args:
            secret_type: Type of secret
            severity: Severity level
            group_data: Grouped finding data
            
        Returns:
            Slack block
        """
        emoji = self._get_severity_emoji(severity)
        status_icon = self._get_status_icon(group_data['status'])
        
        # Format secret type name
        formatted_type = secret_type.replace('_', ' ').replace('-', ' ').title()
        
        # Build main text
        text_lines = [
            f"{emoji} *{formatted_type}*"
        ]
        
        # Build count line with new indicator
        count_parts = [f"*Unique Count:* {group_data['unique_count']}"]
        if group_data['new_count'] > 0:
            count_parts.append(f"({group_data['new_count']} new)")
        
        text_lines.append(f"{' '.join(count_parts)} | *Status:* {status_icon} {group_data['status']}")
        
        # Add sample locations (limit to 3)
        if group_data['urls']:
            text_lines.append("*Sample Locations:*")
            for url_info in group_data['urls'][:3]:
                text_lines.append(f"• `{url_info['display']}`")
            
            if len(group_data['urls']) > 3:
                text_lines.append(f"• [View all {len(group_data['urls'])} locations →]")
        
        return {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "\n".join(text_lines)
            }
        }
    
    def _format_severity_summary(self, by_severity_unique: Dict[str, int]) -> str:
        """Format severity summary in bullet points"""
        severity_order = ['critical', 'high', 'medium', 'low']
        lines = []
        
        for severity in severity_order:
            count = by_severity_unique.get(severity, 0)
            if count > 0:
                emoji = self._get_severity_emoji(severity)
                lines.append(f"• {emoji} *{severity.capitalize()}:* {count}")
        
        return "\n".join(lines) if lines else "No findings"
    
    def _sort_findings_by_priority(self, groups: Dict) -> List[Tuple]:
        """Sort findings by severity and unique count"""
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
        
        return sorted(
            groups.items(),
            key=lambda x: (
                severity_order.get(x[0][1], 0),  # severity score
                x[1]['unique_count'],  # unique count
                x[0][0]  # secret type name (for consistent ordering)
            ),
            reverse=True
        )
    
    def _format_url_for_display(self, url: str) -> str:
        """Format URL for clean display"""
        if '#inline-script-' in url:
            parent_url = url.split('#')[0]
            script_num = url.split('#inline-script-')[1]
            # Shorten parent URL if too long
            if len(parent_url) > 50:
                domain = parent_url.split('/')[2] if '/' in parent_url else parent_url
                path = '/'.join(parent_url.split('/')[3:])
                if len(path) > 30:
                    path = '...' + path[-27:]
                parent_url = f"{domain}/{path}"
            return f"{parent_url} (inline script #{script_num})"
        else:
            # Regular URL - shorten if needed
            if len(url) > 60:
                parts = url.split('/')
                if len(parts) > 3:
                    domain = parts[2]
                    path = '/'.join(parts[3:])
                    if len(path) > 40:
                        path = '...' + path[-37:]
                    return f"{domain}/{path}"
            return url
    
    def _get_status_icon(self, status: str) -> str:
        """Get icon for status"""
        icons = {
            'Active/Verified': '✅',
            'Invalid/Inactive': '❌',
            'Not Verified': '⚠️',
            'Unknown': '❓'
        }
        return icons.get(status, '❓')
    
    def _prepare_summary_message(self, findings: List[Dict[str, Any]], 
                               summary_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Prepare clean summary message
        
        Args:
            findings: List of findings
            summary_data: Summary data
            
        Returns:
            Slack message payload
        """
        blocks = []
        
        # Analyze findings
        analysis = self._analyze_findings_improved(findings)
        
        # Header
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"✅ Secret Scan Completed",
                "emoji": True
            }
        })
        
        # Scan info
        scan_id = summary_data.get('scan_id', 'N/A') if summary_data else 'N/A'
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Scan ID:* `{scan_id}`"
            }
        })
        
        # Key metrics in a clean grid
        if summary_data:
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Duration:*\n{summary_data.get('duration', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*URLs Scanned:*\n{summary_data.get('urls_scanned', 0)}"},
                    {"type": "mrkdwn", "text": f"*Total New Unique Secrets:*\n{analysis['total_new']}"},  # Changed label
                    {"type": "mrkdwn", "text": f"*Verified Active:*\n{summary_data.get('verified_active', 0)}"}
                ]
            })
        
        # Severity breakdown
        if analysis['by_severity_unique']:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Severity Breakdown (Unique Only):*\n{self._format_severity_summary(analysis['by_severity_unique'])}"
                }
            })
        
        # Top findings
        sorted_findings = self._sort_findings_by_priority(analysis['groups'])[:3]
        if sorted_findings:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top Findings:*"
                }
            })
            
            for (secret_type, severity), group_data in sorted_findings:
                emoji = self._get_severity_emoji(severity)
                formatted_type = secret_type.replace('_', ' ').title()
                blocks.append({
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": f"{emoji} {formatted_type}: {group_data['unique_count']} unique"
                    }]
                })
        
        # Report link
        report_url = self._get_report_url(scan_id if summary_data else None)
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"📊 <{report_url}|View Full Report>"
            }
        })
        
        # Footer
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"Completed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
            }]
        })
        
        message = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": ":white_check_mark:",
            "blocks": blocks,
            "text": f"Scan completed: {analysis['total_unique']} unique secrets found"
        }
        
        return message
    
    def _prepare_critical_message(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Prepare critical alert message
        
        Args:
            findings: List of critical findings
            
        Returns:
            Slack message payload
        """
        blocks = []
        
        # Header
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 CRITICAL SECRETS DETECTED 🚨",
                "emoji": True
            }
        })
        
        # Critical finding details
        for finding in findings[:5]:  # Limit to 5 critical findings
            secret_type = finding.get('type', 'unknown').replace('_', ' ').title()
            url = finding.get('url', 'Unknown location')
            status = "✅ Verified Active" if finding.get('verified') else "⚠️ Not Verified"
            
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Type:* {secret_type}"},
                    {"type": "mrkdwn", "text": f"*Status:* {status}"},
                    {"type": "mrkdwn", "text": f"*Location:* `{self._format_url_for_display(url)}`"}
                ]
            })
            blocks.append({"type": "divider"})
        
        # Action required message
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "⚡ *IMMEDIATE ACTION REQUIRED* ⚡\nThese secrets should be rotated immediately!"
            }
        })
        
        message = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": ":rotating_light:",
            "blocks": blocks,
            "text": f"🚨 CRITICAL: {len(findings)} critical secrets detected! Immediate action required."
        }
        
        # Always mention for critical findings
        mentions = ["<!here>"] + [f"<@{user}>" for user in self.mention_users]
        message["text"] = f"{' '.join(mentions)} - " + message["text"]
        
        return message
    
    def _send_slack_message(self, message: Dict[str, Any]) -> bool:
        """Send message to Slack"""
        try:
            response = requests.post(
                self.webhook_url,
                json=message,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                logger.debug("Slack message sent successfully")
                time.sleep(self.rate_limit_delay)
                return True
            else:
                logger.error(f"Slack API error: {response.status_code} - {response.text}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Error sending Slack message: {e}")
            return False
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emojis = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵',
            'unknown': '⚪'
        }
        return emojis.get(severity.lower(), '⚪')
    
    def _should_mention(self, findings: List[Dict[str, Any]]) -> bool:
        """Check if mentions should be included"""
        if not self.mention_on_critical:
            return False
            
        for finding in findings:
            if finding.get('severity') in ['critical', 'high'] and finding.get('verified'):
                return True
        return False
    
    def _get_mention_text(self, findings: List[Dict[str, Any]]) -> str:
        """Get mention text for critical findings"""
        critical_count = sum(1 for f in findings if f.get('severity') == 'critical' and f.get('verified'))
        
        if critical_count > 0:
            mentions = ["<!here>"] + [f"<@{user}>" for user in self.mention_users]
            return f"{' '.join(mentions)} - {critical_count} critical verified secrets found!"
        else:
            high_count = sum(1 for f in findings if f.get('severity') == 'high' and f.get('verified'))
            if high_count > 0:
                mentions = [f"<@{user}>" for user in self.mention_users]
                return f"{' '.join(mentions)} - {high_count} high severity verified secrets detected"
        return ""
    
    def _get_base_url(self) -> str:
        """Get base URL for reports"""
        return self.slack_config.get('report_base_url', 'http://localhost:5000')
    
    def _get_report_url(self, scan_id: Optional[str] = None) -> str:
        """Get URL to full report with scan ID if available"""
        base_url = self._get_base_url()
        
        if scan_id:
            # Use consistent filename format
            return f"{base_url}/reports/{scan_id}_full_report.html"
        else:
            return f"{base_url}/reports/latest"
    
    def send_message(self, text: str, severity: str = 'info') -> bool:
        """
        Send a simple text message to Slack
        
        Args:
            text: Message text
            severity: Message severity for emoji selection
            
        Returns:
            True if successful
        """
        emoji_map = {
            'info': ':information_source:',
            'warning': ':warning:',
            'error': ':x:',
            'success': ':white_check_mark:',
            'critical': ':rotating_light:'
        }
        
        message = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": emoji_map.get(severity, self.icon_emoji),
            "text": text
        }
        
        return self._send_slack_message(message)
    
    def send_secret_alert(self, secret: Dict[str, Any]) -> bool:
        """
        Send alert for a single secret
        
        Args:
            secret: Secret finding dictionary
            
        Returns:
            True if successful
        """
        severity = secret.get('severity', 'unknown')
        secret_type = secret.get('type', 'unknown').replace('_', ' ').title()
        url = secret.get('url', 'Unknown location')
        
        emoji = self._get_severity_emoji(severity)
        status = "✅ Verified" if secret.get('verified') else "⚠️ Not Verified"
        
        text = (
            f"{emoji} *{severity.upper()} Security Alert*\n"
            f"*Type:* {secret_type}\n"
            f"*Status:* {status}\n"
            f"*Location:* `{self._format_url_for_display(url)}`"
        )
        
        if severity == 'critical':
            mentions = [f"<@{user}>" for user in self.mention_users]
            text = f"{' '.join(mentions)} - Critical secret detected!\n\n" + text
        
        return self.send_message(text, severity)
    
    def send_scan_started(self, domains: List[str], scan_type: str, scan_id: str = None) -> bool:
        """
        Send notification when scan starts
        
        Args:
            domains: List of domains being scanned
            scan_type: Type of scan
            scan_id: Scan ID
            
        Returns:
            True if successful
        """
        domain_list = ', '.join(domains[:3])
        if len(domains) > 3:
            domain_list += f' and {len(domains) - 3} more'
        
        text = f"🔍 Secret scan started\n"
        if scan_id:
            text += f"*Scan ID:* `{scan_id}`\n"
        text += f"*Domains:* {domain_list}\n"
        text += f"*Scan Type:* {scan_type}"
        
        return self.send_message(text, 'info')
    
    def send_scan_completed(self, summary_data: Dict[str, Any], scan_id: str = None) -> bool:
        """
        Send notification when scan completes
        
        Args:
            summary_data: Summary data
            scan_id: Scan ID
            
        Returns:
            True if successful
        """
        # Build a proper completion message that uses the summary data directly
        blocks = []
        
        # Header
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"✅ Secret Scan Completed",
                "emoji": True
            }
        })
        
        # Scan info
        scan_id = scan_id or summary_data.get('scan_id', 'N/A')
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Scan ID:* `{scan_id}`"
            }
        })
        
        # Key metrics
        blocks.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Duration:*\n{summary_data.get('duration', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*URLs Scanned:*\n{summary_data.get('urls_scanned', 0)}"},
                {"type": "mrkdwn", "text": f"*Total Secrets:*\n{summary_data.get('total_unique_secrets', 0)}"},
                {"type": "mrkdwn", "text": f"*Verified Active:*\n{summary_data.get('verified_active', 0)}"}
            ]
        })
        
        # Report link
        report_url = self._get_report_url(scan_id)
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"📊 <{report_url}|View Full Report>"
            }
        })
        
        # Footer
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"Completed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
            }]
        })
        
        message = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": ":white_check_mark:",
            "blocks": blocks,
            "text": f"Scan completed: {summary_data.get('total_unique_secrets', 0)} unique secrets found"
        }
        
        return self._send_slack_message(message)
    
    def send_scan_failed(self, error: str, scan_id: str = None, stage: str = None) -> bool:
        """
        Send notification when scan fails
        
        Args:
            error: Error message
            scan_id: Scan ID
            stage: Stage where failure occurred
            
        Returns:
            True if successful
        """
        text = f"❌ Secret scan failed\n"
        if scan_id:
            text += f"*Scan ID:* `{scan_id}`\n"
        if stage:
            text += f"*Failed Stage:* {stage}\n"
        text += f"*Error:* {error}"
        
        return self.send_message(text, 'error')
    
    def send_error_notification(self, error_type: str, error_details: str) -> bool:
        """
        Send error notification
        
        Args:
            error_type: Type of error
            error_details: Error details
            
        Returns:
            True if successful
        """
        text = f"⚠️ Scanner Error: {error_type}\n*Details:* {error_details}"
        return self.send_message(text, 'warning')
    
    def test_connection(self) -> bool:
        """
        Test Slack connection
        
        Returns:
            True if successful
        """
        test_message = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": "✅ Slack connection test successful! Secret scanner is ready."
        }
        
        return self._send_slack_message(test_message)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get notification statistics"""
        return self.stats