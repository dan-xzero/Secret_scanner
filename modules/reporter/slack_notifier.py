#!/usr/bin/env python3
"""
Enhanced Slack Notifier for Secret Scanner - Database Integrated Version with Precise URL Mapping
Focuses on unique findings with precise context, load methods, timing, and resource chains
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
    """Handles Slack notifications for secret findings with database integration and precise URL mapping"""
    
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
        self.db_path = db_path or Path(config.get('data_storage_path', './data')) / 'secrets_scanner.db'
        
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
            
            # Get findings from database with precise URL mapping
            findings = self._get_findings_from_db_with_precise_mapping(scan_run_id, notification_type)
            summary_data = self._get_scan_summary_from_db(scan_run_id)
            
            if not findings and notification_type != 'summary':
                logger.info("No findings to notify")
                return True
            
            # Send notification using enhanced method
            success = self.send_findings_notification(findings, notification_type, summary_data)
            
            # Track notification in database
            if success:
                self._track_notification(scan_run_id, findings, notification_type)
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending notification from DB: {e}")
            logger.exception(e)
            return False
    
    def _get_findings_from_db_with_precise_mapping(self, scan_run_id: int, notification_type: str) -> List[Dict[str, Any]]:
        """
        Enhanced method to get findings from database WITH precise URL mapping data
        
        Args:
            scan_run_id: Scan run ID
            notification_type: Type of notification
            
        Returns:
            List of findings with precise URL mapping context
        """
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                
                if notification_type == 'critical':
                    # Get critical findings with precise mapping
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
                            END as baseline_status,
                            -- Precise URL mapping data
                            pr.resource_url as precise_resource_url,
                            pr.load_method,
                            pr.load_timing_ms,
                            pr.referrer_url,
                            pr.resource_type,
                            pu.url as precise_parent_url,
                            jcm.webpack_chunk_id,
                            jcm.load_context,
                            CASE 
                                WHEN pr.id IS NOT NULL THEN 'exact'
                                ELSE 'fallback'
                            END as precision_level
                        FROM findings f
                        JOIN secrets s ON f.secret_id = s.id
                        JOIN urls u ON f.url_id = u.id
                        LEFT JOIN baselines b ON s.id = b.secret_id
                        LEFT JOIN page_resources pr ON (
                            f.file_path = pr.resource_filename 
                            AND f.scan_run_id = (
                                SELECT sr.id FROM scan_runs sr 
                                WHERE pr.scan_id = COALESCE(sr.id, 'scan_' || sr.id)
                            )
                        )
                        LEFT JOIN urls pu ON pr.parent_url_id = pu.id
                        LEFT JOIN js_chunk_metadata jcm ON (
                            pr.resource_filename = jcm.chunk_filename
                            AND pr.parent_url_id = jcm.parent_page_url_id
                        )
                        WHERE f.scan_run_id = ?
                        AND s.severity = 'critical'
                        AND s.is_active = 1
                        ORDER BY s.severity DESC, s.secret_type
                    '''
                    rows = conn.execute(query, (scan_run_id,)).fetchall()
                    
                elif notification_type == 'new':
                    # Get new findings with precise mapping
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
                            'new' as baseline_status,
                            -- Precise URL mapping data
                            pr.resource_url as precise_resource_url,
                            pr.load_method,
                            pr.load_timing_ms,
                            pr.referrer_url,
                            pr.resource_type,
                            pu.url as precise_parent_url,
                            jcm.webpack_chunk_id,
                            jcm.load_context,
                            CASE 
                                WHEN pr.id IS NOT NULL THEN 'exact'
                                ELSE 'fallback'
                            END as precision_level
                        FROM findings f
                        JOIN secrets s ON f.secret_id = s.id
                        JOIN urls u ON f.url_id = u.id
                        LEFT JOIN baselines b ON s.id = b.secret_id
                        LEFT JOIN page_resources pr ON (
                            f.file_path = pr.resource_filename 
                            AND f.scan_run_id = (
                                SELECT sr.id FROM scan_runs sr 
                                WHERE pr.scan_id = COALESCE(sr.id, 'scan_' || sr.id)
                            )
                        )
                        LEFT JOIN urls pu ON pr.parent_url_id = pu.id
                        LEFT JOIN js_chunk_metadata jcm ON (
                            pr.resource_filename = jcm.chunk_filename
                            AND pr.parent_url_id = jcm.parent_page_url_id
                        )
                        WHERE f.scan_run_id = ?
                        AND b.id IS NULL
                        ORDER BY s.severity DESC, s.secret_type
                    '''
                    rows = conn.execute(query, (scan_run_id,)).fetchall()
                    
                else:
                    # Get all findings for summary with precise mapping
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
                            END as baseline_status,
                            -- Precise URL mapping data
                            pr.resource_url as precise_resource_url,
                            pr.load_method,
                            pr.load_timing_ms,
                            pr.referrer_url,
                            pr.resource_type,
                            pu.url as precise_parent_url,
                            jcm.webpack_chunk_id,
                            jcm.load_context,
                            CASE 
                                WHEN pr.id IS NOT NULL THEN 'exact'
                                ELSE 'fallback'
                            END as precision_level
                        FROM findings f
                        JOIN secrets s ON f.secret_id = s.id
                        JOIN urls u ON f.url_id = u.id
                        LEFT JOIN baselines b ON s.id = b.secret_id
                        LEFT JOIN page_resources pr ON (
                            f.file_path = pr.resource_filename 
                            AND f.scan_run_id = (
                                SELECT sr.id FROM scan_runs sr 
                                WHERE pr.scan_id = COALESCE(sr.id, 'scan_' || sr.id)
                            )
                        )
                        LEFT JOIN urls pu ON pr.parent_url_id = pu.id
                        LEFT JOIN js_chunk_metadata jcm ON (
                            pr.resource_filename = jcm.chunk_filename
                            AND pr.parent_url_id = jcm.parent_page_url_id
                        )
                        WHERE f.scan_run_id = ?
                        ORDER BY s.severity DESC, s.secret_type
                        LIMIT 100
                    '''
                    rows = conn.execute(query, (scan_run_id,)).fetchall()
                
                # Convert rows to dictionaries with enhanced context
                findings = []
                for row in rows:
                    finding = dict(row)
                    
                    # Parse JSON fields
                    if finding.get('validation_result'):
                        try:
                            finding['validation_result'] = json.loads(finding['validation_result'])
                        except:
                            finding['validation_result'] = {}
                    
                    if finding.get('load_context'):
                        try:
                            finding['load_context'] = json.loads(finding['load_context'])
                        except:
                            finding['load_context'] = {}
                    
                    # For deduplication purposes, add a dummy 'raw' field
                    finding['raw'] = f"secret_{finding['secret_id']}"
                    
                    # Add file path from resource URL if available
                    if finding.get('precise_resource_url'):
                        finding['file_path'] = finding['precise_resource_url'].split('/')[-1]
                    elif not finding.get('file_path'):
                        finding['file_path'] = finding.get('url', '').split('/')[-1]
                    
                    findings.append(finding)
                
                logger.debug(f"Retrieved {len(findings)} findings with precise mapping for {notification_type}")
                return findings
                
        except Exception as e:
            logger.error(f"Error getting findings from DB with precise mapping: {e}")
            logger.exception(e)
            return []
    
    def _get_findings_from_db(self, scan_run_id: int, notification_type: str) -> List[Dict[str, Any]]:
        """
        Get findings from database for notification (legacy method for backward compatibility)
        
        Args:
            scan_run_id: Scan run ID
            notification_type: Type of notification
            
        Returns:
            List of findings
        """
        # Use the enhanced method with precise mapping
        return self._get_findings_from_db_with_precise_mapping(scan_run_id, notification_type)
    
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
    
    # ===== NEW PRECISE URL MAPPING HELPER METHODS =====
    
    def _get_load_method_emoji(self, load_method: str) -> str:
        """
        Get emoji for load method
        
        Args:
            load_method: Load method ('static', 'dynamic', 'fetch', 'xhr')
            
        Returns:
            Emoji string
        """
        emojis = {
            'static': '🔗',
            'dynamic': '⚡',
            'fetch': '🌐',
            'xhr': '🔄',
            'unknown': '❓'
        }
        return emojis.get(load_method, '❓')
    
    def _format_timing_badge(self, timing_ms: Optional[int]) -> str:
        """
        Format timing badge with color coding
        
        Args:
            timing_ms: Timing in milliseconds
            
        Returns:
            Formatted timing string
        """
        if timing_ms is None:
            return "⏱ Unknown"
        
        if timing_ms < 500:
            return f"🟢 {timing_ms}ms"  # Fast - Green
        elif timing_ms < 2000:
            return f"🟡 {timing_ms}ms"  # Medium - Yellow
        else:
            return f"🔴 {timing_ms}ms"  # Slow - Red
    
    def _format_precision_indicator(self, precision_level: str) -> str:
        """
        Format precision level indicator
        
        Args:
            precision_level: 'exact' or 'fallback'
            
        Returns:
            Formatted precision string
        """
        if precision_level == 'exact':
            return "✅ Exact Mapping"
        else:
            return "⚠️ Fallback Mapping"
    
    def _format_resource_chain(self, finding: Dict[str, Any]) -> str:
        """
        Format resource chain showing Page → JS Chunk → Secret
        
        Args:
            finding: Finding with precise mapping data
            
        Returns:
            Formatted resource chain
        """
        chain_parts = []
        
        # Parent page
        parent_url = finding.get('precise_parent_url')
        if parent_url:
            # Shorten URL for display
            parent_display = self._format_url_for_display(parent_url)
            chain_parts.append(parent_display)
        
        # Resource file
        resource_file = finding.get('file_path') or finding.get('precise_resource_url', '').split('/')[-1]
        if resource_file:
            chain_parts.append(resource_file)
        
        # Join with arrows
        if len(chain_parts) >= 2:
            return " → ".join(chain_parts)
        elif len(chain_parts) == 1:
            return chain_parts[0]
        else:
            return "Unknown chain"
    
    def _format_precise_context_alert(self, finding: Dict[str, Any]) -> str:
        """
        Format complete precise context for alert
        
        Args:
            finding: Finding with precise mapping data
            
        Returns:
            Formatted precise context
        """
        context_lines = []
        
        # Parent page
        parent_url = finding.get('precise_parent_url')
        if parent_url:
            context_lines.append(f"📍 *Parent Page:* {parent_url}")
        
        # Resource file
        resource_file = finding.get('file_path') or finding.get('precise_resource_url', '').split('/')[-1]
        if resource_file:
            context_lines.append(f"📄 *JS Chunk:* `{resource_file}`")
        
        # Load method and timing
        load_method = finding.get('load_method')
        timing_ms = finding.get('load_timing_ms')
        if load_method:
            load_emoji = self._get_load_method_emoji(load_method)
            timing_badge = self._format_timing_badge(timing_ms)
            context_lines.append(f"🔗 *Load:* {load_emoji} {load_method.title()} ({timing_badge})")
        
        # Resource chain
        chain = self._format_resource_chain(finding)
        if chain and "Unknown" not in chain:
            context_lines.append(f"🔍 *Trace:* {chain}")
        
        # Precision level
        precision = finding.get('precision_level', 'fallback')
        precision_indicator = self._format_precision_indicator(precision)
        context_lines.append(f"🎯 *Precision:* {precision_indicator}")
        
        return "\n".join(context_lines)
    
    # ===== END NEW METHODS =====
    
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
        Send notification for findings with improved formatting and precise URL mapping
        
        Args:
            findings: List of findings with precise mapping data
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
            
            # Prepare message based on type with precise context
            if notification_type == 'critical':
                message = self._prepare_enhanced_critical_message(findings)
            elif notification_type == 'summary':
                message = self._prepare_enhanced_summary_message(findings, summary_data)
            else:
                message = self._prepare_enhanced_findings_message(findings, notification_type, summary_data)
            
            # Send message
            success = self._send_slack_message(message)
            
            if success:
                self.stats['notifications_sent'] += 1
                self.stats['last_notification'] = datetime.utcnow().isoformat()
                logger.info(f"Sent {notification_type} notification for {len(findings)} findings with precise URL mapping")
            
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
    
    def _prepare_enhanced_findings_message(self, findings: List[Dict[str, Any]], 
                                         notification_type: str,
                                         summary_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Prepare enhanced message with precise URL mapping context
        
        Args:
            findings: List of findings with precise mapping data
            notification_type: Type of notification
            summary_data: Additional summary data including scan_id
            
        Returns:
            Slack message payload with precise context
        """
        # Extract scan_id and domain for report URL
        scan_id = None
        domain = 'Unknown'
        if summary_data:
            scan_id = summary_data.get('scan_id')
            domain = summary_data.get('domain', 'Unknown')
        
        # Analyze findings with precise context
        analysis = self._analyze_findings_with_precise_context(findings)
    
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
        
        # Enhanced scan metadata section with precise mapping stats
        if scan_id:
            precise_count = sum(1 for f in findings if f.get('precision_level') == 'exact')
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"},
                    {"type": "mrkdwn", "text": f"*Domain:*\n{domain}"},
                    {"type": "mrkdwn", "text": f"*Date:*\n{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"},
                    {"type": "mrkdwn", "text": f"*Precise Mappings:*\n✅ {precise_count}/{len(findings)}"}
                ]
            })
        
        # Report button
        report_url = self._get_report_url(scan_id)
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"📊 *Full Report:* View detailed findings with precise location context"
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
        
        # Enhanced summary section with precise mapping metrics
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*📊 Enhanced Summary*"
            }
        })
        
        # Add summary metrics with precise mapping info
        summary_text = f"*Total Secrets Found:* {analysis['total_unique']}\n"
        summary_text += f"*New Secrets:* {analysis['total_new']}\n"
        precise_count = sum(1 for f in findings if f.get('precision_level') == 'exact')
        summary_text += f"*Precise Mappings:* ✅ {precise_count} / ⚠️ {len(findings) - precise_count}\n"
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
        
        # Enhanced secret findings section with precise location cards
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🔐 Findings with Precise Location Context*"
            }
        })
        
        # Sort findings by priority
        sorted_findings = self._sort_findings_by_priority(analysis['groups'])
        
        # Group findings by severity for better organization
        findings_by_severity = defaultdict(list)
        for (secret_type, severity), group_data in sorted_findings:
            findings_by_severity[severity].append((secret_type, group_data))
        
        # Display findings organized by severity level with precise context
        finding_number = 1
        findings_shown = 0
        
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
            
            # Add findings for this severity with precise context
            for secret_type, group_data in findings_by_severity[severity]:
                if findings_shown >= self.max_findings_per_message:
                    break
                
                # Create enhanced finding block with precise context
                finding_block = self._create_enhanced_finding_block_with_precise_context(
                    finding_number, secret_type, severity, group_data
                )
                blocks.append(finding_block)
                
                finding_number += 1
                findings_shown += 1
        
        # Add "more findings" note if needed
        total_groups = len(analysis['groups'])
        if total_groups > self.max_findings_per_message:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"_... and {total_groups - self.max_findings_per_message} more secret types. <{report_url}|View full report> for complete precise location details._"
                }]
            })
        
        # Footer with enhanced actions
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
                "text": f"• <{report_url}|🔗 View Detailed Findings with Precise Location Context>"
            }
        })
        
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"_Automated scan with precise URL mapping by DirHunterAI | Next scan: {summary_data.get('next_scan', '2025-05-30 01:55 UTC') if summary_data else '2025-05-30 01:55 UTC'}_"
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
        message["text"] = f"Secret Scan Alert: {analysis['total_unique']} unique secrets found with precise location mapping"
        
        # Add mentions if needed
        if self._should_mention(findings):
            mention_text = self._get_mention_text(findings)
            message["text"] = f"{mention_text} - {message['text']}"
        
        return message
    
    def _create_enhanced_finding_block_with_precise_context(self, finding_number: int, secret_type: str, 
                                                          severity: str, group_data: Dict) -> Dict[str, Any]:
        """
        Create enhanced finding block with precise URL mapping context
        
        Args:
            finding_number: Finding number
            secret_type: Type of secret
            severity: Severity level
            group_data: Grouped finding data with precise context
            
        Returns:
            Enhanced Slack block with precise location details
        """
        emoji = self._get_severity_emoji(severity)
        status_icon = self._get_status_icon(group_data['status'])
        
        # Format secret type name
        formatted_type = self._format_secret_type_for_display(secret_type)
        # DEBUG: Log secret type formatting
        logger.debug(f"Formatting secret type: '{secret_type}' -> '{formatted_type}'")

        
        # Build main text with precise context
        text_lines = [
            f"{emoji} *{finding_number}. {formatted_type}*"
        ]
        
        # Build count line with new indicator
        count_parts = [f"*Unique Count:* {group_data['unique_count']}"]
        if group_data['new_count'] > 0:
            count_parts.append(f"({group_data['new_count']} new)")
        
        count_line = f"• {' '.join(count_parts)} | *Status:* {status_icon} {group_data['status']}"
        text_lines.append(count_line)
        
        # Add precise location context for sample finding
        if group_data.get('sample_findings'):
            sample_finding = group_data['sample_findings'][0]
            
            # Parent page
            parent_url = sample_finding.get('precise_parent_url')
            if parent_url:
                text_lines.append(f"• *📍 Parent Page:* `{self._format_url_for_display(parent_url)}`")
            
            # Resource file with load method
            resource_file = sample_finding.get('file_path')
            load_method = sample_finding.get('load_method')
            timing_ms = sample_finding.get('load_timing_ms')
            
            if resource_file:
                load_context = ""
                if load_method:
                    load_emoji = self._get_load_method_emoji(load_method)
                    timing_badge = self._format_timing_badge(timing_ms)
                    load_context = f" ({load_emoji} {load_method}, {timing_badge})"
                text_lines.append(f"• *📄 JS Chunk:* `{resource_file}`{load_context}")
            
            # Precision indicator
            precision_level = sample_finding.get('precision_level', 'fallback')
            precision_indicator = self._format_precision_indicator(precision_level)
            text_lines.append(f"• *🎯 Mapping:* {precision_indicator}")
        
        # Add sample locations (other URLs if multiple)
        if group_data['urls'] and len(group_data['urls']) > 1:
            text_lines.append("• *📄 Additional Locations:*")
            for url_info in group_data['urls'][1:3]:  # Show 2 more
                text_lines.append(f"   • `{url_info['display']}`")
            if len(group_data['urls']) > 3:
                text_lines.append(f"   • [View all {len(group_data['urls'])} locations →]")
        
        return {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "\n".join(text_lines)
            }
        }
    
    def _analyze_findings_with_precise_context(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Enhanced analysis including precise URL mapping context
        
        Returns:
            Dictionary with analysis results including precise mapping data
        """
        analysis = {
            'groups': {},  # Grouped by (type, severity)
            'by_severity_unique': defaultdict(int),
            'by_severity_new': defaultdict(int),
            'total_unique': 0,
            'total_new': 0,
            'total_verified': 0,
            'total_active': 0,
            'total_precise': 0,  # NEW: Count of precise mappings
            'global_unique_secrets': set()  # Track ALL unique secrets globally by secret_id
        }
        
        # First pass: collect all unique secrets globally using secret_id
        for finding in findings:
            secret_identifier = finding.get('secret_id') or finding.get('secret_hash', '')
            if secret_identifier:
                analysis['global_unique_secrets'].add(str(secret_identifier))
            
            # Count precise mappings
            if finding.get('precision_level') == 'exact':
                analysis['total_precise'] += 1
        
        # Set the correct total unique count
        analysis['total_unique'] = len(analysis['global_unique_secrets'])
        
        # Process each finding with precise context
        processed_secrets = set()
        
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
                    'sample_findings': [],  # Store sample findings with precise context
                    'precise_count': 0,  # NEW: Count of precise mappings in this group
                    'load_methods': set(),  # NEW: Track load methods
                    'avg_timing': 0  # NEW: Average load timing
                }
            
            group = analysis['groups'][group_key]
            
            # Track unique secrets within this group using secret_id
            if secret_identifier and str(secret_identifier) not in group['unique_secrets']:
                group['unique_secrets'].add(str(secret_identifier))
                group['unique_count'] += 1
                
                # Count precise mappings for this group
                if finding.get('precision_level') == 'exact':
                    group['precise_count'] += 1
                
                # Track load methods
                if finding.get('load_method'):
                    group['load_methods'].add(finding.get('load_method'))
                
                # Only count for severity breakdown if this is the first time we see this secret
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
            
            # Keep sample findings with precise context (first 3 unique by secret_id)
            if len(group['sample_findings']) < 3:
                existing_ids = [f.get('secret_id') or f.get('secret_hash', '') for f in group['sample_findings']]
                if secret_identifier not in existing_ids:
                    group['sample_findings'].append(finding)
        
        # Calculate average timing for each group
        for group_key, group in analysis['groups'].items():
            timings = []
            for finding in group['sample_findings']:
                timing = finding.get('load_timing_ms')
                if timing is not None:
                    timings.append(timing)
            group['avg_timing'] = sum(timings) / len(timings) if timings else 0
        
        # Determine status for each group
        for group_key, group in analysis['groups'].items():
            if group['verified_count'] > 0:
                group['status'] = "Active/Verified"
            elif any(f.get('validation_result', {}).get('valid') is False for f in group['sample_findings']):
                group['status'] = "Invalid/Inactive"
            else:
                group['status'] = "Not Verified"
        
        # Debug logging with precise context
        logger.debug(f"Enhanced analysis: {analysis['total_unique']} unique, {analysis['total_new']} new, {analysis['total_precise']} precise")
        for (secret_type, severity), group in analysis['groups'].items():
            logger.debug(f"  {secret_type} ({severity}): {group['unique_count']} unique, {group['precise_count']} precise")
        
        return analysis
    
    def _prepare_enhanced_critical_message(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Prepare enhanced critical alert message with precise URL mapping
        
        Args:
            findings: List of critical findings with precise mapping data
            
        Returns:
            Slack message payload with precise context
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
        
        # Enhanced critical finding details with precise context
        for i, finding in enumerate(findings[:5], 1):  # Limit to 5 critical findings
            secret_type = finding.get('type', 'unknown').replace('_', ' ').title()
            url = finding.get('url', 'Unknown location')
            status = "✅ Verified Active" if finding.get('verified') else "⚠️ Not Verified"
            
            # Create finding header
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🔴 Critical Finding #{i}: {secret_type}*"
                }
            })
            
            # Enhanced details with precise context
            precise_context = self._format_precise_context_alert(finding)
            if precise_context:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": precise_context
                    }
                })
            else:
                # Fallback to basic info
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
                "text": "⚡ *IMMEDIATE ACTION REQUIRED* ⚡\nThese secrets should be rotated immediately! Use precise location context above for faster remediation."
            }
        })
        
        message = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": ":rotating_light:",
            "blocks": blocks,
            "text": f"🚨 CRITICAL: {len(findings)} critical secrets detected with precise location context! Immediate action required."
        }
        
        # Always mention for critical findings
        mentions = ["<!here>"] + [f"<@{user}>" for user in self.mention_users]
        message["text"] = f"{' '.join(mentions)} - " + message["text"]
        
        return message
    
    def _prepare_enhanced_summary_message(self, findings: List[Dict[str, Any]], 
                                        summary_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Prepare enhanced summary message with precise URL mapping context
        
        Args:
            findings: List of findings with precise mapping data
            summary_data: Summary data
            
        Returns:
            Slack message payload with enhanced summary
        """
        blocks = []
        
        # Analyze findings with precise context
        analysis = self._analyze_findings_with_precise_context(findings)
        
        # Header
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"✅ Secret Scan Completed with Precise Mapping",
                "emoji": True
            }
        })
        
        # Enhanced scan info with precise mapping stats
        scan_id = summary_data.get('scan_id', 'N/A') if summary_data else 'N/A'
        precise_count = analysis.get('total_precise', 0)
        total_findings = len(findings)
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Scan ID:* `{scan_id}`\n*Precise Mappings:* ✅ {precise_count}/{total_findings} findings"
            }
        })
        
        # Enhanced key metrics with precise mapping
        if summary_data:
            blocks.append({
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Duration:*\n{summary_data.get('duration', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*URLs Scanned:*\n{summary_data.get('urls_scanned', 0)}"},
                    {"type": "mrkdwn", "text": f"*Total New Unique Secrets:*\n{analysis['total_new']}"},
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
        
        # Top findings with precise context
        sorted_findings = self._sort_findings_by_priority(analysis['groups'])[:3]
        if sorted_findings:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top Findings with Precise Context:*"
                }
            })
            
            for (secret_type, severity), group_data in sorted_findings:
                emoji = self._get_severity_emoji(severity)
                formatted_type = self._format_secret_type_for_display(secret_type)
        # DEBUG: Log secret type formatting
        logger.debug(f"Formatting secret type: '{secret_type}' -> '{formatted_type}'").title()
        precise_info = f"({group_data.get('precise_count', 0)} precise)"
        blocks.append({
                "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": f"{emoji} {formatted_type}: {group_data['unique_count']} unique {precise_info}"
                    }]
                })
        
        # Report link
        report_url = self._get_report_url(scan_id if summary_data else None)
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"📊 <{report_url}|View Full Report with Precise Location Details>"
            }
        })
        
        # Footer
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"Completed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC with precise URL mapping"
            }]
        })
        
        message = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": ":white_check_mark:",
            "blocks": blocks,
            "text": f"Scan completed: {analysis['total_unique']} unique secrets found with {precise_count} precise mappings"
        }
        
        return message
    
    # ===== KEEP ALL EXISTING METHODS =====
    
    def _prepare_improved_findings_message(self, findings: List[Dict[str, Any]], 
                                         notification_type: str,
                                         summary_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Legacy method - redirects to enhanced version for backward compatibility
        """
        return self._prepare_enhanced_findings_message(findings, notification_type, summary_data)
    
    def _analyze_findings_improved(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Legacy method - redirects to enhanced version for backward compatibility
        """
        return self._analyze_findings_with_precise_context(findings)
    
    def _create_clean_finding_block(self, secret_type: str, severity: str, 
                                   group_data: Dict) -> Dict[str, Any]:
        """
        Create clean Slack block focusing on unique counts (legacy method)
        
        Args:
            secret_type: Type of secret
            severity: Severity level
            group_data: Grouped finding data
            
        Returns:
            Slack block
        """
        # Use enhanced version if precise context is available
        if group_data.get('sample_findings'):
            return self._create_enhanced_finding_block_with_precise_context(1, secret_type, severity, group_data)
        
        # Fallback to basic version
        emoji = self._get_severity_emoji(severity)
        status_icon = self._get_status_icon(group_data['status'])
        
        # Format secret type name
        formatted_type = self._format_secret_type_for_display(secret_type)
        # DEBUG: Log secret type formatting
        logger.debug(f"Formatting secret type: '{secret_type}' -> '{formatted_type}'")

        
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
        Legacy method - redirects to enhanced version for backward compatibility
        """
        return self._prepare_enhanced_summary_message(findings, summary_data)
    
    def _prepare_critical_message(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Legacy method - redirects to enhanced version for backward compatibility
        """
        return self._prepare_enhanced_critical_message(findings)
    
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
        Send alert for a single secret with precise context if available
        
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
        
        # Check if we have precise context
        precise_context = self._format_precise_context_alert(secret)
        
        if precise_context:
            text = (
                f"{emoji} *{severity.upper()} Security Alert*\n"
                f"*Type:* {secret_type}\n"
                f"*Status:* {status}\n\n"
                f"*🎯 Precise Location Context:*\n"
                f"{precise_context}"
            )
        else:
            # Fallback to basic format
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
        
        text = f"🔍 Secret scan with precise URL mapping started\n"
        if scan_id:
            text += f"*Scan ID:* `{scan_id}`\n"
        text += f"*Domains:* {domain_list}\n"
        text += f"*Scan Type:* {scan_type}\n"
        text += f"*Features:* ✅ Precise URL mapping enabled"
        
        return self.send_message(text, 'info')
    
    def send_scan_completed(self, summary_data: Dict[str, Any], scan_id: str = None) -> bool:
        """
        Send notification when scan completes with enhanced context
        
        Args:
            summary_data: Summary data
            scan_id: Scan ID
            
        Returns:
            True if successful
        """
        # Use the enhanced summary message format
        blocks = []
        
        # Header
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"✅ Secret Scan Completed with Precise Mapping",
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
                "text": f"📊 <{report_url}|View Full Report with Precise Location Details>"
            }
        })
        
        # Footer
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"Completed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC with precise URL mapping"
            }]
        })
        
        message = {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": ":white_check_mark:",
            "blocks": blocks,
            "text": f"Scan completed: {summary_data.get('total_unique_secrets', 0)} unique secrets found with precise location mapping"
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
        text = f"❌ Secret scan with precise URL mapping failed\n"
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
            "text": "✅ Slack connection test successful! Secret scanner with precise URL mapping is ready."
        }
        
        return self._send_slack_message(test_message)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get notification statistics"""

    def _format_secret_type_for_display(self, secret_type: str) -> str:
        """
        FIXED: Format secret type for display using HTML generator's logic
        """
        if not secret_type:
            return "Unknown"
        
        # Apply same transformation as HTML generator template
        formatted = secret_type.replace('_', ' ').replace('-', ' ').title()
        
        # Additional normalization for common cases
        normalized_mapping = {
            'Cloudflareapitoken': 'Cloudflare API Token',
            'Genericapikey': 'Generic Api Key',
            'Genericsecret': 'Generic Secret',
            'Googleapikey': 'Google Api Key',
            'Slackwebhook': 'Slack Webhook',
            'Awsaccesskey': 'AWS Access Key',
            'Githubtoken': 'GitHub Token'
        }
        
        # Check if we need to apply additional normalization
        normalized_key = formatted.replace(' ', '').lower()
        for key, display_name in normalized_mapping.items():
            if normalized_key == key.lower():
                return display_name
        
        return formatted

    def _get_display_url_for_finding(self, finding: Dict[str, Any]) -> str:
        """
        FIXED: Get the best display URL for a finding (prioritize actual JS URLs)
        """
        # FIXED: Prioritize actual JS file URL from precise mapping
        if finding.get('precise_mapping', {}).get('resource_url'):
            return finding['precise_mapping']['resource_url']
        
        # Fallback to main URL
        if finding.get('url') and finding['url'] != 'Unknown':
            return finding['url']
        
        # Last resort: construct from file path
        if finding.get('file_path'):
            file_path = finding['file_path']
            if '/js/' in file_path:
                # Extract filename and try to construct URL
                filename = file_path.split('/js/')[-1]
                if finding.get('domain'):
                    return f"https://{finding['domain']}/js/{filename}"
            

    def _get_severity_priority(self, severity: str) -> int:
        """
        Get numeric priority for severity (lower number = higher priority)
        Critical=0, High=1, Medium=2, Low=3
        """
        severity_map = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3
        }
        return severity_map.get(severity.lower(), 999)
    def send_enhanced_findings_notification_with_baseline(self, summary_data: Dict[str, Any], baseline_comparison: Dict[str, int]) -> bool:
        """
        Send detailed Slack notification with baseline comparison and enhanced formatting.
        
        Args:
            summary_data: Complete scan summary data including findings
            baseline_comparison: Dictionary with new/recurring/resolved/false_positives counts
            
        Returns:
            bool: True if notification sent successfully
        """
        try:
            if not self.webhook_url:
                logger.warning("No Slack webhook URL configured")
                return False
                
            # Extract data
            findings = summary_data.get('findings', [])
            domain = summary_data.get('domain', 'Unknown')
            scan_type = summary_data.get('scan_type', 'full')
            scan_id = summary_data.get('scan_id', 'Unknown')
            
            new_count = baseline_comparison.get('new', 0)
            recurring_count = baseline_comparison.get('recurring', 0)
            resolved_count = baseline_comparison.get('resolved', 0)
            fp_count = baseline_comparison.get('false_positives', 0)
            
            # Determine overall status and styling
            if new_count > 0:
                status_emoji = "🚨"
                status_text = "NEW SECRETS DETECTED"
                color = "danger"
                urgency = "HIGH"
            elif recurring_count > 0:
                status_emoji = "⚠️"
                status_text = "RECURRING SECRETS MONITORED"
                color = "warning"
                urgency = "MEDIUM"
            elif resolved_count > 0:
                status_emoji = "✅"
                status_text = "SECRETS RESOLVED"
                color = "good"
                urgency = "LOW"
            else:
                status_emoji = "✅"
                status_text = "CLEAN SCAN COMPLETED"
                color = "good"
                urgency = "INFO"
            
            # Build main header
            header_text = f"{status_emoji} *{status_text}*\n"
            header_text += f"🎯 *Domain:* `{domain}`\n"
            header_text += f"🔍 *Scan Type:* {scan_type.title()}\n"
            header_text += f"📊 *Baseline Summary:* {new_count} new • {recurring_count} recurring • {resolved_count} resolved"
            
            if fp_count > 0:
                header_text += f" • {fp_count} filtered"
            
            # Create payload structure
            payload = {
                "username": self.username,
                "icon_emoji": self.icon_emoji,
                "attachments": [
                    {
                        "color": color,
                        "blocks": [
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": header_text
                                }
                            }
                        ]
                    }
                ]
            }
            
            # Add severity breakdown if there are current findings
            if findings:
                severity_breakdown = self._calculate_severity_breakdown_enhanced(findings)
                
                if any(count > 0 for count in severity_breakdown.values()):
                    severity_text = "*🎯 Severity Breakdown:*\n"
                    for severity, count in severity_breakdown.items():
                        if count > 0:
                            emoji = {"high": "🔴", "medium": "🟡", "low": "🟢", "critical": "🚫"}.get(severity.lower(), "⚪")
                            severity_text += f"{emoji} {severity.title()}: {count}\n"
                    
                    payload["attachments"][0]["blocks"].append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": severity_text
                        }
                    })
            
            # Add individual secret details for NEW findings only
            if new_count > 0:
                new_findings = [f for f in findings if f.get('baseline_status') == 'new']
                
                if new_findings:
                    secrets_text = "*🔍 New Secret Details:*\n"
                    # FIXED: Sort findings by severity (Critical > High > Medium > Low)
                    new_findings = sorted(new_findings, key=lambda f: self._get_severity_priority(f.get("severity", "low")))
                    for i, finding in enumerate(new_findings[:6], 1):  # Show up to 6 secrets
                        secret_type = self._format_secret_type_for_display(finding.get('secret_type', finding.get('type', 'unknown')))
                        file_path = finding.get('file_path', finding.get('url', 'Unknown'))
                        line_num = finding.get('line_number', 'N/A')
                        severity = finding.get('severity', 'medium').title()
                        
                        # Truncate long file paths for readability
                        display_path = self._get_display_url_for_finding(finding)
                        # FIXED: Only truncate if we dont have a proper web URL
                        if not display_path.startswith("http") and len(display_path) > 45:
                            display_path = "..." + display_path[-42:]
                        
                        # Use web icon for URLs, folder icon for file paths
                        icon = "🔗" if display_path.startswith("http") else "📁"
                        
                        secrets_text += f"`{i}.` *{secret_type}* ({severity})\n"
                        secrets_text += f"   {icon} `{display_path}:{line_num}`\n"
                    
                    if len(new_findings) > 6:
                        secrets_text += f"   ➕ ...and {len(new_findings) - 6} more new secrets\n"
                    
                    payload["attachments"][0]["blocks"].append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": secrets_text
                        }
                    })
            
            # Add mapping precision statistics
            total_findings = len(findings)
            if total_findings > 0:
                precise_count = len([f for f in findings if f.get('file_path')])
                fuzzy_count = total_findings - precise_count
                
                if total_findings > 0:
                    precision_percent = (precise_count / total_findings) * 100
                    mapping_text = f"*🎯 Mapping Precision:*\n"
                    mapping_text += f"📍 Precise: {precise_count} ({precision_percent:.0f}%) • 🔄 Fuzzy: {fuzzy_count}"
                    
                    payload["attachments"][0]["blocks"].append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": mapping_text
                        }
                    })
            
            # Add scan details and actions
            duration = summary_data.get('duration', 'Unknown')
            urls_scanned = summary_data.get('urls_scanned', 0)
            
            action_text = f"*📋 Scan Details:*\n"
            action_text += f"🔍 Scan ID: `{scan_id}`\n"
            action_text += f"⏱️ Duration: {duration}\n"
            action_text += f"🔗 URLs Processed: {urls_scanned}\n"
            action_text += f"📊 Report: Available in dashboard"
            
            payload["attachments"][0]["blocks"].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": action_text
                }
            })
            
            # Add critical mentions for high-priority new findings
            if new_count > 0:
                critical_new = [f for f in findings 
                              if f.get('baseline_status') == 'new' 
                              and f.get('severity', '').lower() in ['critical', 'high']]
                
                if critical_new and self.mention_on_critical and self.mention_users:
                    mention_text = " ".join([f"<@{user}>" for user in self.mention_users])
                    payload["text"] = f"{mention_text} {len(critical_new)} critical/high severity secrets detected!"
            
            # Send the notification
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Enhanced baseline Slack notification sent for {domain} "
                           f"({new_count} new, {recurring_count} recurring, {resolved_count} resolved)")
                
                # Record notification if tracking table exists
                try:
                    self._record_notification_enhanced(scan_id, 'enhanced_baseline', 'sent', baseline_comparison)
                except:
                    pass  # Non-critical
                
                return True
            else:
                logger.error(f"Failed to send enhanced Slack notification. "
                            f"Status: {response.status_code}, Response: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending enhanced baseline Slack notification: {e}")
            return False

    def _calculate_severity_breakdown_enhanced(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate enhanced severity breakdown from findings."""
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for finding in findings:
            severity = finding.get('severity', 'medium').lower()
            if severity in breakdown:
                breakdown[severity] += 1
            else:
                breakdown['medium'] += 1  # Default unknown to medium
        
        return breakdown

    def _record_notification_enhanced(self, scan_id: str, notification_type: str, status: str, 
                                     baseline_data: Dict[str, int]) -> None:
        """Record enhanced notification with baseline data."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Check if notification_history table exists
            table_check = conn.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='notification_history'
            """).fetchone()
            
            if table_check:
                message_summary = f"New:{baseline_data.get('new',0)} Recurring:{baseline_data.get('recurring',0)} Resolved:{baseline_data.get('resolved',0)}"
                
                conn.execute("""
                INSERT INTO notification_history 
                (scan_run_id, notification_type, sent_at, status, message_id)
                VALUES (?, ?, ?, ?, ?)
                """, (scan_id, notification_type, datetime.now().isoformat(), status, message_summary))
                
                conn.commit()
            conn.close()
            
        except Exception as e:
            logger.debug(f"Could not record enhanced notification: {e}")  # Non-critical
