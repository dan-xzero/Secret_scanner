#!/usr/bin/env python3
"""
Enhanced HTML Report Generator for Secret Scanner
Generates interactive HTML reports with deduplication for secret findings
"""

import os
import json
import base64
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from collections import defaultdict
import hashlib
from jinja2 import Template
from loguru import logger

class HTMLReportGenerator:
    """Generates interactive HTML reports for secret findings with deduplication"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize HTML Report Generator
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.reports_path = Path(config.get('data_storage_path', './data')) / 'reports'
        self.reports_path.mkdir(parents=True, exist_ok=True)
        
        # Report settings - ALWAYS show secrets
        self.company_name = config.get('report', {}).get('company_name', 'Security Team')
        self.show_secrets = True  # Always show actual secrets
        self.max_findings_per_page = config.get('report', {}).get('max_findings_per_page', 100)
        self.enable_deduplication = config.get('report', {}).get('enable_deduplication', True)
        
        # Statistics
        self.stats = {
            'reports_generated': 0,
            'generation_errors': []
        }
        
        logger.info(f"Enhanced HTML Report Generator initialized with reports path: {self.reports_path}")
    
    def generate_report(self, findings: List[Dict[str, Any]], 
                   report_type: str = 'full',
                   comparison_data: Optional[Dict[str, Any]] = None,
                   validation_results: Optional[Dict[str, Any]] = None,
                    scan_id: Optional[str] = None) -> Path:
        """
        Generate HTML report with optional deduplication
        
        Args:
            findings: List of findings
            report_type: Type of report ('full', 'new', 'summary')
            comparison_data: Baseline comparison data
            validation_results: Validation results
            scan_id: Scan ID to use in filename
            
        Returns:
            Path to generated report
        """
        try:
            logger.info(f"Generating {report_type} HTML report for {len(findings)} findings")
            
            # Prepare report data with or without deduplication
            if self.enable_deduplication:
                report_data = self._prepare_deduplicated_report_data(
                    findings, report_type, comparison_data, validation_results
                )
            else:
                report_data = self._prepare_report_data(
                    findings, report_type, comparison_data, validation_results
                )
            
            # Add scan_id to report data
            if scan_id:
                report_data['scan_id'] = scan_id
            
            # Generate HTML
            html_content = self._render_html(report_data)
            
            # Save report with scan_id
            report_file = self._save_report(html_content, report_type, scan_id)
            
            # Update statistics
            self.stats['reports_generated'] += 1
            
            logger.info(f"Generated HTML report: {report_file}")
            return report_file
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            logger.exception(e)
            self.stats['generation_errors'].append({
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
            return None

    def _save_report(self, html_content: str, report_type: str, scan_id: Optional[str] = None) -> Path:
        """
        Save HTML report to file
        
        Args:
            html_content: HTML content
            report_type: Type of report
            scan_id: Scan ID to use in filename
            
        Returns:
            Path to saved report
        """
        if scan_id:
            # Use scan_id for consistent naming
            filename = f"{scan_id}_{report_type}_report.html"
        else:
            # Fallback to timestamp if no scan_id provided
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"secrets_report_{report_type}_{timestamp}.html"
        
        report_file = self.reports_path / filename
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_file
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Deduplicate findings by grouping identical secrets
        Returns dict keyed by secret hash with aggregated data
        """
        deduplicated = {}
        
        for finding in findings:
            # Get the actual secret value
            secret_value = finding.get('raw', finding.get('secret', 'N/A'))
            if secret_value == 'N/A':
                continue
                
            # Create a hash of the secret for grouping
            secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()[:16]
            
            if secret_hash not in deduplicated:
                # Initialize the deduplicated entry
                deduplicated[secret_hash] = {
                    'secret': secret_value,
                    'secret_display': secret_value,  # Full secret
                    'redacted': finding.get('redacted', self._redact_secret(secret_value)),
                    'type': finding.get('type', 'unknown'),
                    'severity': finding.get('severity', 'unknown'),
                    'occurrences': [],
                    'detection_tools': set(),
                    'unique_files': set(),
                    'unique_urls': set(),
                    'total_count': 0,
                    'verified_count': 0,
                    'first_seen': finding.get('timestamp', datetime.utcnow().timestamp()),
                    'validation_results': [],
                    'highest_confidence': 'low',
                    'risk_scores': [],
                    'baseline_status': 'unknown'
                }
            
            # Add this occurrence
            occurrence = {
                'id': finding.get('id', ''),
                'file_path': finding.get('file', finding.get('file_path', 'Unknown')),
                'relative_path': finding.get('relative_path', ''),
                'url': finding.get('url', ''),
                'line': finding.get('line', finding.get('line_number', 0)),
                'column': finding.get('column', 0),
                'context': finding.get('context', ''),
                'tool': finding.get('detector', finding.get('tool', 'unknown')),
                'confidence': finding.get('confidence', 'unknown'),
                'timestamp': finding.get('timestamp', datetime.utcnow().timestamp()),
                'validation_result': finding.get('validation_result', {}),
                'baseline_status': finding.get('baseline_status', 'unknown')
            }
            
            deduplicated[secret_hash]['occurrences'].append(occurrence)
            deduplicated[secret_hash]['total_count'] += 1
            
            # Track detection tools
            deduplicated[secret_hash]['detection_tools'].add(occurrence['tool'])
            
            # Track unique locations
            if occurrence['file_path']:
                deduplicated[secret_hash]['unique_files'].add(occurrence['file_path'])
            if occurrence['url']:
                deduplicated[secret_hash]['unique_urls'].add(occurrence['url'])
            
            # Track validation results
            if occurrence['validation_result']:
                deduplicated[secret_hash]['validation_results'].append(occurrence['validation_result'])
                if occurrence['validation_result'].get('valid'):
                    deduplicated[secret_hash]['verified_count'] += 1
            
            # Update highest confidence
            confidence_levels = {'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
            current_conf = confidence_levels.get(occurrence['confidence'], 0)
            highest_conf = confidence_levels.get(deduplicated[secret_hash]['highest_confidence'], 0)
            if current_conf > highest_conf:
                deduplicated[secret_hash]['highest_confidence'] = occurrence['confidence']
            
            # Track risk scores
            if 'risk_score' in finding:
                deduplicated[secret_hash]['risk_scores'].append(finding['risk_score'])
            
            # Update baseline status (prefer 'new' over 'recurring' over 'unknown')
            if occurrence['baseline_status'] == 'new':
                deduplicated[secret_hash]['baseline_status'] = 'new'
            elif occurrence['baseline_status'] == 'recurring' and deduplicated[secret_hash]['baseline_status'] != 'new':
                deduplicated[secret_hash]['baseline_status'] = 'recurring'
        
        # Post-process deduplicated data
        for secret_hash, data in deduplicated.items():
            # Convert sets to sorted lists
            data['detection_tools'] = sorted(list(data['detection_tools']))
            data['unique_files'] = sorted(list(data['unique_files']))
            data['unique_urls'] = sorted(list(data['unique_urls']))
            
            # Calculate aggregated risk score
            if data['risk_scores']:
                data['avg_risk_score'] = sum(data['risk_scores']) / len(data['risk_scores'])
                data['max_risk_score'] = max(data['risk_scores'])
            else:
                data['avg_risk_score'] = 0
                data['max_risk_score'] = 0
            
            # Determine overall validation status
            if data['verified_count'] > 0:
                data['overall_validation_status'] = 'Verified Active'
                data['validation_class'] = 'verified'
            elif data['validation_results']:
                data['overall_validation_status'] = 'Invalid/Inactive'
                data['validation_class'] = 'invalid'
            else:
                data['overall_validation_status'] = 'Not Validated'
                data['validation_class'] = 'not-validated'
            
            # Sort occurrences by timestamp
            data['occurrences'].sort(key=lambda x: x['timestamp'])
        
        return deduplicated
    
    def _redact_secret(self, secret: str) -> str:
        """Redact a secret value for display"""
        if len(secret) <= 8:
            return '*' * len(secret)
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
    
    def _prepare_deduplicated_report_data(self, findings: List[Dict[str, Any]], 
                                        report_type: str,
                                        comparison_data: Optional[Dict[str, Any]],
                                        validation_results: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare report data with deduplication"""
        try:
            # Deduplicate findings
            deduplicated = self._deduplicate_findings(findings)
            
            # Convert deduplicated dict to list and sort
            findings_list = list(deduplicated.values())
            
            # Sort by severity first, then by occurrence count
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}
            findings_list.sort(key=lambda x: (
                severity_order.get(x['severity'], 4),
                -x['total_count'],  # More occurrences first
                -x.get('max_risk_score', 0)
            ))
            
            # Calculate enhanced statistics
            stats = self._calculate_enhanced_statistics(deduplicated, findings)
            
            # Prepare report data
            report_data = {
                'report_type': report_type,
                'generated_at': datetime.utcnow().isoformat(),
                'generated_at_formatted': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                'company_name': self.company_name,
                'total_raw_findings': len(findings),
                'total_unique_secrets': len(deduplicated),
                'findings': findings_list,
                'statistics': stats,
                'charts_data': self._prepare_enhanced_charts_data(deduplicated),
                'max_findings_per_page': self.max_findings_per_page,
                'deduplicated': True
            }
            
            # Add comparison data if available
            if comparison_data:
                report_data['comparison'] = {
                    'new_count': len(comparison_data.get('new', [])),
                    'recurring_count': len(comparison_data.get('recurring', [])),
                    'resolved_count': len(comparison_data.get('resolved', []))
                }
            
            return report_data
            
        except Exception as e:
            logger.error(f"Error preparing deduplicated report data: {e}")
            # Fall back to non-deduplicated report
            return self._prepare_report_data(findings, report_type, comparison_data, validation_results)
    
    def _calculate_enhanced_statistics(self, deduplicated: Dict[str, Dict[str, Any]], 
                                     raw_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate enhanced statistics with deduplication info"""
        stats = {
            'total_raw_findings': len(raw_findings),
            'total_unique_secrets': len(deduplicated),
            'total': len(deduplicated),  # For backward compatibility
            'deduplication_ratio': f"{(1 - len(deduplicated)/len(raw_findings) if raw_findings else 0)*100:.1f}%",
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'by_tool': defaultdict(int),
            'by_validation_status': defaultdict(int),
            'verified': 0,
            'critical_count': 0,
            'high_count': 0,
            'unique_files': set(),
            'unique_urls': set(),
            'total_occurrences': 0
        }
        
        for secret_data in deduplicated.values():
            # Count by type
            stats['by_type'][secret_data['type']] += 1
            
            # Count by severity
            severity = secret_data['severity']
            stats['by_severity'][severity] += 1
            
            if severity == 'critical':
                stats['critical_count'] += 1
            elif severity == 'high':
                stats['high_count'] += 1
            
            # Count by validation status
            stats['by_validation_status'][secret_data['overall_validation_status']] += 1
            if secret_data['verified_count'] > 0:
                stats['verified'] += 1
            
            # Count by tools
            for tool in secret_data['detection_tools']:
                stats['by_tool'][tool] += 1
            
            # Aggregate locations
            stats['unique_files'].update(secret_data['unique_files'])
            stats['unique_urls'].update(secret_data['unique_urls'])
            
            # Total occurrences
            stats['total_occurrences'] += secret_data['total_count']
        
        # Convert sets to counts
        stats['unique_files'] = len(stats['unique_files'])
        stats['unique_urls'] = len(stats['unique_urls'])
        
        # Convert defaultdicts to regular dicts
        stats['by_type'] = dict(stats['by_type'])
        stats['by_severity'] = dict(stats['by_severity'])
        stats['by_tool'] = dict(stats['by_tool'])
        stats['by_validation_status'] = dict(stats['by_validation_status'])
        
        return stats
    
    def _prepare_enhanced_charts_data(self, deduplicated: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare enhanced charts data including validation and occurrence distribution"""
        charts_data = {
            'severity_chart': [],
            'type_chart': [],
            'tool_chart': [],
            'validation_chart': [],
            'occurrence_distribution': []
        }
        
        if not deduplicated:
            # Return default empty data
            return {
                'severity_chart': [{'label': 'None', 'value': 0, 'color': '#95a5a6'}],
                'type_chart': [{'label': 'None', 'value': 0}],
                'tool_chart': [{'label': 'None', 'value': 0}],
                'validation_chart': [{'label': 'None', 'value': 0, 'color': '#95a5a6'}],
                'occurrence_distribution': [{'label': 'None', 'value': 0}]
            }
        
        # Severity chart
        severity_counts = defaultdict(int)
        for secret_data in deduplicated.values():
            severity_counts[secret_data['severity']] += 1
        
        severity_colors = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#95a5a6',
            'unknown': '#95a5a6'
        }
        
        for severity, count in severity_counts.items():
            charts_data['severity_chart'].append({
                'label': severity.capitalize(),
                'value': count,
                'color': severity_colors.get(severity, '#95a5a6')
            })
        
        # Type chart (top 10)
        type_counts = defaultdict(int)
        for secret_data in deduplicated.values():
            type_counts[secret_data['type']] += 1
        
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for ftype, count in sorted_types:
            charts_data['type_chart'].append({
                'label': ftype.replace('_', ' ').replace('-', ' ').title(),
                'value': count
            })
        
        # Tool chart
        tool_counts = defaultdict(int)
        for secret_data in deduplicated.values():
            for tool in secret_data['detection_tools']:
                tool_counts[tool] += 1
        
        for tool, count in tool_counts.items():
            charts_data['tool_chart'].append({
                'label': tool,
                'value': count
            })
        
        # Validation status chart
        validation_counts = defaultdict(int)
        for secret_data in deduplicated.values():
            validation_counts[secret_data['overall_validation_status']] += 1
        
        validation_colors = {
            'Verified Active': '#e74c3c',
            'Invalid/Inactive': '#27ae60',
            'Not Validated': '#95a5a6'
        }
        
        for status, count in validation_counts.items():
            charts_data['validation_chart'].append({
                'label': status,
                'value': count,
                'color': validation_colors.get(status, '#95a5a6')
            })
        
        # Occurrence distribution
        occurrence_ranges = {
            '1 occurrence': 0,
            '2-5 occurrences': 0,
            '6-10 occurrences': 0,
            '10+ occurrences': 0
        }
        
        for secret_data in deduplicated.values():
            count = secret_data['total_count']
            if count == 1:
                occurrence_ranges['1 occurrence'] += 1
            elif count <= 5:
                occurrence_ranges['2-5 occurrences'] += 1
            elif count <= 10:
                occurrence_ranges['6-10 occurrences'] += 1
            else:
                occurrence_ranges['10+ occurrences'] += 1
        
        for label, count in occurrence_ranges.items():
            if count > 0:
                charts_data['occurrence_distribution'].append({
                    'label': label,
                    'value': count
                })
        
        # Ensure all charts have data
        for chart_name in charts_data:
            if not charts_data[chart_name]:
                charts_data[chart_name] = [{'label': 'None', 'value': 0, 'color': '#95a5a6'}]
        
        return charts_data
    
    def _prepare_report_data(self, findings: List[Dict[str, Any]], 
                           report_type: str,
                           comparison_data: Optional[Dict[str, Any]],
                           validation_results: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Prepare data for report generation (original non-deduplicated version)
        
        Args:
            findings: List of findings
            report_type: Type of report
            comparison_data: Baseline comparison data
            validation_results: Validation results
            
        Returns:
            Report data dictionary
        """
        try:
            # Basic report data
            report_data = {
                'report_type': report_type,
                'generated_at': datetime.utcnow().isoformat(),
                'generated_at_formatted': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                'company_name': self.company_name,
                'total_findings': len(findings),
                'findings': [],
                'statistics': self._calculate_statistics(findings),
                'charts_data': self._prepare_charts_data(findings),
                'max_findings_per_page': self.max_findings_per_page,
                'deduplicated': False
            }
            
            # Process findings
            for finding in findings:
                processed_finding = finding.copy()
                
                # Always show actual secret
                processed_finding['secret_display'] = processed_finding.get('secret', processed_finding.get('raw', 'N/A'))
                
                # Ensure URL is included
                if not processed_finding.get('url') and processed_finding.get('file_path'):
                    # Try to extract URL from file path or other metadata
                    if 'file' in processed_finding:
                        processed_finding['url'] = processed_finding['file']
                    elif 'location' in processed_finding:
                        processed_finding['url'] = processed_finding['location']
                
                # Add validation status
                if validation_results and 'validation_result' in processed_finding:
                    val_result = processed_finding['validation_result']
                    processed_finding['validation_status'] = self._get_validation_status(val_result)
                
                report_data['findings'].append(processed_finding)
            
            # Add comparison data if available
            if comparison_data:
                report_data['comparison'] = {
                    'new_count': len(comparison_data.get('new', [])),
                    'recurring_count': len(comparison_data.get('recurring', [])),
                    'resolved_count': len(comparison_data.get('resolved', []))
                }
            
            # Add validation summary if available
            if validation_results:
                report_data['validation_summary'] = validation_results.get('summary', {})
            
            # Sort findings by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            report_data['findings'].sort(
                key=lambda x: severity_order.get(x.get('severity', 'low'), 4)
            )
            
            return report_data
            
        except Exception as e:
            logger.error(f"Error preparing report data: {e}")
            return {
                'report_type': report_type,
                'generated_at': datetime.utcnow().isoformat(),
                'generated_at_formatted': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                'error': str(e),
                'findings': [],
                'statistics': {'total': 0, 'by_type': {}, 'by_severity': {}, 'by_tool': {}, 'verified': 0, 'critical_count': 0, 'unique_files': 0, 'unique_urls': 0},
                'charts_data': {'severity_chart': [], 'type_chart': [], 'tool_chart': []}
            }
    
    def _calculate_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate statistics from findings (original version)
        
        Args:
            findings: List of findings
            
        Returns:
            Statistics dictionary
        """
        stats = {
            'total': len(findings),
            'by_type': {},
            'by_severity': {},
            'by_tool': {},
            'verified': 0,
            'critical_count': 0,
            'unique_files': set(),
            'unique_urls': set()
        }
        
        for finding in findings:
            # By type
            ftype = finding.get('type', 'unknown')
            stats['by_type'][ftype] = stats['by_type'].get(ftype, 0) + 1
            
            # By severity
            severity = finding.get('severity', 'unknown')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # By tool
            tool = finding.get('tool', finding.get('detector', 'unknown'))
            stats['by_tool'][tool] = stats['by_tool'].get(tool, 0) + 1
            
            # Verified count
            if finding.get('verified') or finding.get('validation_result', {}).get('valid'):
                stats['verified'] += 1
            
            # Critical findings
            if severity in ['critical', 'high']:
                stats['critical_count'] += 1
            
            # Unique locations
            if finding.get('file_path'):
                stats['unique_files'].add(finding['file_path'])
            if finding.get('url'):
                stats['unique_urls'].add(finding['url'])
        
        # Convert sets to counts
        stats['unique_files'] = len(stats['unique_files'])
        stats['unique_urls'] = len(stats['unique_urls'])
        
        return stats
    
    def _prepare_charts_data(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Prepare data for charts (original version)
        
        Args:
            findings: List of findings
            
        Returns:
            Charts data dictionary
        """
        # If deduplication is enabled, delegate to enhanced version
        if self.enable_deduplication and isinstance(findings, dict):
            return self._prepare_enhanced_charts_data(findings)
            
        charts_data = {
            'severity_chart': [],
            'type_chart': [],
            'tool_chart': []
        }
        
        if not findings:
            # Return default data if no findings
            return {
                'severity_chart': [{'label': 'None', 'value': 0, 'color': '#95a5a6'}],
                'type_chart': [{'label': 'None', 'value': 0}],
                'tool_chart': [{'label': 'None', 'value': 0}]
            }
        
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Prepare severity chart data
        severity_colors = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#95a5a6',
            'unknown': '#95a5a6'
        }
        
        for severity, count in severity_counts.items():
            charts_data['severity_chart'].append({
                'label': severity.capitalize(),
                'value': count,
                'color': severity_colors.get(severity, '#95a5a6')
            })
        
        # Count by type (top 10)
        type_counts = {}
        for finding in findings:
            ftype = finding.get('type', 'unknown')
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
        
        # Sort and take top 10
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for ftype, count in sorted_types:
            charts_data['type_chart'].append({
                'label': ftype,
                'value': count
            })
        
        # Count by tool
        tool_counts = {}
        for finding in findings:
            tool = finding.get('tool', finding.get('detector', 'unknown'))
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        for tool, count in tool_counts.items():
            charts_data['tool_chart'].append({
                'label': tool,
                'value': count
            })
        
        # Ensure we have data for charts even if empty
        if not charts_data['severity_chart']:
            charts_data['severity_chart'] = [{'label': 'None', 'value': 0, 'color': '#95a5a6'}]
        if not charts_data['type_chart']:
            charts_data['type_chart'] = [{'label': 'None', 'value': 0}]
        if not charts_data['tool_chart']:
            charts_data['tool_chart'] = [{'label': 'None', 'value': 0}]
        
        return charts_data
    
    def _get_validation_status(self, val_result: Dict[str, Any]) -> str:
        """
        Get validation status display
        
        Args:
            val_result: Validation result
            
        Returns:
            Status string
        """
        if val_result.get('valid') is True:
            return 'Verified Active'
        elif val_result.get('valid') is False:
            return 'Invalid/Inactive'
        else:
            return 'Not Verified'
    
    def _render_html(self, report_data: Dict[str, Any]) -> str:
        """
        Render HTML report from data
        
        Args:
            report_data: Report data
            
        Returns:
            HTML content
        """
        # Use enhanced template if deduplicated
        if report_data.get('deduplicated', False):
            template = Template(self._get_enhanced_html_template())
        else:
            template = Template(self._get_html_template())
        
        # Add helper functions to template context
        report_data['json_dumps'] = json.dumps
        report_data['enumerate'] = enumerate
        
        # Convert chart data to JSON strings for JavaScript
        charts = report_data['charts_data']
        
        # Basic charts
        for chart_name in ['severity_chart', 'type_chart', 'tool_chart']:
            if chart_name in charts:
                report_data[f'{chart_name}_labels'] = json.dumps([item['label'] for item in charts[chart_name]])
                report_data[f'{chart_name}_values'] = json.dumps([item['value'] for item in charts[chart_name]])
                if 'color' in charts[chart_name][0] if charts[chart_name] else False:
                    report_data[f'{chart_name}_colors'] = json.dumps([item.get('color', '#3498db') for item in charts[chart_name]])
        
        # Enhanced charts (if present)
        for chart_name in ['validation_chart', 'occurrence_distribution']:
            if chart_name in charts:
                report_data[f'{chart_name}_labels'] = json.dumps([item['label'] for item in charts[chart_name]])
                report_data[f'{chart_name}_values'] = json.dumps([item['value'] for item in charts[chart_name]])
                if 'color' in charts[chart_name][0] if charts[chart_name] else False:
                    report_data[f'{chart_name}_colors'] = json.dumps([item.get('color', '#3498db') for item in charts[chart_name]])
        
        return template.render(**report_data)
    
    def _get_enhanced_html_template(self) -> str:
        """
        Get enhanced HTML template with deduplication support
        
        Returns:
            Enhanced HTML template string
        """
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ company_name }} - Enhanced Secret Scanner Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px 0;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        header h1 {
            margin: 0 20px;
            font-size: 2.5em;
        }
        .subtitle {
            margin: 10px 20px 0;
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        /* Enhanced Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
            position: relative;
            overflow: hidden;
        }
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #3498db, #2ecc71);
        }
        .summary-card.critical::before {
            background: linear-gradient(90deg, #e74c3c, #c0392b);
        }
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }
        .summary-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #3498db;
            margin-bottom: 5px;
        }
        .summary-label {
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .summary-sublabel {
            color: #95a5a6;
            font-size: 0.8em;
            margin-top: 5px;
        }
        
        /* Color classes */
        .critical { color: #e74c3c !important; }
        .high { color: #e67e22 !important; }
        .medium { color: #f39c12 !important; }
        .low { color: #95a5a6 !important; }
        .verified { color: #e74c3c !important; }
        .invalid { color: #27ae60 !important; }
        
        /* Enhanced Charts Section */
        .charts-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .chart-container {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            height: 400px;
        }
        .chart-container canvas {
            max-height: 300px !important;
        }
        .chart-title {
            font-size: 1.3em;
            margin-bottom: 15px;
            color: #2c3e50;
        }
        
        /* Enhanced Findings Section */
        .findings-section {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .section-title {
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        
        /* Deduplicated Finding Card */
        .finding-card {
            border: 1px solid #e1e8ed;
            border-radius: 8px;
            margin-bottom: 20px;
            transition: all 0.3s;
            background: white;
            overflow: hidden;
        }
        .finding-card:hover {
            border-color: #3498db;
            box-shadow: 0 4px 8px rgba(52, 152, 219, 0.1);
        }
        .finding-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #e1e8ed;
            cursor: pointer;
            position: relative;
        }
        .finding-header:hover {
            background: #f1f3f5;
        }
        .finding-header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .finding-type {
            font-weight: bold;
            color: #2c3e50;
            font-size: 1.2em;
        }
        .finding-badges {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            display: inline-block;
        }
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #95a5a6; color: white; }
        .verified { background: #e74c3c; color: white; }
        .invalid { background: #27ae60; color: white; }
        .not-validated { background: #95a5a6; color: white; }
        
        .finding-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 10px;
        }
        .summary-item {
            display: flex;
            align-items: center;
            gap: 8px;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .summary-item strong {
            color: #2c3e50;
        }
        
        /* Secret Display */
        .secret-display {
            background: #ffe6e6;
            padding: 10px 15px;
            border-radius: 6px;
            margin-top: 15px;
            font-family: 'Consolas', 'Monaco', monospace;
            word-break: break-all;
            border: 1px solid #ffcccc;
        }
        .secret-value {
            color: #c0392b;
            font-weight: bold;
        }
        
        /* Occurrences Section */
        .finding-details {
            padding: 20px;
            display: none;
            max-height: 600px;
            overflow-y: auto;
        }
        .finding-details.expanded {
            display: block;
        }
        .occurrences-header {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.1em;
        }
        .occurrence-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 10px;
            border: 1px solid #e1e8ed;
        }
        .occurrence-item:hover {
            background: #f1f3f5;
        }
        .detail-row {
            margin-bottom: 8px;
            display: flex;
            align-items: flex-start;
        }
        .detail-label {
            font-weight: bold;
            color: #2c3e50;
            min-width: 120px;
            flex-shrink: 0;
        }
        .detail-value {
            word-break: break-all;
            flex: 1;
        }
        .url-value {
            color: #3498db;
            text-decoration: none;
        }
        .url-value:hover {
            text-decoration: underline;
        }
        .code-context {
            background: #f4f4f4;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
            margin-top: 10px;
            overflow-x: auto;
            border: 1px solid #ddd;
        }
        
        /* Expand/Collapse Icon */
        .expand-icon {
            transition: transform 0.3s;
            margin-left: 10px;
            color: #3498db;
            font-size: 1.2em;
        }
        .expand-icon.expanded {
            transform: rotate(180deg);
        }
        
        /* Original finding styles for non-deduplicated */
        .finding-card.original {
            border: 1px solid #e1e8ed;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            transition: all 0.3s;
        }
        .finding-card.original:hover {
            border-color: #3498db;
            box-shadow: 0 4px 8px rgba(52, 152, 219, 0.1);
        }
        .finding-card.original .finding-header {
            background: none;
            padding: 0;
            border: none;
            cursor: default;
        }
        .finding-card.original .finding-details {
            display: block;
            padding: 0;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            margin-top: 10px;
        }
        
        /* Filters */
        .filters {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .filter-group {
            display: inline-block;
            margin-right: 20px;
            margin-bottom: 10px;
        }
        .filter-label {
            font-weight: bold;
            margin-right: 10px;
            color: #2c3e50;
        }
        select, input[type="text"] {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .export-buttons {
            float: right;
            margin-top: -10px;
        }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            margin-left: 10px;
            transition: all 0.3s;
        }
        .btn-primary {
            background: #3498db;
            color: white;
        }
        .btn-primary:hover {
            background: #2980b9;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 30px 0;
            color: #7f8c8d;
            margin-top: 50px;
        }
        
        /* Print Styles */
        @media print {
            .filters, .export-buttons, .expand-icon {
                display: none !important;
            }
            .finding-details {
                display: block !important;
            }
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
            .finding-header-top {
                flex-direction: column;
                align-items: flex-start;
            }
            .finding-badges {
                margin-top: 10px;
            }
            .charts-section {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔐 {{ company_name }} Security Report</h1>
            <div class="subtitle">
                Enhanced Secret Scanner Results - {{ report_type|title }} Report
                <br>Generated: {{ generated_at_formatted }}
            </div>
        </div>
    </header>
    
    <div class="container">
        <!-- Enhanced Summary Cards -->
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value">{{ total_unique_secrets }}</div>
                <div class="summary-label">Total Secrets</div>
                <div class="summary-sublabel">{{ statistics.deduplication_ratio }} deduplication rate</div>
            </div>
            <div class="summary-card critical">
                <div class="summary-value critical">{{ statistics.critical_count + statistics.high_count }}</div>
                <div class="summary-label">Critical/High Severity</div>
                <div class="summary-sublabel">{{ statistics.critical_count }} critical, {{ statistics.high_count }} high</div>
            </div>
            <div class="summary-card">
                <div class="summary-value verified">{{ statistics.verified }}</div>
                <div class="summary-label">Verified Active</div>
                <div class="summary-sublabel">Confirmed through validation</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">{{ statistics.unique_files + statistics.unique_urls }}</div>
                <div class="summary-label">Unique Locations</div>
                <div class="summary-sublabel">{{ statistics.unique_files }} files, {{ statistics.unique_urls }} URLs</div>
            </div>
        </div>
        
        {% if comparison %}
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value critical">{{ comparison.new_count }}</div>
                <div class="summary-label">New Findings</div>
            </div>
            <div class="summary-card">
                <div class="summary-value medium">{{ comparison.recurring_count }}</div>
                <div class="summary-label">Recurring</div>
            </div>
            <div class="summary-card">
                <div class="summary-value" style="color: #27ae60;">{{ comparison.resolved_count }}</div>
                <div class="summary-label">Resolved</div>
            </div>
        </div>
        {% endif %}
        
        <!-- Enhanced Charts Section -->
        <div class="charts-section">
            <div class="chart-container">
                <h3 class="chart-title">Findings by Severity</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3 class="chart-title">Validation Status</h3>
                <canvas id="validationChart"></canvas>
            </div>
            <div class="chart-container">
                <h3 class="chart-title">Top Secret Types</h3>
                <canvas id="typeChart"></canvas>
            </div>
            <div class="chart-container">
                <h3 class="chart-title">Detection Tools</h3>
                <canvas id="toolChart"></canvas>
            </div>
            <div class="chart-container">
                <h3 class="chart-title">Occurrence Distribution</h3>
                <canvas id="occurrenceChart"></canvas>
            </div>
        </div>
        
        <!-- Filters -->
        <div class="filters">
            <div class="filter-group">
                <span class="filter-label">Severity:</span>
                <select id="severityFilter" onchange="filterFindings()">
                    <option value="">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>
            <div class="filter-group">
                <span class="filter-label">Validation:</span>
                <select id="validationFilter" onchange="filterFindings()">
                    <option value="">All</option>
                    <option value="verified">Verified Active</option>
                    <option value="invalid">Invalid/Inactive</option>
                    <option value="not-validated">Not Validated</option>
                </select>
            </div>
            <div class="filter-group">
                <span class="filter-label">Type:</span>
                <select id="typeFilter" onchange="filterFindings()">
                    <option value="">All</option>
                    {% for type in statistics.by_type.keys() %}
                    <option value="{{ type }}">{{ type.replace('_', ' ').replace('-', ' ').title() }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="filter-group">
                <span class="filter-label">Search:</span>
                <input type="text" id="searchFilter" placeholder="Search findings..." onkeyup="filterFindings()">
            </div>
            <div class="export-buttons">
                <button class="btn btn-primary" onclick="exportToJSON()">Export JSON</button>
                <button class="btn btn-primary" onclick="window.print()">Print Report</button>
            </div>
        </div>
        
        <!-- Enhanced Findings Section -->
        <div class="findings-section">
            <h2 class="section-title">Deduplicated Secret Findings</h2>
            
            {% if findings %}
                <div id="findingsContainer">
                    {% for finding in findings %}
                    <div class="finding-card" 
                         data-severity="{{ finding.severity }}" 
                         data-type="{{ finding.type }}" 
                         data-validation="{{ finding.validation_class }}"
                         data-index="{{ loop.index0 }}">
                        
                        <div class="finding-header" onclick="toggleDetails({{ loop.index0 }})">
                            <div class="finding-header-top">
                                <div>
                                    <span class="finding-type">{{ finding.type.replace('_', ' ').replace('-', ' ').title() }}</span>
                                </div>
                                <div class="finding-badges">
                                    <span class="badge severity-{{ finding.severity }}">
                                        {{ finding.severity|upper }}
                                    </span>
                                    <span class="badge {{ finding.validation_class }}">
                                        {{ finding.overall_validation_status|upper }}
                                    </span>
                                    {% if finding.baseline_status != 'unknown' %}
                                    <span class="badge" style="background: 
                                        {% if finding.baseline_status == 'new' %}#e74c3c
                                        {% elif finding.baseline_status == 'recurring' %}#f39c12
                                        {% else %}#95a5a6{% endif %}; color: white;">
                                        {{ finding.baseline_status|upper }}
                                    </span>
                                    {% endif %}
                                    <span style="color: #7f8c8d;">
                                        {{ finding.total_count }} occurrence{{ 's' if finding.total_count > 1 else '' }}
                                    </span>
                                    <span class="expand-icon" id="expand-{{ loop.index0 }}">▼</span>
                                </div>
                            </div>
                            
                            <div class="finding-summary">
                                <div class="summary-item">
                                    <span>🔍</span>
                                    <span><strong>Detection:</strong> {{ finding.detection_tools|join(', ') }}</span>
                                </div>
                                <div class="summary-item">
                                    <span>📊</span>
                                    <span><strong>Confidence:</strong> {{ finding.highest_confidence|capitalize }}</span>
                                </div>
                                <div class="summary-item">
                                    <span>📍</span>
                                    <span><strong>Locations:</strong> {{ finding.unique_files|length }} files, {{ finding.unique_urls|length }} URLs</span>
                                </div>
                                {% if finding.max_risk_score %}
                                <div class="summary-item">
                                    <span>⚠️</span>
                                    <span><strong>Risk Score:</strong> {{ finding.max_risk_score|int }}/200</span>
                                </div>
                                {% endif %}
                            </div>
                            
                            <div class="secret-display">
                                <strong>Secret:</strong> <code class="secret-value">{{ finding.secret_display }}</code>
                            </div>
                        </div>
                        
                        <div class="finding-details" id="details-{{ loop.index0 }}">
                            <div class="occurrences-header">
                                All Occurrences ({{ finding.total_count }}):
                            </div>
                            
                            {% for occurrence in finding.occurrences %}
                            <div class="occurrence-item">
                                <div class="detail-row">
                                    <span class="detail-label">URL:</span>
                                    <span class="detail-value">
                                        {% if occurrence.url %}
                                        <a href="{{ occurrence.url }}" target="_blank" class="url-value">{{ occurrence.url }}</a>
                                        {% else %}
                                        N/A
                                        {% endif %}
                                    </span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">File Path:</span>
                                    <span class="detail-value">{{ occurrence.file_path }}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Line:Column:</span>
                                    <span class="detail-value">{{ occurrence.line }}:{{ occurrence.column }}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Tool:</span>
                                    <span class="detail-value">{{ occurrence.tool }}</span>
                                </div>
                                <div class="detail-row">
                                    <span class="detail-label">Confidence:</span>
                                    <span class="detail-value">{{ occurrence.confidence|capitalize }}</span>
                                </div>
                                {% if occurrence.validation_result %}
                                <div class="detail-row">
                                    <span class="detail-label">Validation:</span>
                                    <span class="detail-value">
                                        {{ 'Valid' if occurrence.validation_result.valid else 'Invalid' }}
                                        {% if occurrence.validation_result.reason %}
                                        - {{ occurrence.validation_result.reason }}
                                        {% endif %}
                                        ({{ occurrence.validation_result.validated_at }})
                                    </span>
                                </div>
                                {% endif %}
                                {% if occurrence.baseline_status != 'unknown' %}
                                <div class="detail-row">
                                    <span class="detail-label">Status:</span>
                                    <span class="detail-value">{{ occurrence.baseline_status|capitalize }}</span>
                                </div>
                                {% endif %}
                                {% if occurrence.context %}
                                <div class="code-context">{{ occurrence.context }}</div>
                                {% endif %}
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            {% else %}
                <div class="no-findings">
                    <p>🎉 No secrets found!</p>
                    <p>Great job keeping your code secure.</p>
                </div>
            {% endif %}
        </div>
    </div>
    
    <div class="footer">
        <p>Generated by Enhanced Automated Secrets Scanner | {{ company_name }}</p>
        <p>Report generated on {{ generated_at_formatted }}</p>
        <p>{{ total_unique_secrets }} total secrets found</p>
    </div>
    
    <script>
        // Toggle finding details
        function toggleDetails(index) {
            const details = document.getElementById('details-' + index);
            const icon = document.getElementById('expand-' + index);
            
            if (details.classList.contains('expanded')) {
                details.classList.remove('expanded');
                icon.classList.remove('expanded');
            } else {
                details.classList.add('expanded');
                icon.classList.add('expanded');
            }
        }
        
        // Chart initialization
        document.addEventListener('DOMContentLoaded', function() {
            const chartOptions = {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15
                        }
                    }
                }
            };
            
            // Severity Chart
            const severityCtx = document.getElementById('severityChart');
            if (severityCtx && {{ severity_chart_values|default('[]')|safe }}.length > 0) {
                new Chart(severityCtx.getContext('2d'), {
                    type: 'doughnut',
                    data: {
                        labels: {{ severity_chart_labels|default('[]')|safe }},
                        datasets: [{
                            data: {{ severity_chart_values|default('[]')|safe }},
                            backgroundColor: {{ severity_chart_colors|default('[]')|safe }}
                        }]
                    },
                    options: chartOptions
                });
            }
            
            // Validation Chart
            const validationCtx = document.getElementById('validationChart');
            if (validationCtx && {{ validation_chart_values|default('[]')|safe }}.length > 0) {
                new Chart(validationCtx.getContext('2d'), {
                    type: 'pie',
                    data: {
                        labels: {{ validation_chart_labels|default('[]')|safe }},
                        datasets: [{
                            data: {{ validation_chart_values|default('[]')|safe }},
                            backgroundColor: {{ validation_chart_colors|default('[]')|safe }}
                        }]
                    },
                    options: chartOptions
                });
            }
            
            // Type Chart
            const typeCtx = document.getElementById('typeChart');
            if (typeCtx && {{ type_chart_values|default('[]')|safe }}.length > 0) {
                new Chart(typeCtx.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: {{ type_chart_labels|default('[]')|safe }},
                        datasets: [{
                            label: 'Count',
                            data: {{ type_chart_values|default('[]')|safe }},
                            backgroundColor: '#3498db'
                        }]
                    },
                    options: {
                        ...chartOptions,
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    precision: 0
                                }
                            }
                        }
                    }
                });
            }
            
            // Tool Chart
            const toolCtx = document.getElementById('toolChart');
            if (toolCtx && {{ tool_chart_values|default('[]')|safe }}.length > 0) {
                new Chart(toolCtx.getContext('2d'), {
                    type: 'doughnut',
                    data: {
                        labels: {{ tool_chart_labels|default('[]')|safe }},
                        datasets: [{
                            data: {{ tool_chart_values|default('[]')|safe }},
                            backgroundColor: [
                                '#3498db', '#e74c3c', '#f39c12', '#27ae60', '#9b59b6',
                                '#1abc9c', '#34495e', '#e67e22', '#95a5a6', '#d35400'
                            ]
                        }]
                    },
                    options: chartOptions
                });
            }
            
            // Occurrence Distribution Chart
            const occurrenceCtx = document.getElementById('occurrenceChart');
            if (occurrenceCtx && {{ occurrence_distribution_values|default('[]')|safe }}.length > 0) {
                new Chart(occurrenceCtx.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: {{ occurrence_distribution_labels|default('[]')|safe }},
                        datasets: [{
                            label: 'Secrets',
                            data: {{ occurrence_distribution_values|default('[]')|safe }},
                            backgroundColor: '#9b59b6'
                        }]
                    },
                    options: {
                        ...chartOptions,
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    precision: 0
                                }
                            }
                        }
                    }
                });
            }
        });
        
        // Filtering functionality
        function filterFindings() {
            const severityFilter = document.getElementById('severityFilter').value;
            const validationFilter = document.getElementById('validationFilter').value;
            const typeFilter = document.getElementById('typeFilter').value;
            const searchFilter = document.getElementById('searchFilter').value.toLowerCase();
            
            const findings = document.querySelectorAll('.finding-card');
            let visibleCount = 0;
            
            findings.forEach(finding => {
                const severity = finding.getAttribute('data-severity');
                const validation = finding.getAttribute('data-validation');
                const type = finding.getAttribute('data-type');
                const text = finding.textContent.toLowerCase();
                
                const matchesSeverity = !severityFilter || severity === severityFilter;
                const matchesValidation = !validationFilter || validation === validationFilter;
                const matchesType = !typeFilter || type === typeFilter;
                const matchesSearch = !searchFilter || text.includes(searchFilter);
                
                if (matchesSeverity && matchesValidation && matchesType && matchesSearch) {
                    finding.style.display = 'block';
                    visibleCount++;
                } else {
                    finding.style.display = 'none';
                }
            });
        }
        
        // Export functionality
        function exportToJSON() {
            const reportData = {{ findings|tojson }};
            const exportData = {
                report_type: '{{ report_type }}',
                generated_at: '{{ generated_at }}',
                total_unique_secrets: {{ total_unique_secrets }},
                total_raw_findings: {{ total_raw_findings }},
                statistics: {{ statistics|tojson }},
                findings: reportData
            };
            
            const dataStr = JSON.stringify(exportData, null, 2);
            const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
            
            const exportFileDefaultName = 'enhanced_secret_findings_' + new Date().toISOString().slice(0,10) + '.json';
            
            const linkElement = document.createElement('a');
            linkElement.setAttribute('href', dataUri);
            linkElement.setAttribute('download', exportFileDefaultName);
            linkElement.click();
        }
    </script>
</body>
</html>
        '''
    
    def _get_html_template(self) -> str:
        """
        Get HTML report template (original version)
        
        Returns:
            HTML template string
        """
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ company_name }} - Secret Scanner Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px 0;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        header h1 {
            margin: 0 20px;
            font-size: 2.5em;
        }
        .subtitle {
            margin: 10px 20px 0;
            opacity: 0.9;
            font-size: 1.1em;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.15);
        }
        .summary-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #3498db;
            margin-bottom: 5px;
        }
        .summary-label {
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .critical { color: #e74c3c !important; }
        .high { color: #e67e22 !important; }
        .medium { color: #f39c12 !important; }
        .low { color: #95a5a6 !important; }
        .charts-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .chart-container {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            height: 400px;
        }
        .chart-container canvas {
            max-height: 300px !important;
        }
        .chart-title {
            font-size: 1.3em;
            margin-bottom: 15px;
            color: #2c3e50;
        }
        .findings-section {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .section-title {
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        .finding-card {
            border: 1px solid #e1e8ed;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            transition: all 0.3s;
        }
        .finding-card:hover {
            border-color: #3498db;
            box-shadow: 0 4px 8px rgba(52, 152, 219, 0.1);
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .finding-type {
            font-weight: bold;
            color: #2c3e50;
            font-size: 1.1em;
        }
        .badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            display: inline-block;
            margin-left: 10px;
        }
        .severity-critical { background: #e74c3c; color: white; }
        .severity-high { background: #e67e22; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #95a5a6; color: white; }
        .verified { background: #27ae60; color: white; }
        .invalid { background: #e74c3c; color: white; }
        .finding-details {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            margin-top: 10px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }
        .detail-row {
            margin-bottom: 8px;
        }
        .detail-label {
            font-weight: bold;
            color: #2c3e50;
            display: inline-block;
            min-width: 120px;
        }
        .detail-value {
            word-break: break-all;
        }
        .secret-value {
            background: #ffe6e6;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
            color: #c0392b;
        }
        .url-value {
            color: #3498db;
            text-decoration: none;
        }
        .url-value:hover {
            text-decoration: underline;
        }
        .filters {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .filter-group {
            display: inline-block;
            margin-right: 20px;
            margin-bottom: 10px;
        }
        .filter-label {
            font-weight: bold;
            margin-right: 10px;
            color: #2c3e50;
        }
        select, input[type="text"] {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        .export-buttons {
            float: right;
            margin-top: -10px;
        }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            margin-left: 10px;
            transition: all 0.3s;
        }
        .btn-primary {
            background: #3498db;
            color: white;
        }
        .btn-primary:hover {
            background: #2980b9;
        }
        .footer {
            text-align: center;
            padding: 30px 0;
            color: #7f8c8d;
            margin-top: 50px;
        }
        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
            .finding-header {
                flex-direction: column;
                align-items: flex-start;
            }
            .badge {
                margin-top: 5px;
                margin-left: 0;
            }
        }
        .no-findings {
            text-align: center;
            padding: 60px 20px;
            color: #7f8c8d;
            font-size: 1.2em;
        }
        .pagination {
            text-align: center;
            margin-top: 30px;
        }
        .page-link {
            display: inline-block;
            padding: 8px 12px;
            margin: 0 5px;
            border: 1px solid #ddd;
            border-radius: 4px;
            color: #3498db;
            text-decoration: none;
            transition: all 0.3s;
        }
        .page-link:hover, .page-link.active {
            background: #3498db;
            color: white;
            border-color: #3498db;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔐 {{ company_name }} Security Report</h1>
            <div class="subtitle">
                Secret Scanner Results - {{ report_type|title }} Report
                <br>Generated: {{ generated_at_formatted }}
            </div>
        </div>
    </header>
    
    <div class="container">
        <!-- Summary Cards -->
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value">{{ statistics.total }}</div>
                <div class="summary-label">Total Findings</div>
            </div>
            <div class="summary-card">
                <div class="summary-value critical">{{ statistics.critical_count }}</div>
                <div class="summary-label">Critical/High</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">{{ statistics.verified }}</div>
                <div class="summary-label">Verified Active</div>
            </div>
            <div class="summary-card">
                <div class="summary-value">{{ statistics.unique_files + statistics.unique_urls }}</div>
                <div class="summary-label">Unique Locations</div>
            </div>
        </div>
        
        {% if comparison %}
        <div class="summary-grid">
            <div class="summary-card">
                <div class="summary-value critical">{{ comparison.new_count }}</div>
                <div class="summary-label">New Findings</div>
            </div>
            <div class="summary-card">
                <div class="summary-value medium">{{ comparison.recurring_count }}</div>
                <div class="summary-label">Recurring</div>
            </div>
            <div class="summary-card">
                <div class="summary-value" style="color: #27ae60;">{{ comparison.resolved_count }}</div>
                <div class="summary-label">Resolved</div>
            </div>
        </div>
        {% endif %}
        
        <!-- Charts Section -->
        <div class="charts-section">
            <div class="chart-container">
                <h3 class="chart-title">Findings by Severity</h3>
                <canvas id="severityChart" height="300"></canvas>
            </div>
            <div class="chart-container">
                <h3 class="chart-title">Top Secret Types</h3>
                <canvas id="typeChart" height="300"></canvas>
            </div>
            <div class="chart-container">
                <h3 class="chart-title">Detection Tools</h3>
                <canvas id="toolChart" height="300"></canvas>
            </div>
        </div>
        
        <!-- Filters -->
        <div class="filters">
            <div class="filter-group">
                <span class="filter-label">Severity:</span>
                <select id="severityFilter" onchange="filterFindings()">
                    <option value="">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>
            <div class="filter-group">
                <span class="filter-label">Type:</span>
                <select id="typeFilter" onchange="filterFindings()">
                    <option value="">All</option>
                    {% for type in statistics.by_type.keys() %}
                    <option value="{{ type }}">{{ type }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="filter-group">
                <span class="filter-label">Search:</span>
                <input type="text" id="searchFilter" placeholder="Search findings..." onkeyup="filterFindings()">
            </div>
            <div class="export-buttons">
                <button class="btn btn-primary" onclick="exportToJSON()">Export JSON</button>
                <button class="btn btn-primary" onclick="window.print()">Print Report</button>
            </div>
        </div>
        
        <!-- Findings Section -->
        <div class="findings-section">
            <h2 class="section-title">Detailed Findings</h2>
            
            {% if findings %}
                <div id="findingsContainer">
                    {% for finding in findings[:max_findings_per_page] %}
                    <div class="finding-card" data-severity="{{ finding.severity }}" 
                         data-type="{{ finding.type }}" data-index="{{ loop.index0 }}">
                        <div class="finding-header">
                            <div>
                                <span class="finding-type">{{ finding.type }}</span>
                                <span class="badge severity-{{ finding.severity }}">
                                    {{ finding.severity|upper }}
                                </span>
                                {% if finding.verified or (finding.validation_result and finding.validation_result.valid) %}
                                <span class="badge verified">VERIFIED</span>
                                {% elif finding.validation_result and finding.validation_result.valid == false %}
                                <span class="badge invalid">INVALID</span>
                                {% endif %}
                            </div>
                            <div>
                                <span style="color: #7f8c8d;">{{ finding.tool or finding.detector }}</span>
                            </div>
                        </div>
                        <div class="finding-details">
                            {% if finding.url %}
                            <div class="detail-row">
                                <span class="detail-label">URL:</span>
                                <a href="{{ finding.url }}" target="_blank" class="url-value detail-value">{{ finding.url }}</a>
                            </div>
                            {% endif %}
                            <div class="detail-row">
                                <span class="detail-label">File Path:</span>
                                <span class="detail-value">{{ finding.file_path or finding.file or 'Unknown' }}</span>
                            </div>
                            {% if finding.line_number or finding.line %}
                            <div class="detail-row">
                                <span class="detail-label">Line:</span>
                                <span class="detail-value">{{ finding.line_number or finding.line }}</span>
                            </div>
                            {% endif %}
                            <div class="detail-row">
                                <span class="detail-label">Secret:</span>
                                <code class="secret-value detail-value">{{ finding.secret_display }}</code>
                            </div>
                            {% if finding.confidence %}
                            <div class="detail-row">
                                <span class="detail-label">Confidence:</span>
                                <span class="detail-value">{{ finding.confidence|capitalize }}</span>
                            </div>
                            {% endif %}
                            {% if finding.validation_result %}
                            <div class="detail-row">
                                <span class="detail-label">Validation:</span>
                                <span class="detail-value">{{ finding.validation_status }}
                                {% if finding.validation_result.details %}
                                    ({{ finding.validation_result.details }})
                                {% endif %}
                                </span>
                            </div>
                            {% endif %}
                            {% if finding.baseline_status %}
                            <div class="detail-row">
                                <span class="detail-label">Status:</span>
                                <span class="badge" style="background: 
                                    {% if finding.baseline_status == 'new' %}#e74c3c
                                    {% elif finding.baseline_status == 'recurring' %}#f39c12
                                    {% else %}#95a5a6{% endif %}; color: white;">
                                    {{ finding.baseline_status|upper }}
                                </span>
                            </div>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
                
                {% if findings|length > max_findings_per_page %}
                <div class="pagination">
                    <span>Showing {{ max_findings_per_page }} of {{ findings|length }} findings</span>
                </div>
                {% endif %}
            {% else %}
                <div class="no-findings">
                    <p>🎉 No secrets found!</p>
                    <p>Great job keeping your code secure.</p>
                </div>
            {% endif %}
        </div>
    </div>
    
    <div class="footer">
        <p>Generated by Automated Secrets Scanner | {{ company_name }}</p>
        <p>Report generated on {{ generated_at_formatted }}</p>
    </div>
    
    <script>
        // Wait for DOM to load
        document.addEventListener('DOMContentLoaded', function() {
            // Chart configuration
            const chartOptions = {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15
                        }
                    }
                }
            };
            
            // Severity Chart
            const severityCtx = document.getElementById('severityChart');
            if (severityCtx) {
                new Chart(severityCtx.getContext('2d'), {
                    type: 'doughnut',
                    data: {
                        labels: {{ severity_chart_labels|safe }},
                        datasets: [{
                            data: {{ severity_chart_values|safe }},
                            backgroundColor: {{ severity_chart_colors|safe }}
                        }]
                    },
                    options: chartOptions
                });
            }
            
            // Type Chart
            const typeCtx = document.getElementById('typeChart');
            if (typeCtx) {
                new Chart(typeCtx.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: {{ type_chart_labels|safe }},
                        datasets: [{
                            label: 'Count',
                            data: {{ type_chart_values|safe }},
                            backgroundColor: '#3498db'
                        }]
                    },
                    options: {
                        ...chartOptions,
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    precision: 0
                                }
                            }
                        }
                    }
                });
            }
            
            // Tool Chart
            const toolCtx = document.getElementById('toolChart');
            if (toolCtx) {
                new Chart(toolCtx.getContext('2d'), {
                    type: 'pie',
                    data: {
                        labels: {{ tool_chart_labels|safe }},
                        datasets: [{
                            data: {{ tool_chart_values|safe }},
                            backgroundColor: [
                                '#3498db', '#e74c3c', '#f39c12', '#27ae60', '#9b59b6'
                            ]
                        }]
                    },
                    options: chartOptions
                });
            }
        });
        
        // Filtering functionality
        function filterFindings() {
            const severityFilter = document.getElementById('severityFilter').value.toLowerCase();
            const typeFilter = document.getElementById('typeFilter').value.toLowerCase();
            const searchFilter = document.getElementById('searchFilter').value.toLowerCase();
            
            const findings = document.querySelectorAll('.finding-card');
            let visibleCount = 0;
            
            findings.forEach(finding => {
                const severity = finding.getAttribute('data-severity');
                const type = finding.getAttribute('data-type');
                const text = finding.textContent.toLowerCase();
                
                const matchesSeverity = !severityFilter || severity === severityFilter;
                const matchesType = !typeFilter || type === typeFilter;
                const matchesSearch = !searchFilter || text.includes(searchFilter);
                
                if (matchesSeverity && matchesType && matchesSearch) {
                    finding.style.display = 'block';
                    visibleCount++;
                } else {
                    finding.style.display = 'none';
                }
            });
            
            // Update count
            const container = document.getElementById('findingsContainer');
            if (visibleCount === 0) {
                if (!document.getElementById('noResults')) {
                    const noResults = document.createElement('div');
                    noResults.id = 'noResults';
                    noResults.className = 'no-findings';
                    noResults.innerHTML = '<p>No findings match your filters.</p>';
                    container.appendChild(noResults);
                }
            } else {
                const noResults = document.getElementById('noResults');
                if (noResults) {
                    noResults.remove();
                }
            }
        }
        
        // Export functionality
        function exportToJSON() {
            const reportData = {{ findings|tojson }};
            const dataStr = JSON.stringify(reportData, null, 2);
            const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
            
            const exportFileDefaultName = 'secret_findings_' + new Date().toISOString().slice(0,10) + '.json';
            
            const linkElement = document.createElement('a');
            linkElement.setAttribute('href', dataUri);
            linkElement.setAttribute('download', exportFileDefaultName);
            linkElement.click();
        }
    </script>
</body>
</html>
        '''
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get report generation statistics
        
        Returns:
            Statistics dictionary
        """
        return self.stats