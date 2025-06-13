#!/usr/bin/env python3
"""
Enhanced HTML Report Generator for Secret Scanner with Precise URL Mapping
Generates interactive HTML reports with precise URL context and resource dependency mapping
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
    """Generates interactive HTML reports for secret findings with precise URL mapping and database integration"""
    
    def __init__(self, config: Dict[str, Any], db_manager=None):
        """
        Initialize Enhanced HTML Report Generator
        
        Args:
            config: Configuration dictionary
            db_manager: DatabaseManager instance
        """
        self.config = config
        self.db = db_manager
        self.reports_path = Path(config.get('data_storage_path', './data')) / 'reports'
        self.reports_path.mkdir(parents=True, exist_ok=True)
        
        # Report settings - ALWAYS show secrets
        self.company_name = config.get('report', {}).get('company_name', 'Security Team')
        self.show_secrets = True  # Always show actual secrets
        self.max_findings_per_page = config.get('report', {}).get('max_findings_per_page', 100)
        self.enable_deduplication = config.get('report', {}).get('enable_deduplication', True)
        
        # Enhanced features for precise URL mapping
        self.enable_precise_mapping = config.get('report', {}).get('enable_precise_mapping', True)
        self.show_resource_dependencies = config.get('report', {}).get('show_resource_dependencies', True)
        self.show_load_timing = config.get('report', {}).get('show_load_timing', True)
        
        # Statistics
        self.stats = {
            'reports_generated': 0,
            'generation_errors': [],
            'precise_mapping_enabled': self.enable_precise_mapping
        }
        
        logger.info(f"Enhanced HTML Report Generator initialized with precise URL mapping: {self.enable_precise_mapping}")
    
    def generate_report_from_db(self, scan_run_id: int = None, domains: List[str] = None,
                               report_type: str = 'full', comparison_scan_id: int = None) -> Path:
        """
        Generate HTML report by loading data from database with precise URL mapping
        
        Args:
            scan_run_id: Specific scan run to report on
            domains: Filter by domains
            report_type: Type of report ('full', 'new', 'summary')
            comparison_scan_id: Previous scan ID for comparison
            
        Returns:
            Path to generated report
        """
        if not self.db:
            logger.error("No database connection available")
            return None
        
        try:
            logger.info(f"Generating {report_type} HTML report with precise URL mapping from database")
            
            # Load findings from database with precise URL context
            findings = self._load_findings_from_db_with_precise_mapping(scan_run_id, domains)
            
            if not findings:
                logger.warning("No findings to report")
            
            # Load comparison data if requested
            comparison_data = None
            if comparison_scan_id:
                comparison_data = self._load_comparison_data(scan_run_id, comparison_scan_id)
            
            # Load validation results
            validation_results = self._load_validation_results_from_db(scan_run_id)
            
            # Load resource dependency data
            resource_dependencies = None
            if self.enable_precise_mapping and scan_run_id:
                resource_dependencies = self._load_resource_dependencies_from_db(scan_run_id)
            
            # Generate enhanced report
            report_path = self.generate_enhanced_report(
                findings=findings,
                report_type=report_type,
                comparison_data=comparison_data,
                validation_results=validation_results,
                resource_dependencies=resource_dependencies,
                scan_id=str(scan_run_id) if scan_run_id else None
            )
            
            # Store report metadata in database
            if report_path and scan_run_id:
                self._store_report_metadata(scan_run_id, report_path, report_type)
            
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating enhanced report from database: {e}")
            logger.exception(e)
            return None
    
    def _load_findings_from_db_with_precise_mapping(self, scan_run_id: int = None, domains: List[str] = None) -> List[Dict[str, Any]]:
        """
        Load findings from database with precise URL mapping context
        """
        findings = []
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Enhanced query with precise URL mapping data
                query = """
                    SELECT 
                        f.id as finding_id,
                        f.secret_id,
                        f.line_number,
                        f.snippet,
                        f.file_path,
                        f.validation_status,
                        f.validation_result,
                        f.found_at,
                        s.secret_hash,
                        s.secret_value,
                        s.secret_type,
                        s.detector_name,
                        s.severity,
                        s.confidence,
                        s.is_verified,
                        s.is_active,
                        u.url,
                        u.domain,
                        sr.scan_type,
                        -- Precise URL mapping data
                        pr.resource_url as precise_resource_url,
                        pr.load_method,
                        pr.load_timing_ms,
                        pr.referrer_url,
                        pr.resource_type,
                        pr.first_seen as resource_first_seen,
                        -- JS chunk metadata
                        jcm.webpack_chunk_id,
                        jcm.source_map_url,
                        jcm.entry_point,
                        jcm.chunk_size_bytes,
                        jcm.load_order,
                        jcm.dependencies as chunk_dependencies,
                        jcm.load_context,
                        -- Baseline status calculation
                        CASE 
                            WHEN b.secret_id IS NOT NULL THEN 'false_positive'
                            WHEN prev.secret_hash IS NOT NULL THEN 'recurring'
                            ELSE 'new'
                        END as baseline_status,
                        -- Precision level
                        CASE 
                            WHEN pr.resource_url IS NOT NULL THEN 'exact'
                            ELSE 'fallback'
                        END as mapping_precision
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    LEFT JOIN urls u ON f.url_id = u.id
                    LEFT JOIN scan_runs sr ON f.scan_run_id = sr.id
                    -- Join with precise resource relationships
                    LEFT JOIN page_resources pr ON (
                        pr.resource_filename = CASE WHEN f.file_path LIKE '%/js/%' THEN SUBSTR(f.file_path, INSTR(f.file_path, '/js/')+4) WHEN f.file_path LIKE '%/metadata/%' THEN SUBSTR(f.file_path, INSTR(f.file_path, '/metadata/')+10) ELSE SUBSTR(f.file_path, INSTR(f.file_path, '/')+1) END
                        AND pr.scan_id = sr.id
                    )
                    -- Join with JS chunk metadata
                    LEFT JOIN js_chunk_metadata jcm ON (
                        jcm.chunk_filename = CASE WHEN f.file_path LIKE '%/js/%' THEN SUBSTR(f.file_path, INSTR(f.file_path, '/js/')+4) WHEN f.file_path LIKE '%/metadata/%' THEN SUBSTR(f.file_path, INSTR(f.file_path, '/metadata/')+10) ELSE SUBSTR(f.file_path, INSTR(f.file_path, '/')+1) END
                        AND jcm.scan_id = sr.id
                    )
                    -- Baseline detection
                    LEFT JOIN baselines b ON s.id = b.secret_id 
                        AND (u.domain = b.domain OR b.domain IS NULL OR u.domain IS NULL)
                    -- Previous scan detection
                    LEFT JOIN (
                        SELECT DISTINCT s2.secret_hash, u2.domain
                        FROM findings f2
                        JOIN secrets s2 ON f2.secret_id = s2.id
                        LEFT JOIN urls u2 ON f2.url_id = u2.id
                        WHERE f2.scan_run_id != COALESCE(?, 'dummy_scan_id')
                    ) prev ON s.secret_hash = prev.secret_hash 
                        AND (u.domain = prev.domain OR prev.domain IS NULL OR u.domain IS NULL)
                    WHERE 1=1
                """
                
                params = [scan_run_id or 'dummy_scan_id']
                
                if scan_run_id:
                    query += " AND f.scan_run_id = ?"
                    params.append(scan_run_id)
                
                if domains:
                    placeholders = ','.join(['?' for _ in domains])
                    query += f" AND u.domain IN ({placeholders})"
                    params.extend(domains)
                
                query += " ORDER BY s.severity DESC, f.found_at DESC"
                
                logger.debug(f"Executing enhanced findings query with precise mapping")
                cursor.execute(query, params)
                columns = [desc[0] for desc in cursor.description]
                
                for row in cursor.fetchall():
                    finding_dict = dict(zip(columns, row))
                    
                    # Parse JSON fields
                    validation_result = {}
                    if finding_dict.get('validation_result'):
                        try:
                            validation_result = json.loads(finding_dict['validation_result'])
                        except:
                            validation_result = {}
                    
                    chunk_dependencies = []
                    if finding_dict.get('chunk_dependencies'):
                        try:
                            chunk_dependencies = json.loads(finding_dict['chunk_dependencies'])
                        except:
                            chunk_dependencies = []
                    
                    load_context = {}
                    if finding_dict.get('load_context'):
                        try:
                            load_context = json.loads(finding_dict['load_context'])
                        except:
                            load_context = {}
                    
                    # Enhanced finding with precise URL mapping
                    finding = {
                        'id': finding_dict['finding_id'],
                        'secret_id': finding_dict['secret_id'],
                        'type': finding_dict['secret_type'],
                        'detector': finding_dict['detector_name'],
                        'severity': finding_dict['severity'],
                        'confidence': finding_dict['confidence'],
                        'verified': finding_dict['is_verified'],
                        'line': finding_dict['line_number'],
                        'line_number': finding_dict['line_number'],
                        'context': finding_dict['snippet'],
                        'file': finding_dict['file_path'],
                        'file_path': finding_dict['file_path'],
                        'url': finding_dict['url'] or 'Unknown',
                        'domain': finding_dict['domain'] or 'Unknown',
                        'validation_status': finding_dict['validation_status'],
                        'validation_result': validation_result,
                        'timestamp': finding_dict['found_at'],
                        'scan_type': finding_dict['scan_type'],
                        'raw': finding_dict['secret_value'],
                        'secret': finding_dict['secret_value'],
                        'secret_display': finding_dict['secret_value'],
                        'redacted': finding_dict['secret_value'],
                        'baseline_status': finding_dict['baseline_status'],
                        
                        # ENHANCED: Precise URL mapping context
                        'precise_mapping': {
                            'enabled': self.enable_precise_mapping,
                            'precision_level': finding_dict['mapping_precision'],
                            'parent_page_url': self._get_parent_page_url(finding_dict),
                            'resource_url': finding_dict['precise_resource_url'],
                            'load_method': finding_dict['load_method'],
                            'load_timing_ms': finding_dict['load_timing_ms'],
                            'referrer_url': finding_dict['referrer_url'],
                            'resource_type': finding_dict['resource_type'],
                            'resource_first_seen': finding_dict['resource_first_seen']
                        },
                        
                        # ENHANCED: JS chunk metadata
                        'chunk_metadata': {
                            'webpack_chunk_id': finding_dict['webpack_chunk_id'],
                            'source_map_url': finding_dict['source_map_url'],
                            'entry_point': finding_dict['entry_point'],
                            'chunk_size_bytes': finding_dict['chunk_size_bytes'],
                            'load_order': finding_dict['load_order'],
                            'dependencies': chunk_dependencies,
                            'load_context': load_context
                        }
                    }
                    
                    findings.append(finding)
                
                logger.info(f"Loaded {len(findings)} findings with precise URL mapping context")
                
        except Exception as e:
            logger.error(f"Error loading findings with precise mapping: {e}")
            logger.exception(e)
        
        return findings
    
    def _get_parent_page_url(self, finding_dict: Dict[str, Any]) -> str:
        """Extract parent page URL from finding data"""
        # If we have precise resource URL, extract parent from it
        if finding_dict.get('precise_resource_url'):
            try:
                # Get parent URL from page_resources table via another query if needed
                # For now, use the main URL as fallback
                return finding_dict.get('url', 'Unknown')
            except:
                pass
        
        return finding_dict.get('url', 'Unknown')
    
    def _load_resource_dependencies_from_db(self, scan_run_id: int) -> Dict[str, Any]:
        """
        Load resource dependency data for visualization
        """
        dependencies = {
            'page_resource_map': {},
            'load_method_distribution': {},
            'timing_distribution': {},
            'chunk_dependencies': {},
            'total_resources': 0
        }
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get resource relationships
                cursor.execute("""
                    SELECT 
                        u.url as parent_url,
                        pr.resource_url,
                        pr.resource_filename,
                        pr.load_method,
                        pr.load_timing_ms,
                        pr.resource_type,
                        COUNT(*) as occurrence_count
                    FROM page_resources pr
                    JOIN urls u ON pr.parent_url_id = u.id
                    JOIN scan_runs sr ON pr.scan_id = sr.scan_id
                    WHERE sr.id = ?
                    GROUP BY pr.resource_url, pr.load_method
                    ORDER BY pr.load_timing_ms
                """, (scan_run_id,))
                
                for row in cursor.fetchall():
                    parent_url, resource_url, filename, load_method, timing, res_type, count = row
                    
                    # Build page->resource mapping
                    if parent_url not in dependencies['page_resource_map']:
                        dependencies['page_resource_map'][parent_url] = []
                    
                    dependencies['page_resource_map'][parent_url].append({
                        'resource_url': resource_url,
                        'filename': filename,
                        'load_method': load_method,
                        'timing': timing,
                        'type': res_type,
                        'count': count
                    })
                    
                    # Track load method distribution
                    if load_method:
                        dependencies['load_method_distribution'][load_method] = \
                            dependencies['load_method_distribution'].get(load_method, 0) + count
                    
                    # Track timing distribution
                    if timing:
                        timing_bucket = self._get_timing_bucket(timing)
                        dependencies['timing_distribution'][timing_bucket] = \
                            dependencies['timing_distribution'].get(timing_bucket, 0) + count
                    
                    dependencies['total_resources'] += count
                
                # Get JS chunk dependencies
                cursor.execute("""
                    SELECT 
                        jcm.chunk_filename,
                        jcm.dependencies,
                        jcm.load_context
                    FROM js_chunk_metadata jcm
                    WHERE jcm.scan_id IN (
                        SELECT scan_id FROM scan_runs WHERE id = ?
                    )
                """, (scan_run_id,))
                
                for row in cursor.fetchall():
                    chunk_filename, deps_json, context_json = row
                    
                    try:
                        chunk_deps = json.loads(deps_json or '[]')
                        load_context = json.loads(context_json or '{}')
                        
                        dependencies['chunk_dependencies'][chunk_filename] = {
                            'dependencies': chunk_deps,
                            'context': load_context
                        }
                    except:
                        pass
                
        except Exception as e:
            logger.error(f"Error loading resource dependencies: {e}")
        
        return dependencies
    
    def _get_timing_bucket(self, timing_ms: int) -> str:
        """Get timing bucket for distribution chart"""
        if timing_ms < 100:
            return "0-100ms"
        elif timing_ms < 500:
            return "100-500ms"
        elif timing_ms < 1000:
            return "500ms-1s"
        elif timing_ms < 5000:
            return "1-5s"
        else:
            return "5s+"
    
    def generate_enhanced_report(self, findings: List[Dict[str, Any]], 
                                report_type: str = 'full',
                                comparison_data: Optional[Dict[str, Any]] = None,
                                validation_results: Optional[Dict[str, Any]] = None,
                                resource_dependencies: Optional[Dict[str, Any]] = None,
                                scan_id: Optional[str] = None) -> Path:
        """
        Generate enhanced HTML report with precise URL mapping
        """
        try:
            logger.info(f"Generating enhanced {report_type} HTML report with precise URL mapping for {len(findings)} findings")
            
            # Get enhanced statistics from database if available
            if self.db and scan_id:
                try:
                    scan_run_id = int(scan_id)
                    db_stats = self._calculate_statistics_from_db(scan_run_id)
                except:
                    db_stats = None
            else:
                db_stats = None
            
            # Prepare enhanced report data
            if self.enable_deduplication:
                report_data = self._prepare_enhanced_deduplicated_report_data(
                    findings, report_type, comparison_data, validation_results, resource_dependencies
                )
                if db_stats:
                    report_data['statistics'].update(db_stats)
            else:
                report_data = self._prepare_enhanced_report_data(
                    findings, report_type, comparison_data, validation_results, resource_dependencies
                )
                if db_stats:
                    report_data['statistics'].update(db_stats)
            
            # Add enhanced metadata
            if scan_id:
                report_data['scan_id'] = scan_id
            
            report_data['precise_mapping_enabled'] = self.enable_precise_mapping
            report_data['resource_dependencies_enabled'] = self.show_resource_dependencies
            
            # Generate enhanced HTML
            html_content = self._render_enhanced_html(report_data)
            
            # Save report
            report_file = self._save_report(html_content, report_type, scan_id)
            
            # Update statistics
            self.stats['reports_generated'] += 1
            
            logger.info(f"Generated enhanced HTML report with precise URL mapping: {report_file}")
            return report_file
            
        except Exception as e:
            logger.error(f"Error generating enhanced HTML report: {e}")
            logger.exception(e)
            self.stats['generation_errors'].append({
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
            return None
    
    def _prepare_enhanced_deduplicated_report_data(self, findings: List[Dict[str, Any]], 
                                                  report_type: str,
                                                  comparison_data: Optional[Dict[str, Any]],
                                                  validation_results: Optional[Dict[str, Any]],
                                                  resource_dependencies: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare enhanced deduplicated report data with precise URL mapping"""
        try:
            # Deduplicate findings with precise URL context
            deduplicated = self._deduplicate_findings_with_precise_mapping(findings)
            
            # Convert to list and sort
            findings_list = list(deduplicated.values())
            
            # Enhanced sorting with precision level
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'unknown': 4}
            findings_list.sort(key=lambda x: (
                severity_order.get(x['severity'], 4),
                0 if x.get('precise_mapping', {}).get('precision_level') == 'exact' else 1,  # Exact mappings first
                -x['total_count'],
                -x.get('max_risk_score', 0)
            ))
            
            # Calculate enhanced statistics
            stats = self._calculate_enhanced_statistics_with_precise_mapping(deduplicated, findings, resource_dependencies)
            
            # Prepare enhanced report data
            report_data = {
                'report_type': report_type,
                'generated_at': datetime.utcnow().isoformat(),
                'generated_at_formatted': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                'company_name': self.company_name,
                'total_raw_findings': len(findings),
                'total_unique_secrets': len(deduplicated),
                'findings': findings_list,
                'statistics': stats,
                'charts_data': self._prepare_enhanced_charts_data_with_precise_mapping(deduplicated, resource_dependencies),
                'max_findings_per_page': self.max_findings_per_page,
                'deduplicated': True,
                'precise_mapping_enabled': self.enable_precise_mapping,
                'resource_dependencies': resource_dependencies or {}
            }
            
            # Add comparison data
            if comparison_data:
                report_data['comparison'] = {
                    'new_count': comparison_data.get('new_count', len(comparison_data.get('new', []))),
                    'recurring_count': comparison_data.get('recurring_count', len(comparison_data.get('recurring', []))),
                    'resolved_count': comparison_data.get('resolved_count', len(comparison_data.get('resolved', [])))
                }
            
            return report_data
            
        except Exception as e:
            logger.error(f"Error preparing enhanced deduplicated report data: {e}")
            # Fall back to regular enhanced report
            return self._prepare_enhanced_report_data(findings, report_type, comparison_data, validation_results, resource_dependencies)
    
    def _deduplicate_findings_with_precise_mapping(self, findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Enhanced deduplication with precise URL mapping context"""
        deduplicated = {}
        
        for finding in findings:
            secret_value = finding.get('raw', finding.get('secret', 'N/A'))
            if secret_value == 'N/A':
                continue
                
            secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()[:16]
            
            if secret_hash not in deduplicated:
                deduplicated[secret_hash] = {
                    'secret': secret_value,
                    'secret_display': secret_value,
                    'redacted': secret_value,
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
                    'baseline_status': finding.get('baseline_status', 'unknown'),
                    
                    # ENHANCED: Precise URL mapping data
                    'precise_mapping': {
                        'exact_mappings': 0,
                        'fallback_mappings': 0,
                        'parent_pages': set(),
                        'load_methods': set(),
                        'timing_data': [],
                        'resource_types': set()
                    }
                }
            
            # Enhanced occurrence with precise mapping
            # Create precise_mapping from top-level SQL data
            # Get correct data from validation_result.url_context
            validation_result = finding.get('validation_result', {})
            if isinstance(validation_result, str):
                import json
                try:
                    validation_result = json.loads(validation_result)
                except:
                    validation_result = {}
            
            url_context = validation_result.get('url_context', {})
            precise_mapping = {
                'precision_level': url_context.get('precision_level', 'fallback'),
                'parent_page_url': url_context.get('referrer_url', finding.get('url', 'Unknown')),
                'resource_url': url_context.get('resource_url'),
                'load_method': url_context.get('load_method'),
                'load_timing_ms': url_context.get('load_timing_ms'),
                'referrer_url': url_context.get('referrer_url'),
                'resource_type': url_context.get('resource_type')
            }
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
                'baseline_status': finding.get('baseline_status', 'unknown'),
                
                # ENHANCED: Precise URL mapping context
                'precise_mapping': {
                    'precision_level': precise_mapping.get('precision_level', 'fallback'),
                    'parent_page_url': precise_mapping.get('parent_page_url', 'Unknown'),
                    'resource_url': precise_mapping.get('resource_url'),
                    'load_method': precise_mapping.get('load_method'),
                    'load_timing_ms': precise_mapping.get('load_timing_ms'),
                    'referrer_url': precise_mapping.get('referrer_url'),
                    'resource_type': precise_mapping.get('resource_type')
                }
            }
            
            deduplicated[secret_hash]['occurrences'].append(occurrence)
            deduplicated[secret_hash]['total_count'] += 1
            
            # Track precise mapping metrics
            if precise_mapping.get('precision_level') == 'exact':
                deduplicated[secret_hash]['precise_mapping']['exact_mappings'] += 1
            else:
                deduplicated[secret_hash]['precise_mapping']['fallback_mappings'] += 1
            
            # Track parent pages and load context
            if precise_mapping.get('parent_page_url'):
                deduplicated[secret_hash]['precise_mapping']['parent_pages'].add(precise_mapping['parent_page_url'])
            
            if precise_mapping.get('load_method'):
                deduplicated[secret_hash]['precise_mapping']['load_methods'].add(precise_mapping['load_method'])
            
            if precise_mapping.get('load_timing_ms'):
                deduplicated[secret_hash]['precise_mapping']['timing_data'].append(precise_mapping['load_timing_ms'])
            
            if precise_mapping.get('resource_type'):
                deduplicated[secret_hash]['precise_mapping']['resource_types'].add(precise_mapping['resource_type'])
            
            # Continue with existing logic
            deduplicated[secret_hash]['detection_tools'].add(occurrence['tool'])
            if occurrence['file_path']:
                deduplicated[secret_hash]['unique_files'].add(occurrence['file_path'])
            if occurrence['url']:
                deduplicated[secret_hash]['unique_urls'].add(occurrence['url'])
            
            if occurrence['validation_result']:
                deduplicated[secret_hash]['validation_results'].append(occurrence['validation_result'])
                if occurrence['validation_result'].get('valid'):
                    deduplicated[secret_hash]['verified_count'] += 1
            
            # Update confidence and baseline status
            confidence_levels = {'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
            current_conf = confidence_levels.get(occurrence['confidence'], 0)
            highest_conf = confidence_levels.get(deduplicated[secret_hash]['highest_confidence'], 0)
            if current_conf > highest_conf:
                deduplicated[secret_hash]['highest_confidence'] = occurrence['confidence']
            
            if 'risk_score' in finding:
                deduplicated[secret_hash]['risk_scores'].append(finding['risk_score'])
            
            if occurrence['baseline_status'] == 'new':
                deduplicated[secret_hash]['baseline_status'] = 'new'
            elif occurrence['baseline_status'] == 'recurring' and deduplicated[secret_hash]['baseline_status'] != 'new':
                deduplicated[secret_hash]['baseline_status'] = 'recurring'
        
        # Post-process enhanced data
        for secret_hash, data in deduplicated.items():
            # Convert sets to sorted lists
            data['detection_tools'] = sorted(list(data['detection_tools']))
            data['unique_files'] = sorted(list(data['unique_files']))
            data['unique_urls'] = sorted(list(data['unique_urls']))
            
            # Enhanced precise mapping processing
            precise = data['precise_mapping']
            precise['parent_pages'] = sorted(list(precise['parent_pages']))
            precise['load_methods'] = sorted(list(precise['load_methods']))
            precise['resource_types'] = sorted(list(precise['resource_types']))
            
            # Calculate timing statistics
            if precise['timing_data']:
                precise['avg_load_timing'] = sum(precise['timing_data']) / len(precise['timing_data'])
                precise['min_load_timing'] = min(precise['timing_data'])
                precise['max_load_timing'] = max(precise['timing_data'])
            else:
                precise['avg_load_timing'] = 0
                precise['min_load_timing'] = 0
                precise['max_load_timing'] = 0
            
            # Calculate precision percentage
            total_mappings = precise['exact_mappings'] + precise['fallback_mappings']
            if total_mappings > 0:
                precise['precision_percentage'] = (precise['exact_mappings'] / total_mappings) * 100
            else:
                precise['precision_percentage'] = 0
            
            # Continue with existing post-processing
            if data['risk_scores']:
                data['avg_risk_score'] = sum(data['risk_scores']) / len(data['risk_scores'])
                data['max_risk_score'] = max(data['risk_scores'])
            else:
                data['avg_risk_score'] = 0
                data['max_risk_score'] = 0
            
            if data['verified_count'] > 0:
                data['overall_validation_status'] = 'Verified Active'
                data['validation_class'] = 'verified'
            elif data['validation_results']:
                data['overall_validation_status'] = 'Invalid/Inactive'
                data['validation_class'] = 'invalid'
            else:
                data['overall_validation_status'] = 'Not Validated'
                data['validation_class'] = 'not-validated'
            
            data['occurrences'].sort(key=lambda x: x['timestamp'])
        
        return deduplicated
    
    def _calculate_enhanced_statistics_with_precise_mapping(self, deduplicated: Dict[str, Dict[str, Any]], 
                                                          raw_findings: List[Dict[str, Any]],
                                                          resource_dependencies: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate enhanced statistics including precise mapping metrics"""
        stats = self._calculate_enhanced_statistics(deduplicated, raw_findings)
        
        # Add precise mapping statistics
        if self.enable_precise_mapping:
            total_exact = sum(data['precise_mapping']['exact_mappings'] for data in deduplicated.values())
            total_fallback = sum(data['precise_mapping']['fallback_mappings'] for data in deduplicated.values())
            total_mappings = total_exact + total_fallback
            
            stats['precise_mapping'] = {
                'total_mappings': total_mappings,
                'exact_mappings': total_exact,
                'fallback_mappings': total_fallback,
                'precision_rate': (total_exact / total_mappings * 100) if total_mappings > 0 else 0,
                'unique_parent_pages': len(set().union(*(data['precise_mapping']['parent_pages'] for data in deduplicated.values()))),
                'load_methods_found': len(set().union(*(data['precise_mapping']['load_methods'] for data in deduplicated.values()))),
                'resource_types_found': len(set().union(*(data['precise_mapping']['resource_types'] for data in deduplicated.values())))
            }
            
            # Load method distribution
            load_method_counts = {}
            for data in deduplicated.values():
                for method in data['precise_mapping']['load_methods']:
                    load_method_counts[method] = load_method_counts.get(method, 0) + 1
            stats['by_load_method'] = load_method_counts
            
            # Resource type distribution
            resource_type_counts = {}
            for data in deduplicated.values():
                for rtype in data['precise_mapping']['resource_types']:
                    resource_type_counts[rtype] = resource_type_counts.get(rtype, 0) + 1
            stats['by_resource_type'] = resource_type_counts
        
        # Add resource dependency statistics
        if resource_dependencies:
            stats['resource_dependencies'] = {
                'total_resources': resource_dependencies.get('total_resources', 0),
                'unique_pages': len(resource_dependencies.get('page_resource_map', {})),
                'load_method_distribution': resource_dependencies.get('load_method_distribution', {}),
                'timing_distribution': resource_dependencies.get('timing_distribution', {})
            }
        
        return stats
    
    def _prepare_enhanced_charts_data_with_precise_mapping(self, deduplicated: Dict[str, Dict[str, Any]], 
                                                          resource_dependencies: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare enhanced charts data including precise mapping visualizations"""
        charts_data = self._prepare_enhanced_charts_data(deduplicated)
        
        if not self.enable_precise_mapping:
            return charts_data
        
        # Add precise mapping charts
        if deduplicated:
            # Precision Level Chart
            exact_count = sum(1 for data in deduplicated.values() if data['precise_mapping']['exact_mappings'] > 0)
            fallback_count = len(deduplicated) - exact_count
            
            charts_data['precision_chart'] = [
                {'label': 'Exact Mapping', 'value': exact_count, 'color': '#27ae60'},
                {'label': 'Fallback Mapping', 'value': fallback_count, 'color': '#f39c12'}
            ]
            
            # Load Method Chart
            load_method_counts = {}
            for data in deduplicated.values():
                for method in data['precise_mapping']['load_methods']:
                    load_method_counts[method] = load_method_counts.get(method, 0) + 1
            
            load_method_colors = {
                'static': '#3498db',
                'dynamic': '#e74c3c', 
                'fetch': '#9b59b6',
                'xhr': '#e67e22',
                'import': '#1abc9c'
            }
            
            charts_data['load_method_chart'] = []
            for method, count in load_method_counts.items():
                charts_data['load_method_chart'].append({
                    'label': method.capitalize() if method else 'Unknown',
                    'value': count,
                    'color': load_method_colors.get(method, '#95a5a6')
                })
            
            # Timing Distribution Chart
            timing_buckets = {
                '0-100ms': 0,
                '100-500ms': 0, 
                '500ms-1s': 0,
                '1-5s': 0,
                '5s+': 0
            }
            
            for data in deduplicated.values():
                for timing in data['precise_mapping']['timing_data']:
                    bucket = self._get_timing_bucket(timing)
                    timing_buckets[bucket] += 1
            
            charts_data['timing_distribution_chart'] = []
            for bucket, count in timing_buckets.items():
                if count > 0:
                    charts_data['timing_distribution_chart'].append({
                        'label': bucket,
                        'value': count
                    })
        
        # Add resource dependency charts from database
        if resource_dependencies:
            # Resource dependency overview
            dep_data = resource_dependencies.get('page_resource_map', {})
            if dep_data:
                page_counts = []
                for page, resources in dep_data.items():
                    page_counts.append({
                        'label': page.split('/')[-1][:20] + '...' if len(page) > 20 else page,
                        'value': len(resources)
                    })
                
                # Top 10 pages by resource count
                page_counts.sort(key=lambda x: x['value'], reverse=True)
                charts_data['resource_dependency_chart'] = page_counts[:10]
        
        # Ensure all charts have data
        chart_defaults = {
            'precision_chart': [{'label': 'No Data', 'value': 0, 'color': '#95a5a6'}],
            'load_method_chart': [{'label': 'No Data', 'value': 0, 'color': '#95a5a6'}], 
            'timing_distribution_chart': [{'label': 'No Data', 'value': 0}],
            'resource_dependency_chart': [{'label': 'No Data', 'value': 0}]
        }
        
        for chart_name, default_data in chart_defaults.items():
            if chart_name not in charts_data or not charts_data[chart_name]:
                charts_data[chart_name] = default_data
        
        return charts_data
    
    def _render_enhanced_html(self, report_data: Dict[str, Any]) -> str:
        """Render enhanced HTML report with precise URL mapping"""
        # Use enhanced template if precise mapping is enabled
        if report_data.get('precise_mapping_enabled', False):
            template = Template(self._get_enhanced_precise_mapping_html_template())
        elif report_data.get('deduplicated', False):
            template = Template(self._get_enhanced_html_template())
        else:
            template = Template(self._get_html_template())
        
        # Add helper functions
        report_data['json_dumps'] = json.dumps
        report_data['enumerate'] = enumerate
        
        # Convert chart data to JSON for JavaScript
        charts = report_data['charts_data']
        
        # Basic charts
        chart_names = ['severity_chart', 'type_chart', 'tool_chart', 'validation_chart', 'occurrence_distribution']
        
        # Enhanced charts for precise mapping
        if report_data.get('precise_mapping_enabled', False):
            chart_names.extend(['precision_chart', 'load_method_chart', 'timing_distribution_chart', 'resource_dependency_chart'])
        
        for chart_name in chart_names:
            if chart_name in charts and charts[chart_name]:
                report_data[f'{chart_name}_labels'] = json.dumps([item['label'] for item in charts[chart_name]])
                report_data[f'{chart_name}_values'] = json.dumps([item['value'] for item in charts[chart_name]])
                if charts[chart_name] and 'color' in charts[chart_name][0]:
                    report_data[f'{chart_name}_colors'] = json.dumps([item.get('color', '#3498db') for item in charts[chart_name]])
            else:
                report_data[f'{chart_name}_labels'] = json.dumps(['No Data'])
                report_data[f'{chart_name}_values'] = json.dumps([0])
                report_data[f'{chart_name}_colors'] = json.dumps(['#95a5a6'])
        
        return template.render(**report_data)
    
    def _get_enhanced_precise_mapping_html_template(self) -> str:
        """Get enhanced HTML template with precise URL mapping features"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ company_name }} - Enhanced Precise URL Mapping Report</title>
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
        .feature-badge {
            background: #27ae60;
            color: white;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            margin-left: 10px;
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
        .summary-card.precise::before {
            background: linear-gradient(90deg, #27ae60, #2ecc71);
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
        
        /* Load Method Indicators */
        .load-method-indicator {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            font-size: 0.85em;
            margin-right: 8px;
        }
        .load-method-static { color: #3498db; }
        .load-method-dynamic { color: #e74c3c; }
        .load-method-fetch { color: #9b59b6; }
        .load-method-xhr { color: #e67e22; }
        
        /* Precision Indicators */
        .precision-indicator {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            font-size: 0.85em;
        }
        .precision-exact { color: #27ae60; }
        .precision-fallback { color: #f39c12; }
        
        /* Timing Badges */
        .timing-badge {
            background: #ecf0f1;
            color: #2c3e50;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            margin-left: 8px;
        }
        .timing-fast { background: #d5f4e6; color: #27ae60; }
        .timing-medium { background: #fef9e7; color: #f39c12; }
        .timing-slow { background: #fadbd8; color: #e74c3c; }
        
        /* Enhanced Charts Section */
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
        
        /* Enhanced Finding Card with Precise Mapping */
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
            margin-bottom: 15px;
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
            flex-wrap: wrap;
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
        
        /* Precise Location Section */
        .precise-location {
            background: #e8f5e8;
            border: 1px solid #d4efd4;
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
        }
        .precise-location-header {
            font-weight: bold;
            color: #27ae60;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .precise-location-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .location-item {
            display: flex;
            align-items: flex-start;
            gap: 8px;
        }
        .location-label {
            font-weight: bold;
            color: #2c3e50;
            min-width: 100px;
            flex-shrink: 0;
        }
        .location-value {
            flex: 1;
            word-break: break-all;
        }
        .parent-page-url {
            color: #27ae60;
            text-decoration: none;
            font-weight: bold;
        }
        .parent-page-url:hover {
            text-decoration: underline;
        }
        
        /* Resource Chain */
        .resource-chain {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 12px;
            margin-top: 10px;
            font-family: monospace;
            font-size: 0.9em;
        }
        .chain-arrow {
            color: #6c757d;
            margin: 0 8px;
        }
        .chain-page {
            color: #007bff;
            text-decoration: none;
        }
        .chain-resource {
            color: #28a745;
            font-weight: bold;
        }
        
        /* Enhanced Finding Summary */
        .finding-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
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
            padding: 15px;
            border-radius: 6px;
            margin-top: 15px;
            font-family: 'Consolas', 'Monaco', monospace;
            word-break: break-all;
            border: 1px solid #ffcccc;
        }
        .secret-value {
            color: #c0392b;
            font-weight: bold;
            font-size: 1.1em;
        }
        
        /* Enhanced Occurrences */
        .finding-details {
            padding: 20px;
            display: none;
            max-height: 800px;
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
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .occurrence-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 15px;
            border: 1px solid #e1e8ed;
            position: relative;
        }
        .occurrence-item:hover {
            background: #f1f3f5;
        }
        .occurrence-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #dee2e6;
        }
        .occurrence-badges {
            display: flex;
            gap: 8px;
            align-items: center;
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
        
        /* Enhanced Context Display */
        .code-context {
            background: #f4f4f4;
            padding: 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
            margin-top: 10px;
            overflow-x: auto;
            border: 1px solid #ddd;
            max-height: 200px;
            overflow-y: auto;
        }
        
        /* Expand/Collapse */
        .expand-icon {
            transition: transform 0.3s;
            margin-left: 10px;
            color: #3498db;
            font-size: 1.2em;
        }
        .expand-icon.expanded {
            transform: rotate(180deg);
        }
        
        /* Enhanced Filters */
        .filters {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .filter-row {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            align-items: center;
            margin-bottom: 15px;
        }
        .filter-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .filter-label {
            font-weight: bold;
            color: #2c3e50;
            min-width: 80px;
        }
        select, input[type="text"] {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            min-width: 150px;
        }
        .export-buttons {
            margin-left: auto;
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
        .btn-success {
            background: #27ae60;
            color: white;
        }
        .btn-success:hover {
            background: #229954;
        }
        
        /* Statistics Panel */
        .stats-panel {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stats-title {
            font-size: 1.5em;
            color: #2c3e50;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .stat-item {
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 0.9em;
            margin-top: 5px;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 30px 0;
            color: #7f8c8d;
            margin-top: 50px;
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
            .filter-row {
                flex-direction: column;
                align-items: flex-start;
            }
            .export-buttons {
                margin-left: 0;
                margin-top: 15px;
            }
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
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔐 {{ company_name }} Security Report</h1>
            <div class="subtitle">
                Enhanced Secret Scanner with Precise URL Mapping - {{ report_type|title }} Report
                <span class="feature-badge">✅ Precise Mapping Enabled</span>
                <br>Generated: {{ generated_at_formatted }}
                {% if scan_id %}<br>Scan ID: {{ scan_id }}{% endif %}
            </div>
        </div>
    </header>
    
    <div class="container">
        <!-- Enhanced Summary Cards with Precise Mapping -->
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
            {% if statistics.precise_mapping %}
            <div class="summary-card precise">
                <div class="summary-value" style="color: #27ae60;">{{ "%.1f"|format(statistics.precise_mapping.precision_rate) }}%</div>
                <div class="summary-label">Mapping Precision</div>
                <div class="summary-sublabel">{{ statistics.precise_mapping.exact_mappings }} exact, {{ statistics.precise_mapping.fallback_mappings }} fallback</div>
            </div>
            {% endif %}
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
        
        <!-- Precise Mapping Statistics Panel -->
        {% if statistics.precise_mapping %}
        <div class="stats-panel">
            <h3 class="stats-title">
                🎯 Precise URL Mapping Statistics
            </h3>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value" style="color: #27ae60;">{{ statistics.precise_mapping.exact_mappings }}</div>
                    <div class="stat-label">Exact Mappings</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value" style="color: #f39c12;">{{ statistics.precise_mapping.fallback_mappings }}</div>
                    <div class="stat-label">Fallback Mappings</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{ statistics.precise_mapping.unique_parent_pages }}</div>
                    <div class="stat-label">Parent Pages</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{ statistics.precise_mapping.load_methods_found }}</div>
                    <div class="stat-label">Load Methods</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{{ statistics.precise_mapping.resource_types_found }}</div>
                    <div class="stat-label">Resource Types</div>
                </div>
            </div>
        </div>
        {% endif %}
        
        <!-- Enhanced Charts Section with Precise Mapping -->
        <div class="charts-section">
            <div class="chart-container">
                <h3 class="chart-title">Findings by Severity</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3 class="chart-title">Validation Status</h3>
                <canvas id="validationChart"></canvas>
            </div>
            {% if statistics.precise_mapping %}
            <div class="chart-container">
                <h3 class="chart-title">Mapping Precision</h3>
                <canvas id="precisionChart"></canvas>
            </div>
            <div class="chart-container">
                <h3 class="chart-title">Load Methods</h3>
                <canvas id="loadMethodChart"></canvas>
            </div>
            <div class="chart-container">
                <h3 class="chart-title">Load Timing Distribution</h3>
                <canvas id="timingDistributionChart"></canvas>
            </div>
            {% endif %}
            <div class="chart-container">
                <h3 class="chart-title">Top Secret Types</h3>
                <canvas id="typeChart"></canvas>
            </div>
        </div>
        
        <!-- Enhanced Filters -->
        <div class="filters">
            <div class="filter-row">
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
                {% if statistics.precise_mapping %}
                <div class="filter-group">
                    <span class="filter-label">Precision:</span>
                    <select id="precisionFilter" onchange="filterFindings()">
                        <option value="">All</option>
                        <option value="exact">Exact Mapping</option>
                        <option value="fallback">Fallback Mapping</option>
                    </select>
                </div>
                <div class="filter-group">
                    <span class="filter-label">Load Method:</span>
                    <select id="loadMethodFilter" onchange="filterFindings()">
                        <option value="">All</option>
                        {% for method in statistics.by_load_method.keys() %}
                        <option value="{{ method }}">{{ method|capitalize }}</option>
                        {% endfor %}
                    </select>
                </div>
                {% endif %}
            </div>
            <div class="filter-row">
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
                    <button class="btn btn-success" onclick="exportPreciseMappingData()">Export Precise Data</button>
                    <button class="btn btn-primary" onclick="exportToJSON()">Export JSON</button>
                    <button class="btn btn-primary" onclick="window.print()">Print Report</button>
                </div>
            </div>
        </div>
        
        <!-- Enhanced Findings Section with Precise URL Mapping -->
        <div class="findings-section">
            <h2 class="section-title">Enhanced Secret Findings with Precise URL Mapping</h2>
            
            {% if findings %}
                <div id="findingsContainer">
                    {% for finding in findings %}
                    <div class="finding-card" 
                         data-severity="{{ finding.severity }}" 
                         data-type="{{ finding.type }}" 
                         data-validation="{{ finding.validation_class }}"
                         {% if finding.precise_mapping %}data-precision="{{ finding.precise_mapping.precision_percentage > 50 }}"
                         data-load-method="{{ finding.precise_mapping.load_methods[0] if finding.precise_mapping.load_methods else 'unknown' }}"{% endif %}
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
                            
                            <!-- Precise Location Information -->
                            {% if finding.precise_mapping and finding.precise_mapping.parent_pages %}
                            <div class="precise-location">
                                <div class="precise-location-header">
                                    🎯 Precise Location Context
                                    {% if finding.precise_mapping.precision_percentage > 80 %}
                                    <span class="precision-indicator precision-exact">✅ Exact Mapping</span>
                                    {% else %}
                                    <span class="precision-indicator precision-fallback">⚠️ Fallback Mapping</span>
                                    {% endif %}
                                </div>
                                <div class="precise-location-grid">
                                    <div class="location-item">
                                        <span class="location-label">Parent Page:</span>
                                        <a href="{{ finding.precise_mapping.parent_pages[0] }}" target="_blank" class="parent-page-url location-value">
                                            {{ finding.precise_mapping.parent_pages[0] }}
                                        </a>
                                    </div>
                                    {% if finding.precise_mapping.load_methods %}
                                    <div class="location-item">
                                        <span class="location-label">Load Method:</span>
                                        <span class="location-value">
                                            {% for method in finding.precise_mapping.load_methods %}
                                            <span class="load-method-indicator load-method-{{ method }}">
                                                {% if method == 'static' %}🔗
                                                {% elif method == 'dynamic' %}⚡
                                                {% elif method == 'fetch' %}🌐
                                                {% elif method == 'xhr' %}📡
                                                {% else %}❓{% endif %}
                                                {{ method|capitalize }}
                                            </span>
                                            {% endfor %}
                                        </span>
                                    </div>
                                    {% endif %}
                                    {% if finding.precise_mapping.avg_load_timing > 0 %}
                                    <div class="location-item">
                                        <span class="location-label">Load Timing:</span>
                                        <span class="location-value">
                                            <span class="timing-badge {% if finding.precise_mapping.avg_load_timing < 500 %}timing-fast{% elif finding.precise_mapping.avg_load_timing < 2000 %}timing-medium{% else %}timing-slow{% endif %}">
                                                ⏱ {{ finding.precise_mapping.avg_load_timing|int }}ms avg
                                            </span>
                                        </span>
                                    </div>
                                    {% endif %}
                                    {% if finding.precise_mapping.resource_types %}
                                    <div class="location-item">
                                        <span class="location-label">Resource Type:</span>
                                        <span class="location-value">{{ finding.precise_mapping.resource_types|join(', ')|title }}</span>
                                    </div>
                                    {% endif %}
                                </div>
                                
                                <!-- Resource Chain Visualization -->
                                {% if finding.precise_mapping.parent_pages and finding.precise_mapping.parent_pages[0] != 'Unknown' %}
                                <div class="resource-chain">
                                    <a href="{{ finding.precise_mapping.parent_pages[0] }}" class="chain-page">{{ finding.precise_mapping.parent_pages[0].split('/')[-1] or 'Page' }}</a>
                                    <span class="chain-arrow">→</span>
                                    <span class="chain-resource">{{ (finding.precise_mapping.resource_url or finding.occurrences[0].file_path or 'Unknown').split('/')[-1] }}</span>
                                    <span class="chain-arrow">→</span>
                                    <span style="color: #e74c3c; font-weight: bold;">🔑 Secret</span>
                                </div>
                                {% endif %}
                            </div>
                            {% endif %}
                            
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
                                📋 All Occurrences ({{ finding.total_count }}):
                            </div>
                            
                            {% for occurrence in finding.occurrences %}
                            <div class="occurrence-item">
                                <div class="occurrence-header">
                                    <strong>Occurrence #{{ loop.index }}</strong>
                                    <div class="occurrence-badges">
                                        {% if occurrence.precise_mapping %}
                                        {% if occurrence.precise_mapping.precision_level == 'exact' %}
                                        <span class="badge" style="background: #27ae60; color: white;">✅ Exact</span>
                                        {% else %}
                                        <span class="badge" style="background: #f39c12; color: white;">⚠️ Fallback</span>
                                        {% endif %}
                                        {% endif %}
                                        {% if occurrence.precise_mapping and occurrence.precise_mapping.load_method %}
                                        <span class="badge load-method-{{ occurrence.precise_mapping.load_method }}" style="background: #ecf0f1; color: #2c3e50;">
                                            {% if occurrence.precise_mapping.load_method == 'static' %}🔗
                                            {% elif occurrence.precise_mapping.load_method == 'dynamic' %}⚡
                                            {% elif occurrence.precise_mapping.load_method == 'fetch' %}🌐
                                            {% else %}📡{% endif %}
                                            {{ occurrence.precise_mapping.load_method|capitalize }}
                                        </span>
                                        {% endif %}
                                    </div>
                                </div>
                                
                                {% if occurrence.precise_mapping and occurrence.precise_mapping.parent_page_url != 'Unknown' %}
                                <div class="detail-row">
                                    <span class="detail-label">Parent Page:</span>
                                    <a href="{{ occurrence.precise_mapping.parent_page_url }}" target="_blank" class="parent-page-url detail-value">
                                        {{ occurrence.precise_mapping.parent_page_url }}
                                    </a>
                                </div>
                                {% endif %}
                                
                                {% if occurrence.precise_mapping.resource_url %}
                                <div class="detail-row">
                                    <span class="detail-label">Resource URL:</span>
                                    <a href="{{ occurrence.precise_mapping.resource_url }}" target="_blank" class="url-value detail-value">{{ occurrence.precise_mapping.resource_url }}</a>
                                </div>
                                {% elif occurrence.url %}
                                <div class="detail-row">
                                    <span class="detail-label">Resource URL:</span>
                                    <a href="{{ occurrence.url }}" target="_blank" class="url-value detail-value">{{ occurrence.url }}</a>
                                </div>
                                {% endif %}
                                
                                <div class="detail-row">
                                    <span class="detail-label">File Path:</span>
                                    <span class="detail-value">{{ occurrence.file_path }}</span>
                                </div>
                                
                                <div class="detail-row">
                                    <span class="detail-label">Line:Column:</span>
                                    <span class="detail-value">{{ occurrence.line }}:{{ occurrence.column }}</span>
                                </div>
                                
                                {% if occurrence.precise_mapping and occurrence.precise_mapping.load_timing_ms %}
                                <div class="detail-row">
                                    <span class="detail-label">Load Timing:</span>
                                    <span class="detail-value">
                                        <span class="timing-badge {% if occurrence.precise_mapping.load_timing_ms < 500 %}timing-fast{% elif occurrence.precise_mapping.load_timing_ms < 2000 %}timing-medium{% else %}timing-slow{% endif %}">
                                            ⏱ {{ occurrence.precise_mapping.load_timing_ms }}ms after page load
                                        </span>
                                    </span>
                                </div>
                                {% endif %}
                                
                                {% if occurrence.precise_mapping and occurrence.precise_mapping.referrer_url %}
                                <div class="detail-row">
                                    <span class="detail-label">Referrer:</span>
                                    <a href="{{ occurrence.precise_mapping.referrer_url }}" target="_blank" class="url-value detail-value">{{ occurrence.precise_mapping.referrer_url }}</a>
                                </div>
                                {% endif %}
                                
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
                                        {% if occurrence.validation_result.validated_at %}
                                        ({{ occurrence.validation_result.validated_at }})
                                        {% endif %}
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
        <p>Generated by Enhanced Automated Secrets Scanner with Precise URL Mapping | {{ company_name }}</p>
        <p>Report generated on {{ generated_at_formatted }}</p>
        <p>{{ total_unique_secrets }} total secrets found with precise URL mapping context</p>
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
        
        // Enhanced chart initialization
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
            
            {% if statistics.precise_mapping %}
            // Precision Chart
            const precisionCtx = document.getElementById('precisionChart');
            if (precisionCtx && {{ precision_chart_values|default('[]')|safe }}.length > 0) {
                new Chart(precisionCtx.getContext('2d'), {
                    type: 'doughnut',
                    data: {
                        labels: {{ precision_chart_labels|default('[]')|safe }},
                        datasets: [{
                            data: {{ precision_chart_values|default('[]')|safe }},
                            backgroundColor: {{ precision_chart_colors|default('[]')|safe }}
                        }]
                    },
                    options: chartOptions
                });
            }
            
            // Load Method Chart
            const loadMethodCtx = document.getElementById('loadMethodChart');
            if (loadMethodCtx && {{ load_method_chart_values|default('[]')|safe }}.length > 0) {
                new Chart(loadMethodCtx.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: {{ load_method_chart_labels|default('[]')|safe }},
                        datasets: [{
                            label: 'Secrets',
                            data: {{ load_method_chart_values|default('[]')|safe }},
                            backgroundColor: {{ load_method_chart_colors|default('[]')|safe }}
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
            
            // Timing Distribution Chart
            const timingCtx = document.getElementById('timingDistributionChart');
            if (timingCtx && {{ timing_distribution_chart_values|default('[]')|safe }}.length > 0) {
                new Chart(timingCtx.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: {{ timing_distribution_chart_labels|default('[]')|safe }},
                        datasets: [{
                            label: 'Secrets',
                            data: {{ timing_distribution_chart_values|default('[]')|safe }},
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
            {% endif %}
            
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
        });
        
        // Enhanced filtering with precise mapping
        function filterFindings() {
            const severityFilter = document.getElementById('severityFilter').value;
            const validationFilter = document.getElementById('validationFilter').value;
            const typeFilter = document.getElementById('typeFilter').value;
            const searchFilter = document.getElementById('searchFilter').value.toLowerCase();
            
            // Enhanced filters
            const precisionFilter = document.getElementById('precisionFilter') ? document.getElementById('precisionFilter').value : '';
            const loadMethodFilter = document.getElementById('loadMethodFilter') ? document.getElementById('loadMethodFilter').value : '';
            
            const findings = document.querySelectorAll('.finding-card');
            let visibleCount = 0;
            
            findings.forEach(finding => {
                const severity = finding.getAttribute('data-severity');
                const validation = finding.getAttribute('data-validation');
                const type = finding.getAttribute('data-type');
                const precision = finding.getAttribute('data-precision');
                const loadMethod = finding.getAttribute('data-load-method');
                const text = finding.textContent.toLowerCase();
                
                const matchesSeverity = !severityFilter || severity === severityFilter;
                const matchesValidation = !validationFilter || validation === validationFilter;
                const matchesType = !typeFilter || type === typeFilter;
                const matchesSearch = !searchFilter || text.includes(searchFilter);
                const matchesPrecision = !precisionFilter || 
                    (precisionFilter === 'exact' && precision === 'true') ||
                    (precisionFilter === 'fallback' && precision === 'false');
                const matchesLoadMethod = !loadMethodFilter || loadMethod === loadMethodFilter;
                
                if (matchesSeverity && matchesValidation && matchesType && matchesSearch && 
                    matchesPrecision && matchesLoadMethod) {
                    finding.style.display = 'block';
                    visibleCount++;
                } else {
                    finding.style.display = 'none';
                }
            });
        }
        
        // Enhanced export with precise mapping data
        function exportPreciseMappingData() {
            const reportData = {{ findings|tojson }};
            const enhancedData = {
                report_type: '{{ report_type }}',
                generated_at: '{{ generated_at }}',
                precise_mapping_enabled: true,
                total_unique_secrets: {{ total_unique_secrets }},
                total_raw_findings: {{ total_raw_findings }},
                statistics: {{ statistics|tojson }},
                findings_with_precise_mapping: reportData,
                resource_dependencies: {{ resource_dependencies|tojson if resource_dependencies else '{}' }}
            };
            
            const dataStr = JSON.stringify(enhancedData, null, 2);
            const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
            
            const exportFileDefaultName = 'precise_mapping_secret_findings_' + new Date().toISOString().slice(0,10) + '.json';
            
            const linkElement = document.createElement('a');
            linkElement.setAttribute('href', dataUri);
            linkElement.setAttribute('download', exportFileDefaultName);
            linkElement.click();
        }
        
        // Regular export functionality
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
    
    # Keep all existing methods unchanged, just add the enhanced methods above
    def _prepare_enhanced_report_data(self, findings: List[Dict[str, Any]], 
                                     report_type: str,
                                     comparison_data: Optional[Dict[str, Any]],
                                     validation_results: Optional[Dict[str, Any]],
                                     resource_dependencies: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Enhanced version of _prepare_report_data with precise URL mapping"""
        # Use existing method as base and enhance it
        report_data = self._prepare_report_data(findings, report_type, comparison_data, validation_results)
        
        # Add precise mapping enhancements
        if self.enable_precise_mapping:
            report_data['precise_mapping_enabled'] = True
            report_data['resource_dependencies'] = resource_dependencies or {}
            
            # Add precise mapping statistics
            if findings:
                precise_stats = self._calculate_precise_mapping_stats(findings)
                if 'statistics' not in report_data:
                    report_data['statistics'] = {}
                report_data['statistics']['precise_mapping'] = precise_stats
        
        return report_data
    
    def _calculate_precise_mapping_stats(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate precise mapping statistics from findings"""
        stats = {
            'total_findings': len(findings),
            'exact_mappings': 0,
            'fallback_mappings': 0,
            'precision_rate': 0,
            'unique_parent_pages': set(),
            'load_methods_found': set(),
            'resource_types_found': set()
        }
        
        for finding in findings:
            precise_mapping = finding.get('precise_mapping', {})
            
            if precise_mapping.get('precision_level') == 'exact':
                stats['exact_mappings'] += 1
            else:
                stats['fallback_mappings'] += 1
            
            if precise_mapping.get('parent_page_url'):
                stats['unique_parent_pages'].add(precise_mapping['parent_page_url'])
            
            if precise_mapping.get('load_method'):
                stats['load_methods_found'].add(precise_mapping['load_method'])
            
            if precise_mapping.get('resource_type'):
                stats['resource_types_found'].add(precise_mapping['resource_type'])
        
        # Calculate precision rate
        total = stats['exact_mappings'] + stats['fallback_mappings']
        if total > 0:
            stats['precision_rate'] = (stats['exact_mappings'] / total) * 100
        
        # Convert sets to counts
        stats['unique_parent_pages'] = len(stats['unique_parent_pages'])
        stats['load_methods_found'] = len(stats['load_methods_found'])
        stats['resource_types_found'] = len(stats['resource_types_found'])
        
        return stats
    
    # Keep all existing methods - just adding to them, not replacing
    def generate_report(self, findings: List[Dict[str, Any]], 
                       report_type: str = 'full',
                       comparison_data: Optional[Dict[str, Any]] = None,
                       validation_results: Optional[Dict[str, Any]] = None,
                       scan_id: Optional[str] = None) -> Path:
        """Generate HTML report (fallback for non-DB usage)"""
        return self.generate_enhanced_report(
            findings=findings,
            report_type=report_type,
            comparison_data=comparison_data,
            validation_results=validation_results,
            resource_dependencies=None,
            scan_id=scan_id
        )
    
    # Keep all other existing methods unchanged from the original implementation
    def _load_findings_from_db(self, scan_run_id: int = None, domains: List[str] = None) -> List[Dict[str, Any]]:
        """Keep original method for compatibility"""
        return self._load_findings_from_db_with_precise_mapping(scan_run_id, domains)
    
    def _load_validation_results_from_db(self, scan_run_id: int = None) -> Dict[str, Any]:
        """Load validation results summary from database"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT 
                        COUNT(DISTINCT f.id) as total_findings,
                        COUNT(DISTINCT CASE WHEN f.validation_status = 'completed' THEN f.id END) as validated,
                        COUNT(DISTINCT CASE WHEN json_extract(f.validation_result, '$.valid') = 1 THEN f.id END) as valid_secrets,
                        COUNT(DISTINCT CASE WHEN json_extract(f.validation_result, '$.valid') = 0 THEN f.id END) as invalid_secrets,
                        COUNT(DISTINCT CASE WHEN f.validation_status = 'error' THEN f.id END) as validation_errors
                    FROM findings f
                    WHERE 1=1
                """
                
                params = []
                if scan_run_id:
                    query += " AND f.scan_run_id = ?"
                    params.append(scan_run_id)
                
                cursor.execute(query, params)
                row = cursor.fetchone()
                
                if row:
                    return {
                        'summary': {
                            'total_findings': row[0],
                            'validated': row[1],
                            'valid_secrets': row[2],
                            'invalid_secrets': row[3],
                            'validation_errors': row[4]
                        }
                    }
                
        except Exception as e:
            logger.error(f"Error loading validation results: {e}")
        
        return {}
    
    def _load_comparison_data(self, current_scan_id: int, previous_scan_id: int) -> Dict[str, Any]:
        """Load comparison data between two scans"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get new findings (in current but not in previous)
                cursor.execute("""
                    SELECT COUNT(DISTINCT s.secret_hash) as new_count
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    WHERE f.scan_run_id = ?
                    AND s.secret_hash NOT IN (
                        SELECT DISTINCT s2.secret_hash
                        FROM findings f2
                        JOIN secrets s2 ON f2.secret_id = s2.id
                        WHERE f2.scan_run_id = ?
                    )
                """, (current_scan_id, previous_scan_id))
                
                new_count = cursor.fetchone()[0]
                
                # Get recurring findings
                cursor.execute("""
                    SELECT COUNT(DISTINCT s.secret_hash) as recurring_count
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    WHERE f.scan_run_id = ?
                    AND s.secret_hash IN (
                        SELECT DISTINCT s2.secret_hash
                        FROM findings f2
                        JOIN secrets s2 ON f2.secret_id = s2.id
                        WHERE f2.scan_run_id = ?
                    )
                """, (current_scan_id, previous_scan_id))
                
                recurring_count = cursor.fetchone()[0]
                
                # Get resolved findings
                cursor.execute("""
                    SELECT COUNT(DISTINCT s.secret_hash) as resolved_count
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    WHERE f.scan_run_id = ?
                    AND s.secret_hash NOT IN (
                        SELECT DISTINCT s2.secret_hash
                        FROM findings f2
                        JOIN secrets s2 ON f2.secret_id = s2.id
                        WHERE f2.scan_run_id = ?
                    )
                """, (previous_scan_id, current_scan_id))
                
                resolved_count = cursor.fetchone()[0]
                
                return {
                    'new': list(range(new_count)),
                    'recurring': list(range(recurring_count)),
                    'resolved': list(range(resolved_count)),
                    'new_count': new_count,
                    'recurring_count': recurring_count,
                    'resolved_count': resolved_count
                }
                
        except Exception as e:
            logger.error(f"Error loading comparison data: {e}")
            return {
                'new': [],
                'recurring': [],
                'resolved': []
            }
    
    def _calculate_statistics_from_db(self, scan_run_id: int = None, domains: List[str] = None) -> Dict[str, Any]:
        """Calculate statistics using database queries"""
        stats = {
            'total': 0,
            'by_type': {},
            'by_severity': {},
            'by_tool': {},
            'verified': 0,
            'critical_count': 0,
            'high_count': 0,
            'unique_files': 0,
            'unique_urls': 0,
            'total_raw_findings': 0,
            'total_unique_secrets': 0,
            'deduplication_ratio': '0%'
        }
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                base_conditions = " WHERE 1=1"
                params = []
                
                if scan_run_id:
                    base_conditions += " AND f.scan_run_id = ?"
                    params.append(scan_run_id)
                
                if domains:
                    placeholders = ','.join(['?' for _ in domains])
                    base_conditions += f" AND u.domain IN ({placeholders})"
                    params.extend(domains)
                
                # Total findings and unique secrets
                cursor.execute(f"""
                    SELECT 
                        COUNT(DISTINCT f.id) as total_findings,
                        COUNT(DISTINCT s.id) as unique_secrets
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    LEFT JOIN urls u ON f.url_id = u.id
                    {base_conditions}
                """, params)
                
                row = cursor.fetchone()
                if row:
                    stats['total_raw_findings'] = row[0]
                    stats['total_unique_secrets'] = row[1]
                    stats['total'] = row[1]
                    
                    if row[0] > 0:
                        dedup_ratio = (1 - row[1]/row[0]) * 100
                        stats['deduplication_ratio'] = f"{dedup_ratio:.1f}%"
                
                # By type
                cursor.execute(f"""
                    SELECT s.secret_type, COUNT(DISTINCT s.id)
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    LEFT JOIN urls u ON f.url_id = u.id
                    {base_conditions}
                    GROUP BY s.secret_type
                """, params)
                
                for row in cursor.fetchall():
                    stats['by_type'][row[0]] = row[1]
                
                # By severity
                cursor.execute(f"""
                    SELECT 
                        s.severity,
                        COUNT(DISTINCT s.id),
                        SUM(CASE WHEN s.severity = 'critical' THEN 1 ELSE 0 END) as critical,
                        SUM(CASE WHEN s.severity = 'high' THEN 1 ELSE 0 END) as high
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    LEFT JOIN urls u ON f.url_id = u.id
                    {base_conditions}
                    GROUP BY s.severity
                """, params)
                
                for row in cursor.fetchall():
                    stats['by_severity'][row[0]] = row[1]
                    if row[2]:
                        stats['critical_count'] += row[2]
                    if row[3]:
                        stats['high_count'] += row[3]
                
                # By tool
                cursor.execute(f"""
                    SELECT s.detector_name, COUNT(DISTINCT s.id)
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    LEFT JOIN urls u ON f.url_id = u.id
                    {base_conditions}
                    GROUP BY s.detector_name
                """, params)
                
                for row in cursor.fetchall():
                    stats['by_tool'][row[0]] = row[1]
                
                # Verified count
                cursor.execute(f"""
                    SELECT COUNT(DISTINCT s.id)
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    LEFT JOIN urls u ON f.url_id = u.id
                    {base_conditions}
                    AND s.is_verified = 1
                """, params)
                
                stats['verified'] = cursor.fetchone()[0]
                
                # Unique locations
                cursor.execute(f"""
                    SELECT 
                        COUNT(DISTINCT f.file_path) as unique_files,
                        COUNT(DISTINCT u.url) as unique_urls
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    LEFT JOIN urls u ON f.url_id = u.id
                    {base_conditions}
                """, params)
                
                row = cursor.fetchone()
                if row:
                    stats['unique_files'] = row[0]
                    stats['unique_urls'] = row[1]
                
        except Exception as e:
            logger.error(f"Error calculating statistics from database: {e}")
        
        return stats
    
    def _store_report_metadata(self, scan_run_id: int, report_path: Path, report_type: str) -> None:
        """Store report metadata in database"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE scan_runs
                    SET report_path = ?,
                        report_type = ?,
                        report_generated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (str(report_path), report_type, scan_run_id))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error storing report metadata: {e}")
    
    def _save_report(self, html_content: str, report_type: str, scan_id: Optional[str] = None) -> Path:
        """Save HTML report to file"""
        if scan_id:
            filename = f"{scan_id}_{report_type}_enhanced_precise_report.html"
        else:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"enhanced_precise_secrets_report_{report_type}_{timestamp}.html"
        
        report_file = self.reports_path / filename
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_file
    
    # Keep all the existing deduplication and charting methods unchanged
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Deduplicate findings by grouping identical secrets (enhanced with precise mapping)"""
        if self.enable_precise_mapping:
            return self._deduplicate_findings_with_precise_mapping(findings)
        
        # Use original implementation for non-precise mapping
        deduplicated = {}
        
        for finding in findings:
            secret_value = finding.get('raw', finding.get('secret', 'N/A'))
            if secret_value == 'N/A':
                continue
                
            secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()[:16]
            
            if secret_hash not in deduplicated:
                deduplicated[secret_hash] = {
                    'secret': secret_value,
                    'secret_display': secret_value,
                    'redacted': secret_value,
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
                    'baseline_status': finding.get('baseline_status', 'unknown')
                }
        
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
            
            # Update baseline status
            if occurrence['baseline_status'] == 'new':
                deduplicated[secret_hash]['baseline_status'] = 'new'
            elif occurrence['baseline_status'] == 'recurring' and deduplicated[secret_hash]['baseline_status'] != 'new':
                deduplicated[secret_hash]['baseline_status'] = 'recurring'
        
        # Post-process data
        for secret_hash, data in deduplicated.items():
            data['detection_tools'] = sorted(list(data['detection_tools']))
            data['unique_files'] = sorted(list(data['unique_files']))
            data['unique_urls'] = sorted(list(data['unique_urls']))
            
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
            
            data['occurrences'].sort(key=lambda x: x['timestamp'])
        
        return deduplicated
    
    def _calculate_enhanced_statistics(self, deduplicated: Dict[str, Dict[str, Any]], 
                                     raw_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate enhanced statistics with deduplication info"""
        stats = {
            'total_raw_findings': len(raw_findings),
            'total_unique_secrets': len(deduplicated),
            'total': len(deduplicated),
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
    
    # Keep all other existing methods unchanged from the original implementation
    def _prepare_report_data(self, findings: List[Dict[str, Any]], 
                           report_type: str,
                           comparison_data: Optional[Dict[str, Any]],
                           validation_results: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare data for report generation (original non-deduplicated version)"""
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
                    'new_count': comparison_data.get('new_count', len(comparison_data.get('new', []))),
                    'recurring_count': comparison_data.get('recurring_count', len(comparison_data.get('recurring', []))),
                    'resolved_count': comparison_data.get('resolved_count', len(comparison_data.get('resolved', [])))
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
        """Calculate statistics from findings (original version)"""
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
        """Prepare data for charts (original version)"""
        # If deduplication is enabled, delegate to enhanced version
        if self.enable_deduplication and isinstance(findings, dict):
            return self._prepare_enhanced_charts_data(findings)
            
        charts_data = {
            'severity_chart': [],
            'type_chart': [],
            'tool_chart': []
        }
        
        if not findings: #danxzero
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
        """Get validation status display"""
        if val_result.get('valid') is True:
            return 'Verified Active'
        elif val_result.get('valid') is False:
            return 'Invalid/Inactive'
        else:
            return 'Not Verified'
    
    def _render_html(self, report_data: Dict[str, Any]) -> str:
        """Render HTML report from data (fallback method)"""
        return self._render_enhanced_html(report_data)
    
    def _get_enhanced_html_template(self) -> str:
        """Get enhanced HTML template with deduplication support"""
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
                {% if scan_id %}<br>Scan ID: {{ scan_id }}{% endif %}
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
        """Get HTML report template (original version)"""
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
                {% if scan_id %}<br>Scan ID: {{ scan_id }}{% endif %}
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
        """Get report generation statistics"""
        return self.stats