"""
Enhanced Secret Scanner Wrapper with Precise URL Mapping and Database Integration

Key improvements:
1. Database-centric architecture for findings storage
2. Precise URL mapping using resource relationship data from enhanced crawler
3. Better tool coordination and parallel execution
4. Enhanced pattern matching with context
5. Improved false positive filtering
6. Better error handling and recovery
7. Detailed finding metadata with exact parent-child URL relationships
8. FIXED: Enhanced data validation and error handling for database operations
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
from urllib.parse import urlparse, urlunparse

from loguru import logger


class URLNormalizer:
    """Utility class for URL normalization and matching."""
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for consistent comparison."""
        if not url:
            return url
        
        try:
            # Parse URL
            parsed = urlparse(url)
            
            # Normalize scheme
            scheme = parsed.scheme.lower() if parsed.scheme else 'https'
            
            # Normalize netloc
            netloc = parsed.netloc.lower()
            
            # Normalize path
            path = parsed.path.rstrip('/') if parsed.path != '/' else '/'
            
            # Reconstruct URL
            normalized = urlunparse((
                scheme,
                netloc,
                path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            return normalized
            
        except Exception:
            return url
    
    @staticmethod
    def get_url_variants(url: str) -> List[str]:
        """Get common variants of a URL for matching."""
        if not url:
            return []
        
        variants = [url]
        
        try:
            # Add normalized version
            normalized = URLNormalizer.normalize_url(url)
            if normalized != url:
                variants.append(normalized)
            
            # Add with/without trailing slash
            if url.endswith('/'):
                variants.append(url.rstrip('/'))
            else:
                variants.append(url + '/')
            
            # Add scheme variants
            if url.startswith('https://'):
                variants.append(url.replace('https://', 'http://'))
            elif url.startswith('http://'):
                variants.append(url.replace('http://', 'https://'))
            
            # Add www variants
            parsed = urlparse(url)
            if parsed.netloc:
                if parsed.netloc.startswith('www.'):
                    # Remove www
                    no_www = parsed.netloc[4:]
                    variants.append(url.replace(parsed.netloc, no_www))
                else:
                    # Add www
                    with_www = 'www.' + parsed.netloc
                    variants.append(url.replace(parsed.netloc, with_www))
            
            # Remove duplicates while preserving order
            seen = set()
            unique_variants = []
            for variant in variants:
                if variant not in seen:
                    seen.add(variant)
                    unique_variants.append(variant)
            
            return unique_variants
            
        except Exception as e:
            logger.debug(f"Error generating URL variants for {url}: {e}")
            return [url]


class DataValidator:
    """Utility class for validating data structures."""
    
    @staticmethod
    def validate_resource_relationship(rel: Dict) -> Tuple[bool, str, Dict]:
        """
        Validate resource relationship data structure.
        
        Returns:
            (is_valid, error_message, normalized_data)
        """
        if not isinstance(rel, dict):
            return False, f"Expected dict, got {type(rel)}", {}
        
        # Required fields with fallbacks
        required_fields = {
            'parentUrl': None,
            'url': None,
            'filename': None,
            'resourceType': 'unknown',
            'loadMethod': 'unknown',
            'loadTime': 0,
            'timestamp': None
        }
        
        normalized = {}
        errors = []
        
        for field, default in required_fields.items():
            if field in rel:
                value = rel[field]
                
                # Type validation and normalization
                if field in ['loadTime']:
                    try:
                        normalized[field] = int(value) if value is not None else 0
                    except (ValueError, TypeError):
                        normalized[field] = 0
                        errors.append(f"Invalid {field}: {value}")
                
                elif field in ['parentUrl', 'url']:
                    if isinstance(value, str) and value.strip():
                        normalized[field] = value.strip()
                    else:
                        errors.append(f"Invalid {field}: {value}")
                        normalized[field] = None
                
                elif field == 'filename':
                    if isinstance(value, str) and value.strip():
                        normalized[field] = value.strip()
                    else:
                        # Try to extract filename from URL
                        url = rel.get('url', '')
                        if url:
                            try:
                                filename = Path(urlparse(url).path).name
                                normalized[field] = filename if filename else 'unknown'
                            except:
                                normalized[field] = 'unknown'
                        else:
                            normalized[field] = 'unknown'
                
                else:
                    normalized[field] = value if value is not None else default
            else:
                if default is not None:
                    normalized[field] = default
                else:
                    errors.append(f"Missing required field: {field}")
        
        # Additional validation
        if not normalized.get('parentUrl'):
            errors.append("parentUrl is required")
        
        if not normalized.get('url'):
            errors.append("url is required")
        
        # Set timestamp if missing
        if not normalized.get('timestamp'):
            normalized['timestamp'] = datetime.now().isoformat()
        
        is_valid = len(errors) == 0
        error_message = "; ".join(errors) if errors else ""
        
        return is_valid, error_message, normalized
    
    @staticmethod
    def validate_finding_data(finding: Dict) -> Tuple[bool, str, Dict]:
        """
        Validate finding data structure.
        
        Returns:
            (is_valid, error_message, normalized_data)
        """
        if not isinstance(finding, dict):
            return False, f"Expected dict, got {type(finding)}", {}
        
        # Required fields with fallbacks
        required_fields = {
            'raw': '',
            'type': 'unknown',
            'detector': 'unknown',
            'file': '',
            'line': 0,
            'confidence': 'medium',
            'severity': 'medium',
            'verified': False
        }
        
        normalized = {}
        errors = []
        
        for field, default in required_fields.items():
            value = finding.get(field, default)
            
            # Type validation and normalization
            if field == 'line':
                try:
                    normalized[field] = int(value) if value is not None else 0
                except (ValueError, TypeError):
                    normalized[field] = 0
            
            elif field == 'verified':
                normalized[field] = bool(value) if value is not None else False
            
            elif field in ['confidence', 'severity']:
                if isinstance(value, str) and value.lower() in ['low', 'medium', 'high', 'critical']:
                    normalized[field] = value.lower()
                else:
                    normalized[field] = default
            
            else:
                normalized[field] = str(value) if value is not None else default
        
        # Validate file path
        if not normalized.get('file'):
            errors.append("file path is required")
        
        # Validate raw secret
        if not normalized.get('raw'):
            errors.append("raw secret value is required")
        
        is_valid = len(errors) == 0
        error_message = "; ".join(errors) if errors else ""
        
        return is_valid, error_message, normalized


class PreciseURLMapper:
    """Enhanced URL mapper using resource relationship data from crawler."""
    
    def __init__(self, db_manager, scan_id: str, logger=None):
        self.db = db_manager
        self.scan_id = scan_id
        self.logger = logger
        self.resource_cache = {}
        self.resource_relationships = []
        
        # Load resource relationships from enhanced crawler
        self._load_resource_relationships()
    
    def _load_resource_relationships(self):
        """Load resource relationships from file_to_url_mappings.json (FIXED)."""
        self.logger.debug(f"🔍 _load_resource_relationships called")
        self.logger.debug(f"🔍 scan_id: {self.scan_id}")
        
        try:
            # FIXED: Load from the correct file - file_to_url_mappings.json
            data_path = Path(f"./data/content/{self.scan_id}")
            mapping_file = data_path / "url_mappings.json"  # ← USE COMPREHENSIVE MAPPING
            
            self.logger.debug(f"🔍 Looking for file: {mapping_file}")
            self.logger.debug(f"🔍 File exists: {mapping_file.exists()}")
            
            if mapping_file.exists():
                # Check file size
                file_size = mapping_file.stat().st_size
                self.logger.debug(f"🔍 File size: {file_size} bytes")
                
                with open(mapping_file, 'r') as f:
                    data = json.load(f)
                    
                self.logger.debug(f"🔍 JSON loaded successfully, type: {type(data)}")
                self.logger.debug(f"🔍 Raw data loaded: {len(data)}")
                
                # Convert file mappings to resource relationships format
                # Process the comprehensive fileToUrl mappings
                file_to_url_data = data.get("fileToUrl", {})
                self.logger.debug(f"🔍 Loaded {len(file_to_url_data)} comprehensive mappings")
                
                for file_path, mapping_info in file_to_url_data.items():
                    # Extract URL from the comprehensive mapping structure
                    url = mapping_info.get("url")
                    parent_url = mapping_info.get("parentUrl")
                    # Extract filename from path
                    filename = os.path.basename(file_path)
                    
                    # Determine resource type and load method
                    resource_type = 'script' if file_path.endswith('.js') else 'document'
                    load_method = 'inline' if 'inline-scripts' in file_path else 'static'
                    
                    # Create resource relationship object
                    resource_rel = {
                        'filename': filename,
                        'full_path': file_path,
                        'url': url,
                        'parentUrl': url.split('#')[0] if '#' in url else url,
                        'resourceType': resource_type,
                        'loadMethod': load_method,
                        'loadTime': 0,
                        'timestamp': None,
                        'source': 'file_mapping'
                    }
                    
                    self.resource_relationships.append(resource_rel)
                    
                    # Add to cache with multiple lookup keys for flexibility
                    self.resource_cache[filename] = resource_rel
                    self.resource_cache[file_path] = resource_rel
                    
                    # Also cache with variations for better matching
                    if '/' in file_path:
                        # Cache by basename for easier lookup
                        self.resource_cache[os.path.basename(file_path)] = resource_rel
                    
                    # For inline scripts, cache additional patterns
                    if 'inline-scripts' in file_path and filename.endswith('.js'):
                        # Cache the HTML parent reference
                        html_name = filename.replace('.js', '').split('_inline_')[0] + '.html'
                        if html_name not in self.resource_cache:
                            # Create a reference to the parent page
                            parent_rel = resource_rel.copy()
                            parent_rel['filename'] = html_name
                            parent_rel['url'] = url.split('#')[0]  # Remove fragment
                            self.resource_cache[html_name] = parent_rel
                    
                self.logger.info(f"✅ Loaded {len(file_to_url_data)} precise file-to-URL mappings")
                
            else:
                self.logger.warning(f"❌ File mapping file not found: {mapping_file}")
                
            # Also try to load from resource_relationships.json if it exists (keep existing logic)
            resource_file = data_path / "resource_relationships.json"
            if resource_file.exists():
                self.logger.debug(f"🔍 Also loading from: {resource_file}")
                with open(resource_file, 'r') as f:
                    resource_data = json.load(f)
                
                # Process resource_relationships.json if it exists
                if isinstance(resource_data, list):
                    for item in resource_data:
                        is_valid, error_msg, normalized = self._validate_and_normalize_resource_relationship(item)
                        if is_valid and normalized:
                            self.resource_relationships.append(normalized)
                            if normalized.get('filename'):
                                self.resource_cache[normalized['filename']] = normalized
                                
                self.logger.info(f"✅ Also loaded {len(resource_data) if isinstance(resource_data, list) else 0} resource relationships")
                
        except Exception as e:
            self.logger.error(f"❌ Exception in _load_resource_relationships: {e}")
            self.logger.debug(f"❌ Exception type: {type(e).__name__}")
            import traceback
            self.logger.debug(f"❌ Traceback: {traceback.format_exc()}")
            self.resource_relationships = []
            self.resource_cache = {}

    def _validate_and_normalize_resource_relationship(self, rel: Dict) -> Tuple[bool, str, Dict]:
        """Validate and normalize resource relationship data."""
        return DataValidator.validate_resource_relationship(rel)
    
    def _store_resource_relationships(self):
        """Store resource relationships in page_resources table with enhanced error handling."""
        if not self.db or not self.resource_relationships:
            self.logger.debug(f"❌ Skipping store: db={bool(self.db)}, relationships={len(getattr(self, 'resource_relationships', []))}")
            return
        
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            stored_count = 0
            skipped_count = 0
            error_count = 0
            
            self.logger.debug(f"🔍 Starting to store {len(self.resource_relationships)} relationships")
            
            for i, rel in enumerate(self.resource_relationships):
                try:
                    # Validate relationship data
                    is_valid, error_msg, normalized = DataValidator.validate_resource_relationship(rel)
                    if not is_valid:
                        self.logger.debug(f"Skipping invalid relationship {i}: {error_msg}")
                        skipped_count += 1
                        continue
                    
                    # Get parent URL ID with enhanced matching
                    parent_url_id = self._find_parent_url_id(cursor, normalized['parentUrl'])
                    
                    if not parent_url_id:
                        self.logger.debug(f"Parent URL not found, creating: {normalized['parentUrl']}")
                        # 🔧 FIX: Create parent URL entry if it doesn't exist
                        try:
                            cursor.execute("""
                                INSERT OR IGNORE INTO urls (url, scan_id, domain, file_name, file_path, crawled_at)
                                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                            """, (
                                normalized['parentUrl'],
                                self.scan_id,
                                self._extract_domain(normalized['parentUrl']),
                                '',  # No file name for parent URL
                                normalized['parentUrl']
                            ))
                            
                            # Try to get the ID again
                            parent_url_id = self._find_parent_url_id(cursor, normalized['parentUrl'])
                            if parent_url_id:
                                self.logger.debug(f"✅ Created parent URL entry: {normalized['parentUrl']}")
                            else:
                                self.logger.warning(f"❌ Failed to create parent URL: {normalized['parentUrl']}")
                                skipped_count += 1
                                continue
                        except Exception as e:
                            self.logger.debug(f"Failed to create parent URL entry: {e}")
                            skipped_count += 1
                            continue
                    
                    # Insert or update resource relationship
                    cursor.execute("""
                        INSERT OR REPLACE INTO page_resources (
                            parent_url_id, resource_url, resource_filename, 
                            resource_type, load_method, load_timing_ms,
                            referrer_url, first_seen, scan_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        parent_url_id,
                        normalized['url'],
                        normalized['filename'],
                        normalized['resourceType'],
                        normalized['loadMethod'],
                        normalized['loadTime'],
                        normalized.get('referrer', normalized['parentUrl']),
                        normalized['timestamp'],
                        self.scan_id
                    ))
                    
                    stored_count += 1
                    
                    if i < 3:  # Log first 3 for debugging
                        self.logger.debug(f"✅ Stored relationship {i}: {normalized['filename']} -> {normalized['url']}")
                    
                except sqlite3.IntegrityError as e:
                    # UNIQUE constraint violations are expected for baseline tracking
                    if "UNIQUE constraint failed" in str(e):
                        self.logger.debug(f"Secret already exists in database (baseline tracking): {e}")
                        continue
                    else:
                        self.logger.error(f"Database integrity error storing finding: {e}")
                        conn.rollback()
                        continue
                except sqlite3.Error as e:
                    self.logger.error(f"Database error storing resource relationship {i}: {e}")
                    error_count += 1
                    continue
                except Exception as e:
                    self.logger.debug(f"Failed to store resource relationship {i}: {e}")
                    error_count += 1
                    continue
            
            conn.commit()
            self.logger.info(f"✅ Resource relationships stored: {stored_count} success, {skipped_count} skipped, {error_count} errors")
            
            # 🔧 VERIFICATION: Check what was actually stored
            cursor.execute("""
                SELECT COUNT(*), MIN(resource_filename), MAX(resource_filename)
                FROM page_resources 
                WHERE scan_id = ?
            """, (self.scan_id,))
            
            result = cursor.fetchone()
            if result and result[0] > 0:
                self.logger.info(f"🔍 Database verification: {result[0]} resources stored. Sample: {result[1]} to {result[2]}")
            else:
                self.logger.error(f"❌ Database verification failed: No resources found for scan_id {self.scan_id}")
                
        except Exception as e:
            self.logger.error(f"Failed to store resource relationships: {e}")
            import traceback
            self.logger.debug(f"Full traceback: {traceback.format_exc()}")

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or 'unknown'
        except:
            return 'unknown'
    
    def _find_parent_url_id(self, cursor, parent_url: str) -> Optional[int]:
        """Find parent URL ID with enhanced matching and better debugging."""
        if not parent_url:
            return None
        
        # Method 1: Exact match
        cursor.execute("""
            SELECT id FROM urls WHERE url = ? AND scan_id = ?
        """, (parent_url, self.scan_id))
        
        result = cursor.fetchone()
        if result:
            return result[0]
        
        # Method 2: Try URL variants
        url_variants = URLNormalizer.get_url_variants(parent_url)
        
        for variant in url_variants:
            cursor.execute("""
                SELECT id FROM urls WHERE url = ? AND scan_id = ?
            """, (variant, self.scan_id))
            
            result = cursor.fetchone()
            if result:
                self.logger.debug(f"Found parent URL via variant: {parent_url} -> {variant}")
                return result[0]
        
        # Method 3: Debug what URLs we actually have
        cursor.execute("""
            SELECT COUNT(*), MIN(url) as sample_url 
            FROM urls 
            WHERE scan_id = ?
        """, (self.scan_id,))
        
        debug_result = cursor.fetchone()
        if debug_result and debug_result[0] > 0:
            self.logger.debug(f"⚠️ Parent URL '{parent_url}' not found. Scan has {debug_result[0]} URLs. Sample: {debug_result[1]}")
        else:
            self.logger.error(f"❌ Scan {self.scan_id} has NO URLs in database!")
        
        return None
    
    def get_precise_url_for_file(self, filename: str) -> Optional[Dict]:
        """Get precise URL mapping for a file with comprehensive matching - FULLY FIXED."""
        if not filename:
            return None
            
        self.logger.debug(f"🔍 Looking up precise mapping for: '{filename}'")
        
        # Ensure stats tracking exists
        if not hasattr(self, 'stats'):
            self.stats = {'precise_mappings_used': 0, 'fallback_mappings_used': 0}
        if 'precise_mappings_used' not in self.stats:
            self.stats['precise_mappings_used'] = 0
        if 'fallback_mappings_used' not in self.stats:
            self.stats['fallback_mappings_used'] = 0
        
        # Method 1: Direct cache lookup (exact match)
        if filename in self.resource_cache:
            self.stats['precise_mappings_used'] += 1
            rel = self.resource_cache[filename]
            self.logger.debug(f"✅ Direct cache hit for: {filename}")
            return self._format_precise_mapping(rel)
        
        # Method 2: Try filename variations for better matching
        variations = [
            filename,
            os.path.basename(filename),
            f"inline-scripts/{filename}",
            f"html/{filename}",
            f"js/{filename}",
            f"json/{filename}",
            f"other/{filename}",
        ]
        
        # For files with directory prefixes, try without prefix
        if '/' in filename:
            base_name = os.path.basename(filename)
            variations.append(base_name)
            
        # For inline scripts, try different patterns
        if '_inline_' in filename and filename.endswith('.js'):
            # Try the base HTML file mapping
            html_name = filename.replace('.js', '').split('_inline_')[0] + '.html'
            variations.extend([
                html_name,
                f"html/{html_name}",
                f"inline-scripts/{html_name}",
            ])
            
            # Also try the parent page URL pattern
            parent_pattern = filename.split('_inline_')[0] + '.html'
            variations.append(f"html/{parent_pattern}")
        
        # Try each variation
        for variation in variations:
            if variation in self.resource_cache:
                self.stats['precise_mappings_used'] += 1
                rel = self.resource_cache[variation]
                self.logger.debug(f"✅ Cache hit with variation '{variation}' for: {filename}")
                return self._format_precise_mapping(rel)
        
        # Method 3: Fuzzy matching through all relationships
        for rel in self.resource_relationships:
            rel_filename = rel.get('filename', '')
            rel_path = rel.get('full_path', '')
            
            # Check various matching patterns
            matches = [
                rel_filename == filename,
                rel_path == filename,
                rel_path.endswith(filename),
                filename.endswith(rel_filename) if rel_filename else False,
                rel_filename in filename if rel_filename else False,
                filename in rel_filename if rel_filename else False,
                rel_path.endswith(f"/{filename}") if rel_path else False,
            ]
            
            if any(matches):
                self.stats['precise_mappings_used'] += 1
                self.logger.debug(f"✅ Fuzzy match found for: {filename} -> {rel_filename}")
                return self._format_precise_mapping(rel)
        
        # Method 4: Database lookup (if available)
        if self.db:
            try:
                conn = self.db.get_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT u.url as parent_url, pr.resource_url, pr.load_method,
                           pr.load_timing_ms, pr.referrer_url, pr.first_seen
                    FROM page_resources pr
                    JOIN urls u ON pr.parent_url_id = u.id
                    WHERE pr.resource_filename = ? AND pr.scan_id = ?
                    ORDER BY pr.first_seen DESC LIMIT 1
                """, (filename, self.scan_id))
                
                result = cursor.fetchone()
                if result:
                    self.stats['precise_mappings_used'] += 1
                    self.logger.debug(f"✅ Database hit for: {filename}")
                    return {
                        'url': result[1] or result[0],  # Prefer resource_url
                        'resource_url': result[1],
                        'parent_url': result[0],
                        'load_method': result[2],
                        'load_timing_ms': result[3],
                        'referrer_url': result[4],
                        'first_seen': result[5],
                        'precision': 'exact',
                        'source': 'database'
                    }
                    
            except Exception as e:
                self.logger.debug(f"❌ Database lookup failed for {filename}: {e}")
        
        # Method 5: Final fallback - increment fallback counter
        self.stats['fallback_mappings_used'] += 1
        self.logger.debug(f"❌ No precise mapping found for: '{filename}' (checked {len(self.resource_relationships)} relationships)")
        
        return None

    def _format_precise_mapping(self, rel: Dict) -> Dict:
        """Format a resource relationship into the expected precise mapping format - FIXED."""
        return {
            'url': rel.get('url'),
            'resource_url': rel.get('url'),
            'parent_url': rel.get('parentUrl'),
            'load_method': rel.get('loadMethod'),
            'load_timing_ms': rel.get('loadTime', 0),
            'referrer_url': rel.get('parentUrl'),
            'first_seen': rel.get('timestamp'),
            'precision': 'exact',
            'source': rel.get('source', 'memory')
        }

    def get_mapping_statistics(self) -> Dict:
        """Get comprehensive mapping statistics."""
        if not hasattr(self, 'stats'):
            return {}
            
        total_lookups = self.stats.get('precise_mappings_used', 0) + self.stats.get('fallback_mappings_used', 0)
        precision_rate = (self.stats.get('precise_mappings_used', 0) / max(total_lookups, 1)) * 100
        
        return {
            'total_lookups': total_lookups,
            'precise_mappings': self.stats.get('precise_mappings_used', 0),
            'fallback_mappings': self.stats.get('fallback_mappings_used', 0),
            'precision_rate': f"{precision_rate:.1f}%",
            'relationships_loaded': len(getattr(self, 'resource_relationships', [])),
            'cache_entries': len(getattr(self, 'resource_cache', {}))
        }

    def store_js_chunk_metadata(self, filename: str, parent_url: str, metadata: Dict):
        """Store JavaScript chunk metadata in database."""
        if not self.db:
            return
        
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Get parent URL ID
            parent_url_id = self._find_parent_url_id(cursor, parent_url)
            if not parent_url_id:
                self.logger.debug(f"Parent URL not found for JS metadata: {parent_url}")
                return
            
            # Validate metadata
            safe_metadata = {
                'hash': str(metadata.get('hash', '')),
                'webpack_chunk_id': str(metadata.get('webpack_chunk_id', '')),
                'source_map_url': str(metadata.get('source_map_url', '')),
                'entry_point': bool(metadata.get('entry_point', False)),
                'size': int(metadata.get('size', 0)) if isinstance(metadata.get('size'), (int, float)) else 0,
                'load_order': int(metadata.get('load_order', 0)) if isinstance(metadata.get('load_order'), (int, float)) else 0,
                'dependencies': metadata.get('dependencies', []),
                'load_context': metadata.get('load_context', {})
            }
            
            # Insert chunk metadata
            cursor.execute("""
                INSERT OR REPLACE INTO js_chunk_metadata (
                    chunk_filename, parent_page_url_id, chunk_hash,
                    webpack_chunk_id, source_map_url, entry_point,
                    chunk_size_bytes, load_order, dependencies, scan_id, load_context
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                filename,
                parent_url_id,
                safe_metadata['hash'],
                safe_metadata['webpack_chunk_id'],
                safe_metadata['source_map_url'],
                safe_metadata['entry_point'],
                safe_metadata['size'],
                safe_metadata['load_order'],
                json.dumps(safe_metadata['dependencies']),
                self.scan_id,
                json.dumps(safe_metadata["load_context"])
            ))
            
            conn.commit()
            self.logger.debug(f"Stored JS chunk metadata for {filename}")
            
        except Exception as e:
            self.logger.error(f"Failed to store JS chunk metadata: {e}")


class SecretScanner:
    """Enhanced secret scanner orchestrating multiple tools with precise URL mapping."""
    
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
        
        # Precise URL mapper (initialized during scan)
        self.precise_url_mapper = None
        
        # Statistics (will be stored in database)
        self.stats = {
            'files_scanned': 0,
            'files_skipped': 0,
            'secrets_found': 0,
            'false_positives_filtered': 0,
            'scan_duration': 0,
            'tool_results': defaultdict(int),
            'secret_types': defaultdict(int),
            'errors': [],
            'precise_mappings_used': 0,
            'fallback_mappings_used': 0
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
        """Get URL for a file using precise mapping when available, with enhanced fallback."""
        if not self.db:
            return None

        try:
            filename = Path(file_path).name
            
            # Skip metadata files
            if filename.endswith('_meta.json'):
                return None
            
            # Method 1: Use precise URL mapper if available (HIGHEST PRIORITY)
            if self.precise_url_mapper:
                precise_mapping = self.precise_url_mapper.get_precise_url_for_file(filename)
                if precise_mapping and precise_mapping.get('url'):
                    self.stats['precise_mappings_used'] += 1
                    self.logger.info(f"✓ PRECISE mapping: {filename} -> {precise_mapping['url']} "
                                    f"(loaded via {precise_mapping['load_method']} in {precise_mapping['load_timing_ms']}ms)")
                    return precise_mapping['url']
            
            # Method 2: Fallback to existing aggressive mapping logic
            self.stats['fallback_mappings_used'] += 1
            scan_id = self.current_scan_run_id or Path(base_directory).name
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Direct filename match
            cursor.execute("""
                SELECT url FROM urls 
                WHERE scan_id = ? AND file_name = ?
                LIMIT 1
            """, (scan_id, filename))
            
            result = cursor.fetchone()
            if result:
                self.logger.debug(f"✓ Direct filename match: {filename} -> {result[0]}")
                return result[0]
            
            # File path contains filename
            cursor.execute("""
                SELECT url FROM urls 
                WHERE scan_id = ? AND file_path LIKE ?
                LIMIT 1
            """, (scan_id, f'%/{filename}'))
            
            result = cursor.fetchone()
            if result:
                self.logger.debug(f"✓ File path match: {filename} -> {result[0]}")
                return result[0]
            
            # AGGRESSIVE MAPPING FOR JS CHUNKS
            if '.js' in filename or filename.endswith('.js'):
                self.logger.debug(f"🔍 Attempting JS chunk mapping for: {filename}")
                
                # Strategy A: Find checkout-related URLs for checkout-related files
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
                        self.logger.info(f"✓ JS chunk mapped to checkout domain: {filename} -> {result[0]}")
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
                    self.logger.info(f"✓ JS chunk mapped to main domain: {filename} -> {result[0]}")
                    return result[0]
                
                # Strategy C: Map to any HTML page as fallback
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
                    self.logger.warning(f"⚠️ JS chunk mapped to fallback HTML: {filename} -> {result[0]}")
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
                    self.logger.error(f"🚨 JS chunk mapped to LAST RESORT URL: {filename} -> {result[0]}")
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
                        self.logger.debug(f"✓ Pattern match for non-JS: {filename} -> {result[0]}")
                        return result[0]
            
            # If we still haven't found a URL, log detailed info for debugging
            self.logger.warning(f"❌ NO URL MAPPING FOUND for file: {filename}")
            
            # Debug: Show what URLs we DO have in this scan
            cursor.execute("""
                SELECT COUNT(*), MIN(url) as sample_url, MAX(url) as max_url 
                FROM urls 
                WHERE scan_id = ? AND url IS NOT NULL
            """, (scan_id,))
            debug_result = cursor.fetchone()
            if debug_result and debug_result[0] > 0:
                self.logger.warning(f"Debug: Scan {scan_id} has {debug_result[0]} URLs. Sample: {debug_result[1]}")
            else:
                self.logger.error(f"Debug: Scan {scan_id} has NO URLs in database!")
            
            return None
                    
        except Exception as e:
            self.logger.error(f"Failed to get URL for file {file_path}: {e}")
            return None
    
    def scan_directory(self, directory: str, scan_type: str = 'full', scan_run_id: str = None) -> int:
        """
        Scan a directory for secrets using all enabled tools with precise URL mapping.
        
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
        
        # Initialize precise URL mapper if database available
        if self.db and scan_run_id:
            self.precise_url_mapper = PreciseURLMapper(self.db, scan_run_id, self.logger)            
            self.precise_url_mapper._load_resource_relationships()
            self.logger.info("✓ Precise URL mapper initialized")
            self.logger.info(f"Loaded {len(self.precise_url_mapper.resource_relationships)} valid resource relationships from crawler")
        else:
            self.logger.warning("Database not available - precise URL mapping disabled")
        
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
        
        # Store findings in database with precise URL mapping
        stored_count = self._store_findings_in_database(filtered_findings, directory)
        
        self.stats['secrets_found'] = stored_count
        self.stats['scan_duration'] = time.time() - start_time
        self.stats['false_positives_filtered'] = len(unique_findings) - len(filtered_findings)
        
        # Update scan statistics in database
        self._update_scan_statistics()
        
        # Log comprehensive mapping statistics
        if self.precise_url_mapper:
            mapping_stats = self.precise_url_mapper.get_mapping_statistics()
            self.logger.info("✅ Precision Mapping Results:")
            self.logger.info(f"   Total lookups: {mapping_stats.get('total_lookups', 0)}")
            self.logger.info(f"   Precise mappings: {mapping_stats.get('precise_mappings', 0)} ({mapping_stats.get('precision_rate', '0%')})")
            self.logger.info(f"   Fallback mappings: {mapping_stats.get('fallback_mappings', 0)}")
            self.logger.info(f"   Relationships loaded: {mapping_stats.get('relationships_loaded', 0)}")
            self.logger.info(f"   Cache entries: {mapping_stats.get('cache_entries', 0)}")
            
            # Update scanner stats
            self.stats['precise_mappings_used'] = mapping_stats.get('precise_mappings', 0)
            self.stats['fallback_mappings_used'] = mapping_stats.get('fallback_mappings', 0)
        
        self.logger.info(
            f"Scan completed in {self.stats['scan_duration']:.2f}s. "
            f"Found {stored_count} secrets "
            f"({self.stats['false_positives_filtered']} false positives filtered)"
        )
        
        return stored_count
    
    def _store_findings_in_database(self, findings: List[Dict], base_directory: str) -> int:
        """Store findings in database with precise URL mapping and enhanced error handling."""
        if not self.db or not findings:
            return 0
        
        stored_count = 0
        
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            for finding in findings:
                try:
                    # Validate finding data first
                    is_valid, error_msg, normalized_finding = DataValidator.validate_finding_data(finding)
                    if not is_valid:
                        self.logger.debug(f"Skipping invalid finding: {error_msg}")
                        continue
                    
                    # Enhanced URL mapping with context
                    url_context = None
                    url = None
                    
                    if self.precise_url_mapper:
                        # Use _get_url_for_file to ensure counter increments
                        url = self._get_url_for_file(normalized_finding['file'], base_directory)
                        
                        if url:
                            # Get full mapping details for database storage
                            filename = Path(normalized_finding['file']).name
                            precise_mapping = self.precise_url_mapper.get_precise_url_for_file(filename)
                            
                            # ✅ FIX: Check if precise_mapping is not None before accessing its keys
                            if precise_mapping:
                                url_context = {
                                    'load_method': precise_mapping['load_method'],
                                    'load_timing_ms': precise_mapping['load_timing_ms'],
                                    'referrer_url': precise_mapping.get('referrer_url'),
                                    'resource_url': precise_mapping.get('resource_url'),
                                    'precision_level': 'exact',
                                    'mapping_source': precise_mapping.get('source', 'unknown')
                                }
                                self.logger.debug(f"Using precise mapping for finding in {filename}")
                            else:
                                self.logger.debug(f"Precise mapping returned None for {filename}, using fallback")
                                url_context = {'precision_level': 'fallback'}
                        else:
                            # url = self._get_url_for_file(normalized_finding['file'], base_directory)
                            url_context = {'precision_level': 'fallback'}
                    else:
                        url = self._get_url_for_file(normalized_finding['file'], base_directory)
                        url_context = {'precision_level': 'legacy'}
                    
                    # Log URL mapping for debugging
                    if not url:
                        self.logger.debug(f"No URL found for file: {normalized_finding['file']}")
                    
                    # Calculate secret hash
                    secret_value = normalized_finding.get('raw', '')
                    if not secret_value:
                        self.logger.debug(f"Skipping finding with empty secret value")
                        continue
                        
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
                            normalized_finding.get('type', 'unknown'),
                            normalized_finding.get('detector', 'unknown'),
                            normalized_finding.get('verified', False),
                            True,  # is_active
                            normalized_finding.get('severity', 'medium'),
                            normalized_finding.get('confidence', 'medium')
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
                    
                    # 🚀 GUARANTEED URL ASSIGNMENT - Ensure url_id is never NULL
                    if url_id is None:
                        self.logger.warning(f"URL mapping failed for {normalized_finding.get('file', '')}, using guaranteed fallback")
                        
                        # Get ANY URL from this scan to ensure url_id is never NULL
                        cursor.execute("""
                            SELECT id, url FROM urls 
                            WHERE scan_id = ? 
                            ORDER BY id 
                            LIMIT 1
                        """, (self.current_scan_run_id,))
                        fallback_url_row = cursor.fetchone()
                        
                        if fallback_url_row:
                            url_id = fallback_url_row[0]
                            fallback_url = fallback_url_row[1]
                            self.logger.info(f"✅ GUARANTEED fallback assigned: {fallback_url}")
                        else:
                            self.logger.error(f"❌ CRITICAL: No URLs found for scan_id: {self.current_scan_run_id}")
                            # Emergency fallback - use ID 1
                            url_id = 1
                    
                    # Check if this specific finding already exists
                    cursor.execute("""
                        SELECT id FROM findings 
                        WHERE secret_id = ? 
                        AND (url_id = ? OR (url_id IS NULL AND ? IS NULL))
                        AND line_number = ?
                        AND scan_run_id = ?
                        
                    """, (secret_id, url_id, url_id, normalized_finding.get('line', 0), self.current_scan_run_id))
                    
                    if not cursor.fetchone():
                        # Insert finding with enhanced validation result including URL context
                        enhanced_validation_result = {
                            'confidence': normalized_finding.get('confidence', 'medium'),
                            'metadata': normalized_finding.get('metadata', {}),
                            'url_context': url_context,
                            'precise_mapping_available': url_context and url_context.get('precision_level') == 'exact'
                        }
                        
                        cursor.execute("""
                            INSERT INTO findings (
                                secret_id, url_id, line_number, snippet,
                                found_at, scan_run_id, file_path,
                                validation_status, validation_result
                            ) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?)
                        """, (
                            secret_id,
                            url_id,
                            normalized_finding.get('line', 0),
                            normalized_finding.get('context', '')[:500],  # Limit snippet length
                            self.current_scan_run_id,
                            normalized_finding.get('file', ''),
                            'pending',
                            json.dumps(enhanced_validation_result)
                        ))
                        
                        stored_count += 1
                        
                        # Store additional JS chunk metadata if available
                        if url and url_context and url_context.get('precision_level') == 'exact':
                            if self.precise_url_mapper and normalized_finding['file'].endswith('.js'):
                                filename = Path(normalized_finding['file']).name
                                chunk_metadata = {
                                    'size': Path(normalized_finding['file']).stat().st_size if Path(normalized_finding['file']).exists() else 0,
                                    'has_secrets': True,
                                    'secret_types': [normalized_finding.get('type', 'unknown')],
                                    'load_context': url_context
                                }
                                self.precise_url_mapper.store_js_chunk_metadata(filename, url, chunk_metadata)
                    
                    # Update statistics
                    self.stats['secret_types'][normalized_finding.get('type', 'unknown')] += 1
                    
                except sqlite3.IntegrityError as e:
                    # UNIQUE constraint violations are expected for baseline tracking
                    if "UNIQUE constraint failed" in str(e):
                        self.logger.debug(f"Secret already exists in database (baseline tracking): {e}")
                        continue
                    else:
                        self.logger.error(f"Database integrity error storing finding: {e}")
                        conn.rollback()
                        continue
                except sqlite3.Error as e:
                    self.logger.error(f"Database error storing finding: {e}")
                    conn.rollback()
                    continue
                except Exception as e:
                    self.logger.error(f"Failed to store finding: {e}")
                    continue
            
            conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to store findings in database: {e}")
        
        return stored_count
    
    def _update_scan_statistics(self):
        """Update scan run statistics in database with precise mapping stats."""
        if not self.db or not self.current_scan_run_id:
            return
        
        try:
            conn = self.db.get_connection()
            cursor = conn.cursor()
            
            # Add precise mapping statistics to tool results
            enhanced_tool_results = dict(self.stats['tool_results'])
            enhanced_tool_results['precise_mappings_used'] = self.stats['precise_mappings_used']
            enhanced_tool_results['fallback_mappings_used'] = self.stats['fallback_mappings_used']
            
            # Convert to JSON
            tool_results_json = json.dumps(enhanced_tool_results)
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
        """Get scanning statistics with precise mapping info."""
        base_stats = {
            **self.stats,
            'scan_rate': f"{self.stats['files_scanned'] / max(self.stats['scan_duration'], 1):.2f} files/sec"
        }
        
        # Add mapping efficiency stats
        total_mappings = self.stats['precise_mappings_used'] + self.stats['fallback_mappings_used']
        if total_mappings > 0:
            base_stats['precise_mapping_rate'] = f"{(self.stats['precise_mappings_used'] / total_mappings) * 100:.1f}%"
        else:
            base_stats['precise_mapping_rate'] = "0.0%"
        
        return base_stats