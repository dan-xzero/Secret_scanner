#!/usr/bin/env python3
"""
Enhanced Content Fetcher Module with Database Integration - FIXED VERSION

Key fixes:
1. Fixed database path to use secrets_scanner.db
2. Proper URL to filename mapping initialization
3. Fixed database schema updates
4. Better error handling for missing mappings
5. Consistent scan_id handling
"""

import os
import subprocess
import json
import time
import sqlite3
import tempfile
import shutil
import hashlib
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set, Any
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from collections import defaultdict
import threading
from datetime import datetime

import requests
from loguru import logger


class ContentFetcher:
    """Fetches HTML and JavaScript content from URLs with database integration."""
    
    def __init__(self, config: Dict, db_path: Optional[str] = None, logger: Optional[logging.Logger] = None):
        """
        Initialize Content Fetcher with database support.
        
        Args:
            config: Configuration dictionary
            db_path: Path to database file
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Database path - FIXED to use the correct database name
        if db_path:
            self.db_path = Path(db_path)
        else:
            self.db_path = Path(config.get('data_storage_path', './data')) / 'secrets_scanner.db'
        
        # Paths
        self.crawler_script = Path(__file__).parent / 'crawler.js'
        self.static_fetcher = None
        
        # URL to filename mapping - Initialize as empty dict
        self.url_filename_map = {}
        
        # Current scan run ID
        self.scan_run_id = None
        
        # Configuration
        self.max_requests = config.get('crawler_max_requests_per_crawl', 1000)
        self.concurrency = config.get('concurrent_requests', 5)
        self.timeout = config.get('crawler_timeout', 60000)
        self.headless = config.get('crawler_headless', True)
        self.use_static_fallback = config.get('use_static_fallback', True)
        self.batch_size = config.get('crawler_batch_size', 50)
        self.retry_failed_with_static = config.get('retry_failed_with_static', True)
        
        # Validate crawler script exists
        if not self.crawler_script.exists():
            self.logger.warning(f"Crawler script not found: {self.crawler_script}")
            # Don't raise error, allow static fetcher to work
        
        # Initialize static fetcher if needed
        if self.use_static_fallback:
            try:
                from .static_fetcher import StaticFetcher
                self.static_fetcher = StaticFetcher(config, logger)
            except ImportError:
                self.logger.warning("Static fetcher not available")
        
        # Statistics
        self.stats = {
            'total_urls': 0,
            'crawler_attempted': 0,
            'crawler_success': 0,
            'crawler_failed': 0,
            'static_attempted': 0,
            'static_success': 0,
            'static_failed': 0,
            'total_success': 0,
            'total_failed': 0,
            'errors': [],
            'failed_urls': [],
            'success_urls': []
        }
        
        # Progress tracking
        self._progress_lock = threading.Lock()
        self._progress = {
            'current': 0,
            'total': 0,
            'status': 'initializing'
        }
        
        # Initialize database tables if needed
        self._init_database_tables()
    
    def _init_database_tables(self):
        """Initialize content fetcher specific tables/columns in database"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Check if tables exist first
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls'")
                if not cursor.fetchone():
                    self.logger.warning("URLs table does not exist yet, skipping column additions")
                    return
                
                # Get existing columns
                cursor = conn.execute("PRAGMA table_info(urls)")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Add missing columns one by one with error handling
                columns_to_add = [
                    ('fetch_status', "ALTER TABLE urls ADD COLUMN fetch_status TEXT DEFAULT 'pending'"),
                    ('fetch_attempted_at', "ALTER TABLE urls ADD COLUMN fetch_attempted_at TIMESTAMP"),
                    ('fetch_completed_at', "ALTER TABLE urls ADD COLUMN fetch_completed_at TIMESTAMP"),
                    ('fetch_error', "ALTER TABLE urls ADD COLUMN fetch_error TEXT"),
                    ('fetcher_type', "ALTER TABLE urls ADD COLUMN fetcher_type TEXT"),
                    ('file_name', "ALTER TABLE urls ADD COLUMN file_name TEXT")
                ]
                
                for col_name, sql in columns_to_add:
                    if col_name not in columns:
                        try:
                            conn.execute(sql)
                            self.logger.debug(f"Added column {col_name} to urls table")
                        except sqlite3.OperationalError as e:
                            if "duplicate column" not in str(e):
                                self.logger.error(f"Failed to add column {col_name}: {e}")
                
                # Add columns to scan_runs table if needed
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_runs'")
                if cursor.fetchone():
                    cursor = conn.execute("PRAGMA table_info(scan_runs)")
                    scan_runs_columns = [col[1] for col in cursor.fetchall()]
                    
                    scan_runs_columns_to_add = [
                        ('last_updated', "ALTER TABLE scan_runs ADD COLUMN last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
                        ('total_urls_fetched', "ALTER TABLE scan_runs ADD COLUMN total_urls_fetched INTEGER DEFAULT 0"),
                        ('total_urls_failed', "ALTER TABLE scan_runs ADD COLUMN total_urls_failed INTEGER DEFAULT 0"),
                        ('tool_results', "ALTER TABLE scan_runs ADD COLUMN tool_results TEXT")
                    ]
                    
                    for col_name, sql in scan_runs_columns_to_add:
                        if col_name not in scan_runs_columns:
                            try:
                                conn.execute(sql)
                                self.logger.debug(f"Added column {col_name} to scan_runs table")
                            except sqlite3.OperationalError as e:
                                if "duplicate column" not in str(e):
                                    self.logger.error(f"Failed to add column {col_name}: {e}")
                
                # Create index for fetch status
                try:
                    conn.execute('''
                        CREATE INDEX IF NOT EXISTS idx_urls_fetch_status 
                        ON urls(fetch_status)
                    ''')
                except Exception as e:
                    self.logger.debug(f"Index creation note: {e}")
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing database tables: {e}")
    
    def set_scan_run_id(self, scan_run_id: str):
        """Set the current scan run ID for progress tracking"""
        self.scan_run_id = scan_run_id
        self.logger.debug(f"Set scan_run_id to: {scan_run_id}")
    
    def _url_to_filename(self, url: str) -> str:
        """Convert URL to a safe filename."""
        parsed = urlparse(url)
        
        # Create base components
        domain = parsed.netloc.replace('.', '_').replace(':', '_')
        path = parsed.path.strip('/').replace('/', '_')
        
        # Handle query parameters
        if parsed.query:
            # Create a short hash of query params
            query_hash = hashlib.md5(parsed.query.encode()).hexdigest()[:8]
            path = f"{path}_q{query_hash}" if path else f"index_q{query_hash}"
        
        # If no path, use index
        if not path:
            path = "index"
        
        # Determine extension based on URL content
        if path.endswith('.js'):
            ext = ''  # Already has extension
        elif path.endswith('.json'):
            ext = ''
        elif any(pattern in url.lower() for pattern in ['api', '/v1/', '/v2/', '/graphql']):
            ext = '.json'
        elif '.js' in url or 'javascript' in url.lower():
            ext = '.js'
        else:
            ext = '.html'
        
        # Construct filename
        filename = f"{domain}_{path}{ext}"
        
        # Ensure filename isn't too long
        if len(filename) > 200:
            # Truncate and add hash
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            base_name = filename[:150]
            ext_part = Path(filename).suffix
            filename = f"{base_name}_{url_hash}{ext_part}"
        
        # Clean up any remaining problematic characters
        filename = re.sub(r'[<>:"|?*\\]', '_', filename)
        
        return filename
    
    def _initialize_url_mappings(self, urls: List[str], scan_id: Optional[str] = None) -> Dict[str, str]:
        """Initialize URL to filename mappings before fetching."""
        mappings = {}
        
        for url in urls:
            # Generate filename
            filename = self._url_to_filename(url)
            mappings[url] = filename
            
            # Store in database
            if scan_id:
                try:
                    with sqlite3.connect(str(self.db_path)) as conn:
                        # First ensure the URL exists in the database
                        cursor = conn.execute("SELECT id FROM urls WHERE url = ? AND scan_id = ?", (url, scan_id))
                        if cursor.fetchone():
                            conn.execute("""
                                UPDATE urls 
                                SET file_name = ?, fetch_status = 'pending'
                                WHERE url = ? AND scan_id = ?
                            """, (filename, url, scan_id))
                        else:
                            self.logger.warning(f"URL not found in database: {url}")
                except Exception as e:
                    self.logger.error(f"Failed to update URL mapping for {url}: {e}")
        
        return mappings
    
    def load_url_mappings_from_db(self, scan_id: Optional[str] = None):
        """Load URL to filename mappings from database"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                if scan_id:
                    # Try both file_path and file_name columns
                    query = '''
                        SELECT url, COALESCE(file_name, file_path) as filename
                        FROM urls 
                        WHERE scan_id = ? AND (file_name IS NOT NULL OR file_path IS NOT NULL)
                    '''
                    rows = conn.execute(query, (scan_id,)).fetchall()
                else:
                    query = '''
                        SELECT url, COALESCE(file_name, file_path) as filename
                        FROM urls 
                        WHERE file_name IS NOT NULL OR file_path IS NOT NULL
                    '''
                    rows = conn.execute(query).fetchall()
                
                self.url_filename_map = {}
                for row in rows:
                    if row[1]:  # If filename exists
                        # Extract just the filename if it's a full path
                        filename = Path(row[1]).name if row[1] else None
                        if filename:
                            self.url_filename_map[row[0]] = filename
                
                self.logger.info(f"Loaded {len(self.url_filename_map)} URL mappings from database")
                
        except Exception as e:
            self.logger.error(f"Error loading URL mappings from DB: {e}")
    
    def fetch_content(self, urls: List[str], output_dir: str, 
                     categorized_urls: Optional[Dict[str, List[str]]] = None,
                     scan_id: Optional[str] = None) -> int:
        """
        Fetch content from a list of URLs with database tracking.
        
        Args:
            urls: List of URLs to fetch
            output_dir: Directory to save fetched content
            categorized_urls: Optional categorized URLs (priority, normal, problematic)
            scan_id: Scan identifier for database tracking
            
        Returns:
            Number of successfully fetched URLs
        """
        self.logger.info(f"Starting content fetching for {len(urls)} URLs")
        self.stats['total_urls'] = len(urls)
        self._progress['total'] = len(urls)
        self._progress['status'] = 'fetching'
        
        # Initialize URL mappings BEFORE trying to load from DB
        self.url_filename_map = self._initialize_url_mappings(urls, scan_id)
        if scan_id:
            self.scan_run_id = scan_id
        
        # Also try to load any existing mappings from database
        if scan_id:
            self.load_url_mappings_from_db(scan_id)
        
        # Update progress in database
        self._update_scan_progress('content_fetching', 0)
        
        # Create output directory structure
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        for subdir in ['html', 'js', 'json', 'inline-scripts', 'metadata', 'errors']:
            (output_path / subdir).mkdir(exist_ok=True)
        
        # Save URL to filename mapping for crawler and other components
        self._save_url_mapping(output_dir)
        
        # Mark URLs as being fetched in database
        if scan_id:
            self._mark_urls_fetching(urls, scan_id)
        
        # Organize URLs by priority if categorized
        if categorized_urls:
            priority_urls = categorized_urls.get('priority', [])
            normal_urls = categorized_urls.get('normal', [])
            problematic_urls = categorized_urls.get('problematic', [])
            
            # Process in order: priority first, then normal, then problematic
            ordered_urls = priority_urls + normal_urls
            
            # Only include problematic if configured
            if self.config.get('include_problematic_urls', False):
                ordered_urls.extend(problematic_urls)
            
            self.logger.info(f"Processing {len(priority_urls)} priority URLs first")
        else:
            ordered_urls = urls
        
        # Track which URLs have been processed
        processed_urls = set()
        failed_urls = []
        
        # Phase 1: Crawler processing
        if not self.config.get('skip_crawler', False) and self.crawler_script.exists():
            crawler_results = self._run_crawler_in_batches(ordered_urls, output_dir)
            processed_urls.update(crawler_results['success'])
            failed_urls.extend(crawler_results['failed'])
            
            # Update database with crawler results
            if scan_id:
                self._update_url_status_batch(crawler_results['success'], 'completed', 'crawler', scan_id)
                self._update_url_status_batch(crawler_results['failed'], 'failed', 'crawler', scan_id)
        else:
            if not self.crawler_script.exists():
                self.logger.warning("Crawler script not found, using static fetcher only")
            else:
                self.logger.info("Crawler skipped by configuration")
            failed_urls = ordered_urls
        
        # Phase 2: Static fallback for failed URLs
        if self.use_static_fallback and failed_urls and self.static_fetcher:
            self.logger.info(f"Attempting static fetch for {len(failed_urls)} failed URLs")
            
            # Pass URL mappings to static fetcher
            if hasattr(self.static_fetcher, 'url_filename_map'):
                self.static_fetcher.url_filename_map = self.url_filename_map
            
            static_results = self._run_static_fetcher(failed_urls, output_dir)
            processed_urls.update(static_results['success'])
            
            # Update database with static fetcher results
            if scan_id:
                self._update_url_status_batch(static_results['success'], 'completed', 'static', scan_id)
            
            # Update final failed list
            final_failed = [url for url in failed_urls if url not in static_results['success']]
            self.stats['failed_urls'] = final_failed
            
            # Mark permanently failed URLs
            if scan_id:
                self._update_url_status_batch(final_failed, 'failed', 'both', scan_id)
        
        # Update final statistics
        self.stats['total_success'] = len(processed_urls)
        self.stats['total_failed'] = self.stats['total_urls'] - self.stats['total_success']
        self.stats['success_urls'] = list(processed_urls)
        
        # Update final progress in database
        self._update_scan_progress('content_fetching', 100)
        
        # Save statistics and reports
        self._save_statistics(output_dir)
        self._save_failed_urls_report(output_dir)
        
        # Update scan run statistics in database
        self._update_scan_run_stats()
        
        self.logger.info(f"Content fetching completed. Total fetched: {self.stats['total_success']}/{self.stats['total_urls']}")
        
        return self.stats['total_success']
    
    def _mark_urls_fetching(self, urls: List[str], scan_id: str):
        """Mark URLs as being fetched in database"""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                timestamp = datetime.utcnow().isoformat()
                for url in urls:
                    conn.execute('''
                        UPDATE urls 
                        SET fetch_status = 'fetching', 
                            fetch_attempted_at = ?
                        WHERE url = ? AND scan_id = ?
                    ''', (timestamp, url, scan_id))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error marking URLs as fetching: {e}")
    
    def _update_url_status_batch(self, urls: List[str], status: str, fetcher_type: str, scan_id: str):
        """Update status for a batch of URLs in database"""
        if not urls:
            return
            
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                timestamp = datetime.utcnow().isoformat()
                
                if status == 'completed':
                    for url in urls:
                        conn.execute('''
                            UPDATE urls 
                            SET fetch_status = ?, 
                                fetch_completed_at = ?,
                                fetcher_type = ?
                            WHERE url = ? AND scan_id = ?
                        ''', (status, timestamp, fetcher_type, url, scan_id))
                else:
                    for url in urls:
                        # Get error message if available
                        error_msg = self._get_error_for_url(url)
                        conn.execute('''
                            UPDATE urls 
                            SET fetch_status = ?, 
                                fetcher_type = ?,
                                fetch_error = ?
                            WHERE url = ? AND scan_id = ?
                        ''', (status, fetcher_type, error_msg, url, scan_id))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error updating URL status batch: {e}")
    
    def _get_error_for_url(self, url: str) -> Optional[str]:
        """Get error message for a failed URL from stats"""
        for error in self.stats['errors']:
            if error.get('url') == url:
                return error.get('error', 'Unknown error')
        return None
    
    def _update_scan_progress(self, stage: str, percentage: int):
        """Update scan progress in database"""
        if not self.scan_run_id:
            return
            
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # First check if last_updated column exists
                cursor = conn.execute("PRAGMA table_info(scan_runs)")
                columns = [col[1] for col in cursor.fetchall()]
                
                if 'last_updated' in columns:
                    conn.execute('''
                        UPDATE scan_runs 
                        SET status = ?,
                            last_updated = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (f'{stage}: {percentage}%', self.scan_run_id))
                else:
                    # Fallback without last_updated
                    conn.execute('''
                        UPDATE scan_runs 
                        SET status = ?
                        WHERE id = ?
                    ''', (f'{stage}: {percentage}%', self.scan_run_id))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error updating scan progress: {e}")
    
    def _update_scan_run_stats(self):
        """Update scan run statistics in database"""
        if not self.scan_run_id:
            return
            
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # First get the scan_id associated with this scan_run_id
                cursor = conn.execute("SELECT domains FROM scan_runs WHERE id = ?", (self.scan_run_id,))
                row = cursor.fetchone()
                if not row:
                    self.logger.warning(f"Scan run {self.scan_run_id} not found")
                    return
                
                # Count fetched URLs
                total_fetched = len(self.stats.get('success_urls', []))
                total_failed = len(self.stats.get('failed_urls', []))
                
                # Check which columns exist
                cursor = conn.execute("PRAGMA table_info(scan_runs)")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Update with available columns
                update_query = "UPDATE scan_runs SET "
                params = []
                
                if 'total_urls_fetched' in columns:
                    update_query += "total_urls_fetched = ?, "
                    params.append(total_fetched)
                
                if 'total_urls_failed' in columns:
                    update_query += "total_urls_failed = ?, "
                    params.append(total_failed)
                
                # Remove trailing comma and add WHERE clause
                update_query = update_query.rstrip(', ') + " WHERE id = ?"
                params.append(self.scan_run_id)
                
                if params and len(params) > 1:  # Only update if we have columns to update
                    conn.execute(update_query, params)
                    conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error updating scan run stats: {e}")
    
    def _save_url_mapping(self, output_dir: str):
        """Save URL to filename mapping for crawler and other components."""
        mapping_file = Path(output_dir) / 'url_filename_mapping.json'
        
        # Create reverse mapping too for easier lookup
        filename_to_url = {filename: url for url, filename in self.url_filename_map.items()}
        
        mapping_data = {
            'url_to_filename': self.url_filename_map,
            'filename_to_url': filename_to_url,
            'total_urls': len(self.url_filename_map),
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        try:
            with open(mapping_file, 'w') as f:
                json.dump(mapping_data, f, indent=2)
            self.logger.debug(f"Saved URL mapping for {len(self.url_filename_map)} URLs")
        except Exception as e:
            self.logger.error(f"Failed to save URL mapping: {e}")
    
    def _run_crawler_in_batches(self, urls: List[str], output_dir: str) -> Dict[str, List[str]]:
        """
        Run the crawler in batches for better performance and error handling.
        
        Returns:
            Dict with 'success' and 'failed' URL lists
        """
        results = {
            'success': [],
            'failed': []
        }
        
        # Split URLs into batches
        batches = [urls[i:i + self.batch_size] for i in range(0, len(urls), self.batch_size)]
        
        self.logger.info(f"Running crawler for {len(urls)} URLs in {len(batches)} batches")
        
        for i, batch in enumerate(batches):
            self.logger.info(f"Processing batch {i + 1}/{len(batches)} ({len(batch)} URLs)")
            
            # Update progress
            progress_pct = int((i / len(batches)) * 50)  # Crawler is 0-50% of progress
            self._update_scan_progress('content_fetching', progress_pct)
            
            try:
                batch_results = self._run_crawler_batch(batch, output_dir)
                
                # Identify which URLs succeeded/failed
                batch_success, batch_failed = self._identify_batch_results(batch, output_dir)
                
                results['success'].extend(batch_success)
                results['failed'].extend(batch_failed)
                
                self.stats['crawler_success'] += len(batch_success)
                self.stats['crawler_failed'] += len(batch_failed)
                
                # Update progress
                with self._progress_lock:
                    self._progress['current'] += len(batch)
                
                # Log batch summary
                self.logger.info(f"Batch {i + 1} completed: {len(batch_success)} success, {len(batch_failed)} failed")
                
                # Small delay between batches
                if i < len(batches) - 1:
                    time.sleep(2)
                    
            except Exception as e:
                self.logger.error(f"Batch {i + 1} processing failed: {e}")
                results['failed'].extend(batch)
                self.stats['crawler_failed'] += len(batch)
                self.stats['errors'].append({
                    'batch': i + 1,
                    'error': str(e),
                    'timestamp': time.time()
                })
        
        self.stats['crawler_attempted'] = len(urls)
        
        return results
    
    def _run_crawler_batch(self, urls: List[str], output_dir: str) -> Dict:
        """
        Run the Node.js crawler for a batch of URLs.
        
        Args:
            urls: List of URLs to crawl
            output_dir: Output directory
            
        Returns:
            Dictionary with batch results
        """
        # Create temporary files for batch processing
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for url in urls:
                f.write(f"{url}\n")
            urls_file = f.name
        
        # Create batch-specific mapping file
        batch_mapping = {url: self.url_filename_map.get(url, self._url_to_filename(url)) for url in urls}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(batch_mapping, f)
            mapping_file = f.name
        
        try:
            # Prepare crawler command
            cmd = [
                'node',
                str(self.crawler_script),
                '--input', urls_file,
                '--output', output_dir,
                '--url-mapping', mapping_file,
                '--max-requests', str(min(len(urls) * 2, self.max_requests)),
                '--concurrency', str(self.concurrency),
                '--timeout', str(self.timeout // 1000),
                '--batch-size', str(self.batch_size),
                '--headless' if self.headless else '--no-headless'
            ]
            # Add scan-id if available
            if self.scan_run_id:
                cmd.extend(['--scan-id', self.scan_run_id])
            
            if self.logger.level == logging.DEBUG:
                cmd.append('--verbose')
            
            self.logger.debug(f"Running crawler command: {' '.join(cmd)}")
            
            # Run crawler
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(300, (self.timeout / 1000) + (10 * len(urls)))
            )
            
            duration = time.time() - start_time
            
            # Parse crawler output
            batch_results = {
                'success': 0,
                'failed': 0,
                'duration': duration
            }
            
            if result.returncode == 0:
                self.logger.info(f"Crawler batch completed successfully in {duration:.2f}s")
                
                # Try to read crawler statistics
                stats_file = Path(output_dir) / 'crawler_stats.json'
                if stats_file.exists():
                    try:
                        with open(stats_file, 'r') as f:
                            crawler_stats = json.load(f)
                        batch_results['success'] = crawler_stats.get('urlsSuccessful', 0)
                        batch_results['failed'] = crawler_stats.get('urlsFailed', 0)
                    except Exception as e:
                        self.logger.warning(f"Failed to read crawler stats: {e}")
            else:
                self.logger.error(f"Crawler batch failed with code {result.returncode}")
                if result.stderr:
                    self.logger.error(f"STDERR: {result.stderr[:500]}")  # Limit error output
            
            return batch_results
            
        except subprocess.TimeoutExpired:
            self.logger.error("Crawler batch timed out")
            return {
                'success': 0,
                'failed': len(urls),
                'error': 'timeout'
            }
        except Exception as e:
            self.logger.error(f"Crawler batch execution failed: {e}")
            return {
                'success': 0,
                'failed': len(urls),
                'error': str(e)
            }
        finally:
            # Clean up temporary files
            for temp_file in [urls_file, mapping_file]:
                try:
                    os.unlink(temp_file)
                except:
                    pass
    
    def _identify_batch_results(self, urls: List[str], output_dir: str) -> Tuple[List[str], List[str]]:
        """
        Identify which URLs succeeded or failed in a batch using URL-based filenames.
        
        Returns:
            Tuple of (success_urls, failed_urls)
        """
        success_urls = []
        failed_urls = []
        
        output_path = Path(output_dir)
        
        # Check each URL
        for url in urls:
            filename = self.url_filename_map.get(url, self._url_to_filename(url))
            
            # Determine expected file location based on extension
            if filename.endswith('.js'):
                expected_path = output_path / 'js' / filename
            elif filename.endswith('.json'):
                expected_path = output_path / 'json' / filename
            else:
                expected_path = output_path / 'html' / filename
            
            # Check if file exists
            if expected_path.exists() and expected_path.stat().st_size > 0:
                success_urls.append(url)
            else:
                # Check metadata for error info
                metadata_path = output_path / 'metadata' / f"{filename}.meta.json"
                if metadata_path.exists():
                    try:
                        with open(metadata_path, 'r') as f:
                            metadata = json.load(f)
                            if metadata.get('error'):
                                failed_urls.append(url)
                            else:
                                success_urls.append(url)
                    except:
                        failed_urls.append(url)
                else:
                    failed_urls.append(url)
        
        return success_urls, failed_urls
    
    def _run_static_fetcher(self, urls: List[str], output_dir: str) -> Dict[str, List[str]]:
        """
        Run static fetcher for URLs that failed with crawler.
        
        Returns:
            Dict with 'success' and 'failed' URL lists
        """
        if not self.static_fetcher:
            return {'success': [], 'failed': urls}
        
        results = {
            'success': [],
            'failed': []
        }
        
        self.logger.info(f"Running static fetcher for {len(urls)} URLs")
        self.stats['static_attempted'] = len(urls)
        
        # Pass URL mapping to static fetcher
        if hasattr(self.static_fetcher, 'url_filename_map'):
            self.static_fetcher.url_filename_map = self.url_filename_map
        
        # Process URLs concurrently
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_to_url = {
                executor.submit(self._fetch_with_static, url, output_dir): url
                for url in urls
            }
            
            total_static = len(urls)
            completed = 0
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                completed += 1
                
                # Update progress (static is 50-100% of progress)
                progress_pct = 50 + int((completed / total_static) * 50)
                self._update_scan_progress('content_fetching', progress_pct)
                
                try:
                    success = future.result()
                    if success:
                        results['success'].append(url)
                        self.stats['static_success'] += 1
                    else:
                        results['failed'].append(url)
                        self.stats['static_failed'] += 1
                except Exception as e:
                    self.logger.error(f"Static fetch failed for {url}: {e}")
                    results['failed'].append(url)
                    self.stats['static_failed'] += 1
                    self.stats['errors'].append({
                        'url': url,
                        'fetcher': 'static',
                        'error': str(e),
                        'timestamp': time.time()
                    })
                
                # Update progress
                with self._progress_lock:
                    self._progress['current'] += 1
        
        return results
    
    def _fetch_with_static(self, url: str, output_dir: str) -> bool:
        """Fetch a single URL with static fetcher using URL-based filename."""
        filename = self.url_filename_map.get(url, self._url_to_filename(url))
        
        # Pass filename to static fetcher if it supports it
        if hasattr(self.static_fetcher, 'fetch_url_with_filename'):
            return self.static_fetcher.fetch_url_with_filename(url, output_dir, filename)
        else:
            # Fallback to regular fetch
            return self.static_fetcher.fetch_url(url, output_dir)
    
    def _save_statistics(self, output_dir: str):
        """Save detailed fetching statistics."""
        stats_file = Path(output_dir) / 'fetcher_stats.json'
        
        # Calculate additional statistics
        self.stats['success_rate'] = (
            f"{(self.stats['total_success'] / self.stats['total_urls'] * 100):.2f}%"
            if self.stats['total_urls'] > 0 else "0%"
        )
        
        self.stats['crawler_success_rate'] = (
            f"{(self.stats['crawler_success'] / self.stats['crawler_attempted'] * 100):.2f}%"
            if self.stats['crawler_attempted'] > 0 else "N/A"
        )
        
        self.stats['static_success_rate'] = (
            f"{(self.stats['static_success'] / self.stats['static_attempted'] * 100):.2f}%"
            if self.stats['static_attempted'] > 0 else "N/A"
        )
        
        # Add URL mapping info
        self.stats['url_mapping'] = {
            'total_mapped': len(self.url_filename_map),
            'mapping_file': 'url_filename_mapping.json'
        }
        
        # Add database info
        self.stats['database'] = {
            'path': str(self.db_path),
            'scan_run_id': self.scan_run_id
        }
        
        try:
            with open(stats_file, 'w') as f:
                json.dump(self.stats, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save statistics: {e}")
    
    def _save_failed_urls_report(self, output_dir: str):
        """Save detailed report of failed URLs."""
        if not self.stats['failed_urls']:
            return
        
        report_file = Path(output_dir) / 'failed_urls_report.json'
        
        # Group failed URLs by error type
        error_groups = defaultdict(list)
        
        for error in self.stats['errors']:
            if 'url' in error:
                error_type = error.get('error', 'Unknown error')
                # Simplify error messages for grouping
                if 'timeout' in error_type.lower():
                    error_type = 'Timeout'
                elif '403' in error_type:
                    error_type = '403 Forbidden'
                elif '404' in error_type:
                    error_type = '404 Not Found'
                elif 'connection' in error_type.lower():
                    error_type = 'Connection Error'
                
                error_groups[error_type].append(error['url'])
        
        report = {
            'summary': {
                'total_failed': len(self.stats['failed_urls']),
                'error_types': len(error_groups),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'error_groups': dict(error_groups),
            'all_failed_urls': self.stats['failed_urls']
        }
        
        try:
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            # Also save simple text list
            failed_txt = Path(output_dir) / 'failed_urls_list.txt'
            with open(failed_txt, 'w') as f:
                for url in self.stats['failed_urls']:
                    f.write(f"{url}\n")
                    
        except Exception as e:
            self.logger.error(f"Failed to save failed URLs report: {e}")
    
    def get_progress(self) -> Dict:
        """Get current progress information."""
        with self._progress_lock:
            return self._progress.copy()
    
    def get_fetch_summary_from_db(self) -> Dict[str, Any]:
        """Get fetch summary from database for current scan"""
        if not self.scan_run_id:
            return {}
            
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Get scan_id from scan_run_id
                cursor = conn.execute("SELECT domains FROM scan_runs WHERE id = ?", (self.scan_run_id,))
                row = cursor.fetchone()
                if not row:
                    return {}
                
                # Get URL stats for this scan
                stats = conn.execute('''
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN fetch_status = 'completed' THEN 1 ELSE 0 END) as completed,
                        SUM(CASE WHEN fetch_status = 'failed' THEN 1 ELSE 0 END) as failed,
                        SUM(CASE WHEN fetch_status = 'pending' THEN 1 ELSE 0 END) as pending,
                        SUM(CASE WHEN fetcher_type = 'crawler' THEN 1 ELSE 0 END) as by_crawler,
                        SUM(CASE WHEN fetcher_type = 'static' THEN 1 ELSE 0 END) as by_static
                    FROM urls
                    WHERE scan_id = ?
                ''', (self.scan_run_id,)).fetchone()
                
                if stats:
                    return {
                        'total_urls': stats[0],
                        'completed': stats[1] or 0,
                        'failed': stats[2] or 0,
                        'pending': stats[3] or 0,
                        'fetched_by_crawler': stats[4] or 0,
                        'fetched_by_static': stats[5] or 0,
                        'success_rate': f"{((stats[1] or 0) / stats[0] * 100):.1f}%" if stats[0] > 0 else "0%"
                    }
                
                return {}
                
        except Exception as e:
            self.logger.error(f"Error getting fetch summary from DB: {e}")
            return {}
    
    def validate_content(self, content_dir: str) -> Dict:
        """
        Validate fetched content and generate report.
        
        Args:
            content_dir: Directory containing fetched content
            
        Returns:
            Validation report
        """
        report = {
            'total_files': 0,
            'html_files': 0,
            'js_files': 0,
            'json_files': 0,
            'inline_scripts': 0,
            'errors': 0,
            'total_size_mb': 0,
            'file_types': {},
            'largest_files': [],
            'suspicious_files': [],
            'url_mapped_files': 0,
            'database_sync': {}
        }
        
        content_path = Path(content_dir)
        
        # Load URL mapping to validate
        mapping_file = content_path / 'url_filename_mapping.json'
        url_mapping = {}
        if mapping_file.exists():
            try:
                with open(mapping_file, 'r') as f:
                    mapping_data = json.load(f)
                    url_mapping = mapping_data.get('filename_to_url', {})
            except:
                pass
        
        # Check database sync
        if self.scan_run_id:
            report['database_sync'] = self.get_fetch_summary_from_db()
        
        # Track largest files
        file_sizes = []
        
        # Count files by type
        for subdir in ['html', 'js', 'json', 'inline-scripts', 'errors']:
            dir_path = content_path / subdir
            if dir_path.exists():
                files = list(dir_path.glob('*'))
                count = len(files)
                
                if subdir == 'html':
                    report['html_files'] = count
                elif subdir == 'js':
                    report['js_files'] = count
                elif subdir == 'json':
                    report['json_files'] = count
                elif subdir == 'inline-scripts':
                    report['inline_scripts'] = count
                elif subdir == 'errors':
                    report['errors'] = count
                
                # Calculate sizes and track files
                for file in files:
                    if file.is_file():
                        size_mb = file.stat().st_size / (1024 * 1024)
                        report['total_size_mb'] += size_mb
                        
                        # Check if file has URL mapping
                        if file.name in url_mapping:
                            report['url_mapped_files'] += 1
                        
                        # Track file info
                        file_info = {
                            'path': str(file.relative_to(content_path)),
                            'size_mb': round(size_mb, 2),
                            'type': subdir,
                            'url': url_mapping.get(file.name, 'unmapped')
                        }
                        file_sizes.append(file_info)
                        
                        # Track file types
                        ext = file.suffix.lower()
                        report['file_types'][ext] = report['file_types'].get(ext, 0) + 1
                        
                        # Check for suspicious patterns
                        if self._is_suspicious_file(file):
                            report['suspicious_files'].append(file_info)
                
                report['total_files'] += count
        
        # Get top 10 largest files
        file_sizes.sort(key=lambda x: x['size_mb'], reverse=True)
        report['largest_files'] = file_sizes[:10]
        
        # Round total size
        report['total_size_mb'] = round(report['total_size_mb'], 2)
        
        # Calculate mapping coverage
        if report['total_files'] > 0:
            report['mapping_coverage'] = f"{(report['url_mapped_files'] / report['total_files'] * 100):.1f}%"
        else:
            report['mapping_coverage'] = "0%"
        
        return report
    
    def _is_suspicious_file(self, file_path: Path) -> bool:
        """Check if a file might contain interesting content."""
        suspicious_patterns = [
            'config', 'env', 'secret', 'key', 'token', 'password',
            'auth', 'api', 'private', 'admin', 'debug', 'test'
        ]
        
        filename = file_path.name.lower()
        return any(pattern in filename for pattern in suspicious_patterns)