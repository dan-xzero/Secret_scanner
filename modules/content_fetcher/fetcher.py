"""
Enhanced Content Fetcher Module

Key improvements:
1. Better coordination between crawler and static fetcher
2. Intelligent retry strategy
3. URL prioritization
4. Better error tracking
5. Progress monitoring
"""

import os
import subprocess
import json
import time
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from collections import defaultdict
import threading

import requests
from loguru import logger


class ContentFetcher:
    """Fetches HTML and JavaScript content from URLs."""
    
    def __init__(self, config: Dict, logger: Optional[logging.Logger] = None):
        """
        Initialize Content Fetcher.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Paths
        self.crawler_script = Path(__file__).parent / 'crawler.js'
        self.static_fetcher = None
        
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
            raise FileNotFoundError(f"Crawler script not found: {self.crawler_script}")
        
        # Initialize static fetcher if needed
        if self.use_static_fallback:
            from .static_fetcher import StaticFetcher
            self.static_fetcher = StaticFetcher(config, logger)
        
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
    
    def fetch_content(self, urls: List[str], output_dir: str, categorized_urls: Optional[Dict[str, List[str]]] = None) -> int:
        """
        Fetch content from a list of URLs.
        
        Args:
            urls: List of URLs to fetch
            output_dir: Directory to save fetched content
            categorized_urls: Optional categorized URLs (priority, normal, problematic)
            
        Returns:
            Number of successfully fetched URLs
        """
        self.logger.info(f"Starting content fetching for {len(urls)} URLs")
        self.stats['total_urls'] = len(urls)
        self._progress['total'] = len(urls)
        self._progress['status'] = 'fetching'
        
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
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
        if not self.config.get('skip_crawler', False):
            crawler_results = self._run_crawler_in_batches(ordered_urls, output_dir)
            processed_urls.update(crawler_results['success'])
            failed_urls.extend(crawler_results['failed'])
        else:
            self.logger.info("Crawler skipped by configuration")
            failed_urls = ordered_urls
        
        # Phase 2: Static fallback for failed URLs
        if self.use_static_fallback and failed_urls:
            self.logger.info(f"Attempting static fetch for {len(failed_urls)} failed URLs")
            static_results = self._run_static_fetcher(failed_urls, output_dir)
            processed_urls.update(static_results['success'])
            
            # Update final failed list
            final_failed = [url for url in failed_urls if url not in static_results['success']]
            self.stats['failed_urls'] = final_failed
        
        # Update final statistics
        self.stats['total_success'] = len(processed_urls)
        self.stats['total_failed'] = self.stats['total_urls'] - self.stats['total_success']
        self.stats['success_urls'] = list(processed_urls)
        
        # Save statistics and reports
        self._save_statistics(output_dir)
        self._save_failed_urls_report(output_dir)
        
        self.logger.info(f"Content fetching completed. Total fetched: {self.stats['total_success']}/{self.stats['total_urls']}")
        
        return self.stats['total_success']
    
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
            
            try:
                batch_results = self._run_crawler_batch(batch, output_dir)
                
                # Parse results
                success_count = batch_results.get('success', 0)
                failed_count = len(batch) - success_count
                
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
        # Create temporary file with URLs
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for url in urls:
                f.write(f"{url}\n")
            urls_file = f.name
        
        try:
            # Prepare crawler command
            cmd = [
                'node',
                str(self.crawler_script),
                '--input', urls_file,
                '--output', output_dir,
                '--max-requests', str(min(len(urls) * 2, self.max_requests)),  # Allow some retries
                '--concurrency', str(self.concurrency),
                '--timeout', str(self.timeout // 1000),  # Convert to seconds
                '--batch-size', str(self.batch_size),
                '--headless' if self.headless else '--no-headless'
            ]
            
            if self.logger.level == logging.DEBUG:
                cmd.append('--verbose')
            
            self.logger.debug(f"Running crawler command: {' '.join(cmd)}")
            
            # Run crawler
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(300, (self.timeout / 1000) + (10 * len(urls)))  # Dynamic timeout
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
                
                # Parse stdout for results if stats file not available
                if batch_results['success'] == 0 and result.stdout:
                    for line in result.stdout.splitlines():
                        if 'Successful:' in line:
                            try:
                                batch_results['success'] = int(line.split('Successful:')[1].split()[0])
                            except:
                                pass
                        elif 'Failed:' in line:
                            try:
                                batch_results['failed'] = int(line.split('Failed:')[1].split()[0])
                            except:
                                pass
            else:
                self.logger.error(f"Crawler batch failed with code {result.returncode}")
                if result.stderr:
                    self.logger.error(f"STDERR: {result.stderr}")
                
                # Try to determine partial success
                batch_results['success'] = self._count_fetched_files(output_dir)
                batch_results['failed'] = len(urls) - batch_results['success']
                
            return batch_results
            
        except subprocess.TimeoutExpired:
            self.logger.error("Crawler batch timed out")
            return {
                'success': self._count_fetched_files(output_dir),
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
            # Clean up temporary file
            try:
                os.unlink(urls_file)
            except:
                pass
    
    def _identify_batch_results(self, urls: List[str], output_dir: str) -> Tuple[List[str], List[str]]:
        """
        Identify which URLs succeeded or failed in a batch.
        
        Returns:
            Tuple of (success_urls, failed_urls)
        """
        success_urls = []
        failed_urls = []
        
        # Check for failed URLs file first
        failed_file = Path(output_dir) / 'failed_urls.txt'
        failed_set = set()
        
        if failed_file.exists():
            try:
                with open(failed_file, 'r') as f:
                    failed_set = set(line.strip() for line in f if line.strip())
            except Exception as e:
                self.logger.warning(f"Failed to read failed URLs file: {e}")
        
        # Check metadata directory for successful fetches
        metadata_dir = Path(output_dir) / 'metadata'
        success_set = set()
        
        if metadata_dir.exists():
            for metadata_file in metadata_dir.glob('*.json'):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        if 'url' in metadata:
                            success_set.add(metadata['url'])
                except:
                    pass
        
        # Categorize URLs
        for url in urls:
            if url in failed_set:
                failed_urls.append(url)
            elif url in success_set:
                success_urls.append(url)
            else:
                # If not explicitly in either set, check if content exists
                if self._check_content_exists(url, output_dir):
                    success_urls.append(url)
                else:
                    failed_urls.append(url)
        
        return success_urls, failed_urls
    
    def _check_content_exists(self, url: str, output_dir: str) -> bool:
        """Check if content for a URL exists in output directory."""
        # First check the url_mappings.json file created by crawler
        mappings_file = Path(output_dir) / 'url_mappings.json'
        if mappings_file.exists():
            try:
                with open(mappings_file, 'r') as f:
                    mappings = json.load(f)
                    # Check if URL was successfully mapped
                    if url in mappings.get('urlToFile', {}):
                        return True
            except Exception as e:
                self.logger.debug(f"Failed to read URL mappings: {e}")
        
        # Fallback: Check file_to_url_mappings.json
        simple_mappings_file = Path(output_dir) / 'file_to_url_mappings.json'
        if simple_mappings_file.exists():
            try:
                with open(simple_mappings_file, 'r') as f:
                    file_mappings = json.load(f)
                    # Check if any file is mapped to this URL
                    for file_path, mapped_url in file_mappings.items():
                        if mapped_url == url:
                            return True
            except Exception as e:
                self.logger.debug(f"Failed to read simple mappings: {e}")
        
        # Last resort: Check metadata directory
        metadata_dir = Path(output_dir) / 'metadata'
        if metadata_dir.exists():
            for metadata_file in metadata_dir.glob('*.json'):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        if metadata.get('url') == url:
                            return True
                except:
                    continue
        
        return False
    
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
        
        # Process URLs concurrently
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_to_url = {
                executor.submit(self.static_fetcher.fetch_url, url, output_dir): url
                for url in urls
            }
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
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
    
    def _count_fetched_files(self, output_dir: str) -> int:
        """Count the number of successfully fetched files."""
        count = 0
        output_path = Path(output_dir)
        
        # Count metadata files (most reliable)
        metadata_dir = output_path / 'metadata'
        if metadata_dir.exists():
            # Only count non-error metadata files
            for metadata_file in metadata_dir.glob('*.json'):
                if not metadata_file.name.endswith('_error.json'):
                    count += 1
        
        return count
    
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
            'suspicious_files': []
        }
        
        content_path = Path(content_dir)
        
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
                        
                        # Track file info
                        file_info = {
                            'path': str(file.relative_to(content_path)),
                            'size_mb': round(size_mb, 2),
                            'type': subdir
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
        
        return report
    
    def _is_suspicious_file(self, file_path: Path) -> bool:
        """Check if a file might contain interesting content."""
        suspicious_patterns = [
            'config', 'env', 'secret', 'key', 'token', 'password',
            'auth', 'api', 'private', 'admin', 'debug', 'test'
        ]
        
        filename = file_path.name.lower()
        return any(pattern in filename for pattern in suspicious_patterns)