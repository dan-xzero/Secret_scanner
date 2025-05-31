"""
Enhanced URL Discovery Module with Active Crawling

Key improvements:
1. Integrated Katana for active crawling
2. Combined passive + active discovery
3. JavaScript-aware crawling with headless mode
4. Better deduplication of passive + active results
5. Enhanced progress tracking
"""

import os
import subprocess
import concurrent.futures
import re
import time
from typing import List, Set, Dict, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse, urljoin
import logging
from datetime import datetime
import json
import tempfile
from collections import defaultdict

from loguru import logger


class URLDiscovery:
    """Discovers URLs for target domains using passive reconnaissance and active crawling."""
    
    def __init__(self, config: Dict, logger: Optional[logging.Logger] = None):
        """
        Initialize URL Discovery module.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Passive discovery tools
        self.enable_gau = config.get('enable_gau', True)
        self.enable_waybackurls = config.get('enable_waybackurls', True)
        self.enable_wayurls = config.get('enable_wayurls', True)
        
        # Active crawling with Katana
        self.enable_katana = config.get('enable_katana', True)
        self.katana_headless = config.get('katana_headless', True)
        self.katana_depth = config.get('katana_depth', 3)
        self.katana_js_crawl = config.get('katana_js_crawl', True)
        self.katana_automatic_form_fill = config.get('katana_automatic_form_fill', False)
        self.katana_timeout = config.get('katana_timeout', 10000)
        self.katana_parallelism = config.get('katana_parallelism', 10)
        self.katana_crawl_duration = config.get('katana_crawl_duration', 0)  # 0 = no limit
        
        # Limits and timeouts
        self.url_discovery_timeout = config.get('url_discovery_timeout', 60000)
        self.max_urls_per_domain = config.get('max_urls_per_domain', 10000)
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 5)
        
        # URL filtering patterns
        self.exclude_extensions = self._parse_exclude_extensions()
        self.exclude_patterns = self._compile_exclude_patterns()
        self.priority_patterns = self._compile_priority_patterns()
        self.problematic_patterns = self._compile_problematic_patterns()
        
        # Results storage
        self.discovered_urls = {}
        self.categorized_urls = defaultdict(lambda: defaultdict(list))
        self.discovery_stats = defaultdict(lambda: defaultdict(int))
        self.errors = []
        
        # Validate tools availability
        self._validate_tools()
    
    def _parse_exclude_extensions(self) -> Set[str]:
        """Parse excluded file extensions from config."""
        # Default excluded extensions
        default_extensions = {
            # Images
            'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'webp', 'bmp', 'tiff',
            # Media
            'mp4', 'mp3', 'avi', 'mov', 'wmv', 'flv', 'wav', 'ogg', 'webm',
            # Documents (usually don't contain secrets)
            #'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            # Archives
            #'zip', 'tar', 'gz', 'rar', '7z', 'bz2',
            # Fonts
            'woff', 'woff2', 'ttf', 'eot', 'otf',
            # Stylesheets (can skip if not looking for secrets in CSS)
            #'css', 'scss', 'sass', 'less'
        }
        
        # Get custom extensions from config
        config_extensions = self.config.get('exclude_extensions', '')
        
        if isinstance(config_extensions, str):
            custom_extensions = set(ext.strip().lower() for ext in config_extensions.split(',') if ext.strip())
        elif isinstance(config_extensions, list):
            custom_extensions = set(ext.strip().lower() for ext in config_extensions)
        else:
            custom_extensions = set()
        
        # Combine default and custom
        return default_extensions.union(custom_extensions)
    
    def _compile_exclude_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for URL exclusion."""
        patterns = []
        
        # Extension-based exclusion
        if self.exclude_extensions:
            ext_pattern = r'\.(' + '|'.join(re.escape(ext) for ext in self.exclude_extensions) + r')(\?|$)'
            patterns.append(re.compile(ext_pattern, re.IGNORECASE))
        
        # Common patterns to exclude (commented out as per your config)
        exclude_patterns = []
        
        # Add custom exclude patterns from config
        custom_patterns = self.config.get('url_exclude_patterns', [])
        exclude_patterns.extend(custom_patterns)
        
        for pattern in exclude_patterns:
            try:
                patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern '{pattern}': {e}")
        
        return patterns
    
    def _compile_priority_patterns(self) -> List[re.Pattern]:
        """Compile patterns for high-priority URLs."""
        priority_patterns = [
            # JavaScript files
            r'\.js$',
            r'\.js[?#]',
            r'\.mjs$',
            r'\.ts$',
            r'/js/',
            r'/javascript/',
            r'/scripts/',
            r'/static/js/',
            r'/assets/js/',
            r'/dist/',
            r'/build/',
            r'/bundle',
            r'/vendor\.js',
            r'/app\.js',
            r'/main\.js',
            
            # Configuration files
            r'/config',
            r'/settings',
            r'/env',
            r'\.json$',
            r'\.json[?#]',
            r'/api/config',
            
            # Development/debug endpoints
            r'/debug',
            r'/test',
            r'/dev',
            r'/staging',
            r'/sandbox',
            r'/demo',
            
            # API documentation
            r'/swagger',
            r'/api-docs',
            r'/graphql',
            r'/playground',
            
            # Source maps
            r'\.map$',
            r'\.js\.map$',
            
            # Framework-specific
            r'/_next/',
            r'/.nuxt/',
            r'/static/chunks/',
            
            # Other interesting files
            r'/robots\.txt',
            r'/sitemap\.xml',
            r'/crossdomain\.xml',
            r'/.well-known/',
            r'/security\.txt',
        ]
        
        # Add custom priority patterns
        custom_patterns = self.config.get('url_priority_patterns', [])
        priority_patterns.extend(custom_patterns)
        
        compiled_patterns = []
        for pattern in priority_patterns:
            try:
                compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                self.logger.warning(f"Invalid priority pattern '{pattern}': {e}")
        
        return compiled_patterns
    
    def _compile_problematic_patterns(self) -> List[re.Pattern]:
        """Compile patterns for URLs that often cause issues."""
        problematic_patterns = []
        
        compiled_patterns = []
        for pattern in problematic_patterns:
            try:
                compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                self.logger.warning(f"Invalid problematic pattern '{pattern}': {e}")
        
        return compiled_patterns
    
    def _validate_tools(self):
        """Validate that required tools are installed."""
        tools_to_check = []
        
        if self.enable_gau:
            tools_to_check.append('gau')
        if self.enable_waybackurls:
            tools_to_check.append('waybackurls')
        if self.enable_wayurls:
            tools_to_check.append('wayurls')
        if self.enable_katana:
            tools_to_check.append('katana')
        
        missing_tools = []
        for tool in tools_to_check:
            if not self._check_tool_exists(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            self.logger.warning(f"Missing tools: {', '.join(missing_tools)}")
            self.logger.warning("Some URL discovery methods will be skipped")
            
            # Disable missing tools
            if 'katana' in missing_tools:
                self.enable_katana = False
                self.logger.warning("Katana not found - active crawling will be disabled")
    
    def _check_tool_exists(self, tool: str) -> bool:
        """Check if a tool exists in PATH."""
        try:
            subprocess.run(
                ['which', tool],
                capture_output=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def discover_urls(self, domain: str) -> List[str]:
        """
        Discover URLs for a single domain using passive + active methods.
        
        Args:
            domain: Target domain
            
        Returns:
            List of discovered URLs
        """
        self.logger.info(f"Starting URL discovery for domain: {domain}")
        
        passive_urls = set()
        active_urls = set()
        
        # Phase 1: Passive Discovery (fast)
        self.logger.info("Phase 1: Passive URL discovery")
        start_time = time.time()
        
        # Run passive discovery tools in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            
            if self.enable_gau and self._check_tool_exists('gau'):
                futures.append(
                    executor.submit(self._run_gau, domain)
                )
            
            if self.enable_waybackurls and self._check_tool_exists('waybackurls'):
                futures.append(
                    executor.submit(self._run_waybackurls, domain)
                )
            
            if self.enable_wayurls and self._check_tool_exists('wayurls'):
                futures.append(
                    executor.submit(self._run_wayurls, domain)
                )
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    urls = future.result()
                    passive_urls.update(urls)
                    self.logger.debug(f"Passive tool returned {len(urls)} URLs")
                except Exception as e:
                    self.logger.error(f"Passive tool execution failed: {e}")
                    self.errors.append({
                        'domain': domain,
                        'phase': 'passive_discovery',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
        
        passive_duration = time.time() - start_time
        self.logger.info(f"Passive discovery found {len(passive_urls)} URLs in {passive_duration:.2f}s")
        self.discovery_stats[domain]['passive_urls'] = len(passive_urls)
        self.discovery_stats[domain]['passive_duration'] = passive_duration
        
        # Phase 2: Active Crawling with Katana (thorough)
        if self.enable_katana and self._check_tool_exists('katana'):
            self.logger.info("Phase 2: Active crawling with Katana")
            start_time = time.time()
            
            try:
                active_urls = self._run_katana(domain)
                active_duration = time.time() - start_time
                
                self.logger.info(f"Active crawling found {len(active_urls)} URLs in {active_duration:.2f}s")
                self.discovery_stats[domain]['active_urls'] = len(active_urls)
                self.discovery_stats[domain]['active_duration'] = active_duration
                
            except Exception as e:
                self.logger.error(f"Active crawling failed: {e}")
                self.errors.append({
                    'domain': domain,
                    'phase': 'active_crawling',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        else:
            self.logger.info("Phase 2: Active crawling skipped (Katana disabled or not found)")
        
        # Combine all URLs
        all_urls = passive_urls.union(active_urls)
        
        # Log statistics
        overlap = len(passive_urls.intersection(active_urls))
        unique_passive = len(passive_urls - active_urls)
        unique_active = len(active_urls - passive_urls)
        
        self.logger.info(f"URL Discovery Statistics for {domain}:")
        self.logger.info(f"  - Total URLs: {len(all_urls)}")
        self.logger.info(f"  - Passive only: {unique_passive}")
        self.logger.info(f"  - Active only: {unique_active}")
        self.logger.info(f"  - Found by both: {overlap}")
        
        self.discovery_stats[domain]['total_urls'] = len(all_urls)
        self.discovery_stats[domain]['overlap'] = overlap
        self.discovery_stats[domain]['unique_passive'] = unique_passive
        self.discovery_stats[domain]['unique_active'] = unique_active
        
        # Filter and categorize URLs
        filtered_urls, categorized = self._filter_and_categorize_urls(list(all_urls), domain)
        
        # Store results
        self.discovered_urls[domain] = filtered_urls
        self.categorized_urls[domain] = categorized
        
        self.logger.info(f"After filtering: {len(filtered_urls)} URLs")
        self.logger.info(f"Categories: Priority: {len(categorized['priority'])}, "
                        f"Normal: {len(categorized['normal'])}, "
                        f"Problematic: {len(categorized['problematic'])}")
        
        return filtered_urls
    
    def _run_katana(self, domain: str) -> Set[str]:
        """Run Katana active crawler."""
        self.logger.debug(f"Running Katana for {domain}")
        
        urls = set()
        
        for attempt in range(self.max_retries):
            try:
                # Create temporary file for JSON output
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                    json_output = tmp.name
                
                # Prepare Katana command
                cmd = [
                    'katana',
                    '-u', f'https://{domain}',
                    '-d', str(self.katana_depth),
                    '-j',  # JSON output
                    '-silent',  # Silent mode
                    '-nc',  # No colors
                    '-o', json_output,  # Output file
                    '-timeout', str(self.katana_timeout),
                    '-parallelism', str(self.katana_parallelism),
                    '-form-extraction',  # Extract form fields
                    # '-display-out-scope'  # Include out-of-scope for filtering
                    '-field-scope', 'rdn',
                    '-match-regex', f'^https?://([a-zA-Z0-9.-]+\.)?{re.escape(domain)}(/.*)?$',
                ]
                
                # Add headless mode if configured
                if self.katana_headless:
                    cmd.extend([
                        '-headless',  # Enable headless browser
                        '-system-chrome',  # Use system Chrome
                        '-headless-options', '--disable-gpu --no-sandbox'
                    ])
                
                # Add JavaScript crawling options
                if self.katana_js_crawl:
                    cmd.extend([
                        '-jc',  # JavaScript crawling
                        '-xhr',  # Extract XHR requests
                        '-jsluice'  # Use JSLuice for JS parsing
                    ])
                
                # Add automatic form filling if enabled
                if self.katana_automatic_form_fill:
                    cmd.append('-automatic-form-fill')
                
                # Add crawl duration limit if set
                if self.katana_crawl_duration > 0:
                    cmd.extend(['-crawl-duration', str(self.katana_crawl_duration)])
                
                self.logger.debug(f"Katana command: {' '.join(cmd)}")
                
                # Run Katana
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.url_discovery_timeout,
                    check=False
                )
                
                if result.returncode == 0:
                    # Parse JSON output
                    if Path(json_output).exists():
                        with open(json_output, 'r') as f:
                            for line in f:
                                try:
                                    if line.strip():
                                        data = json.loads(line)
                                        
                                        # Extract URL from different possible formats
                                        url = None
                                        if isinstance(data, dict):
                                            # Format: {"timestamp":"...", "request":{"method":"GET","endpoint":"..."}}
                                            if 'request' in data and 'endpoint' in data['request']:
                                                url = data['request']['endpoint']
                                            # Format: {"url":"..."}
                                            elif 'url' in data:
                                                url = data['url']
                                            # Format: {"endpoint":"..."}
                                            elif 'endpoint' in data:
                                                url = data['endpoint']
                                        elif isinstance(data, str):
                                            url = data
                                        
                                        if url and self._is_valid_url(url):
                                            urls.add(url)
                                            
                                except json.JSONDecodeError:
                                    # Try treating line as plain URL
                                    if line.strip() and self._is_valid_url(line.strip()):
                                        urls.add(line.strip())
                    
                    # Also check stderr for any URLs (some versions output there)
                    for line in result.stderr.splitlines():
                        if line.strip() and line.startswith('http') and self._is_valid_url(line.strip()):
                            urls.add(line.strip())
                    
                    self.logger.debug(f"Katana found {len(urls)} URLs for {domain}")
                    break
                    
                else:
                    error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                    self.logger.warning(f"Katana failed (attempt {attempt + 1}): {error_msg}")
                    
            except subprocess.TimeoutExpired:
                self.logger.warning(f"Katana timed out for {domain} (attempt {attempt + 1})")
            except Exception as e:
                self.logger.error(f"Katana error for {domain}: {e}")
            finally:
                # Clean up temporary file
                if 'json_output' in locals() and Path(json_output).exists():
                    try:
                        os.unlink(json_output)
                    except:
                        pass
            
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay)
        
        return urls
    
    def _run_gau(self, domain: str) -> Set[str]:
        """Run gau (GetAllURLs) tool."""
        self.logger.debug(f"Running gau for {domain}")
        
        urls = set()
        
        for attempt in range(self.max_retries):
            try:
                # Prepare command
                cmd = [
                    'gau',
                    '--subs',  # Include subdomains
                    '--providers', 'wayback,otx,commoncrawl',
                    '--threads', '5',
                    '--timeout', '30',
                    domain
                ]
                
                # Run command with timeout
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.url_discovery_timeout,
                    check=False
                )
                
                if result.returncode == 0:
                    # Parse output
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line and self._is_valid_url(line):
                            urls.add(line)
                    
                    # Limit URLs per domain
                    if len(urls) > self.max_urls_per_domain:
                        urls = set(list(urls)[:self.max_urls_per_domain])
                    
                    self.logger.debug(f"gau found {len(urls)} URLs for {domain}")
                    break
                else:
                    error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                    self.logger.warning(f"gau failed (attempt {attempt + 1}): {error_msg}")
                    
            except subprocess.TimeoutExpired:
                self.logger.warning(f"gau timed out for {domain} (attempt {attempt + 1})")
            except Exception as e:
                self.logger.error(f"gau error for {domain}: {e}")
            
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay)
        
        return urls
    
    def _run_waybackurls(self, domain: str) -> Set[str]:
        """Run waybackurls tool."""
        self.logger.debug(f"Running waybackurls for {domain}")
        
        urls = set()
        
        for attempt in range(self.max_retries):
            try:
                # Run command with domain as input
                result = subprocess.run(
                    ['waybackurls'],
                    input=domain,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                )
                
                if result.returncode == 0:
                    # Parse output
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line and self._is_valid_url(line):
                            urls.add(line)
                    
                    # Limit URLs per domain
                    if len(urls) > self.max_urls_per_domain:
                        urls = set(list(urls)[:self.max_urls_per_domain])
                    
                    self.logger.debug(f"waybackurls found {len(urls)} URLs for {domain}")
                    break
                else:
                    error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                    self.logger.warning(f"waybackurls failed (attempt {attempt + 1}): {error_msg}")
                    
            except subprocess.TimeoutExpired:
                self.logger.warning(f"waybackurls timed out for {domain} (attempt {attempt + 1})")
            except Exception as e:
                self.logger.error(f"waybackurls error for {domain}: {e}")
            
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay)
        
        return urls
    
    def _run_wayurls(self, domain: str) -> Set[str]:
        """Run wayurls tool."""
        self.logger.debug(f"Running wayurls for {domain}")
        
        urls = set()
        
        for attempt in range(self.max_retries):
            try:
                # Prepare command
                cmd = [
                    'wayurls',
                    '-n',  # Exclude subdomains
                    domain
                ]
                
                # Add VirusTotal API key if available
                vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
                if vt_api_key:
                    cmd.extend(['-vt', vt_api_key])
                
                # Run command with timeout
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.url_discovery_timeout,
                    check=False
                )
                
                if result.returncode == 0:
                    # Parse output
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line and self._is_valid_url(line):
                            urls.add(line)
                    
                    # Limit URLs per domain
                    if len(urls) > self.max_urls_per_domain:
                        urls = set(list(urls)[:self.max_urls_per_domain])
                    
                    self.logger.debug(f"wayurls found {len(urls)} URLs for {domain}")
                    break
                else:
                    error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                    self.logger.warning(f"wayurls failed (attempt {attempt + 1}): {error_msg}")
                    
            except subprocess.TimeoutExpired:
                self.logger.warning(f"wayurls timed out for {domain} (attempt {attempt + 1})")
            except Exception as e:
                self.logger.error(f"wayurls error for {domain}: {e}")
            
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay)
        
        return urls
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if a URL is valid."""
        try:
            # Basic validation
            if not url or len(url) > 2048:  # Max URL length
                return False
            
            # Skip data URLs
            if url.startswith(('data:', 'javascript:', 'vbscript:', 'about:', 'blob:')):
                return False
            
            # Parse URL
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Check hostname
            if not parsed.netloc:
                return False
            
            # Check for common invalid patterns
            if any(char in url for char in ['<', '>', '"', '{', '}', '|', '\\', '^', '`']):
                return False
            
            return True
        except Exception:
            return False
    
    def _filter_and_categorize_urls(self, urls: List[str], domain: str) -> Tuple[List[str], Dict[str, List[str]]]:
        """
        Filter URLs and categorize them by priority.
        
        Args:
            urls: List of URLs to filter
            domain: Target domain for scope checking
            
        Returns:
            Tuple of (filtered_urls, categorized_urls)
        """
        categorized = {
            'priority': [],
            'normal': [],
            'problematic': [],
            'excluded': []
        }
        
        seen_normalized = set()
        
        for url in urls:
            try:
                # Normalize URL for deduplication
                parsed = urlparse(url.lower())
                # Remove common tracking parameters
                normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                if normalized in seen_normalized:
                    continue
                seen_normalized.add(normalized)
                
                # Check if URL is in scope
                if not self._is_in_scope(parsed.netloc, domain):
                    self.logger.debug(f"Out of scope: {parsed.netloc} not in {domain}")
                    continue
                
                # Check exclusion patterns
                if any(pattern.search(url) for pattern in self.exclude_patterns):
                    categorized['excluded'].append(url)
                    continue
                
                # Check if problematic
                if any(pattern.search(url) for pattern in self.problematic_patterns):
                    categorized['problematic'].append(url)
                    # Don't add problematic URLs to final list by default
                    if not self.config.get('include_problematic_urls', False):
                        continue
                
                # Check if priority
                elif any(pattern.search(url) for pattern in self.priority_patterns):
                    categorized['priority'].append(url)
                else:
                    categorized['normal'].append(url)
                    
            except Exception as e:
                self.logger.debug(f"Error filtering URL '{url}': {e}")
        
        # Combine priority and normal URLs
        filtered_urls = categorized['priority'] + categorized['normal']
        
        # If including problematic URLs, add them at the end
        if self.config.get('include_problematic_urls', False):
            filtered_urls.extend(categorized['problematic'])
        
        self.logger.debug(f"URL Filtering Results: {len(urls)} total, "
                         f"{len(categorized['priority'])} priority, "
                         f"{len(categorized['normal'])} normal, "
                         f"{len(categorized['problematic'])} problematic, "
                         f"{len(categorized['excluded'])} excluded")
        
        return filtered_urls, categorized
    
    def _is_in_scope(self, hostname: str, domain: str) -> bool:
        """Check if hostname is in scope for the target domain."""
        # Normalize
        hostname = hostname.lower().strip()
        domain = domain.lower().strip()
        
        # Remove port if present
        hostname = hostname.split(':')[0]
        domain = domain.split(':')[0]
        
        # Remove www prefix for comparison
        hostname_no_www = hostname.replace('www.', '', 1)
        domain_no_www = domain.replace('www.', '', 1)
        
        # Exact match (with or without www)
        if hostname == domain or hostname_no_www == domain_no_www:
            return True
        
        # Check if hostname is subdomain of domain
        if hostname.endswith(f'.{domain}') or hostname_no_www.endswith(f'.{domain_no_www}'):
            return True
        
        # Check if domain is subdomain of hostname (for cases like qa.example.com being the target)
        if domain.endswith(f'.{hostname}') or domain_no_www.endswith(f'.{hostname_no_www}'):
            return True
        
        # Special case: if target domain itself is a subdomain, be more flexible
        if '.' in domain_no_www:
            # Extract parent domain
            parts = domain_no_www.split('.')
            if len(parts) >= 2:
                parent_domain = '.'.join(parts[-2:])  # Get last two parts (e.g., example.com)
                
                # Check if hostname is under parent domain
                if hostname_no_www == parent_domain or hostname_no_www.endswith(f'.{parent_domain}'):
                    return True
        
        return False
    
    def get_prioritized_urls(self, domain: str) -> Dict[str, List[str]]:
        """Get URLs categorized by priority for a domain."""
        return self.categorized_urls.get(domain, {})
    
    def save_results(self, output_file: str):
        """
        Save discovered URLs to a file.
        
        Args:
            output_file: Path to output file
        """
        try:
            # Prepare data
            data = {
                'timestamp': datetime.now().isoformat(),
                'total_urls': sum(len(urls) for urls in self.discovered_urls.values()),
                'domains': self.discovered_urls,
                'categorized': dict(self.categorized_urls),
                'statistics': self.get_statistics(),
                'discovery_stats': dict(self.discovery_stats),
                'errors': self.errors
            }
            
            # Determine format from extension
            output_path = Path(output_file)
            
            if output_path.suffix == '.json':
                # Save as JSON
                with open(output_file, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                # Save as plain text (URLs only)
                with open(output_file, 'w') as f:
                    # Write priority URLs first
                    for domain, categorized in self.categorized_urls.items():
                        f.write(f"# Domain: {domain}\n")
                        
                        # Write discovery statistics
                        if domain in self.discovery_stats:
                            stats = self.discovery_stats[domain]
                            f.write(f"# Total URLs: {stats.get('total_urls', 0)}\n")
                            f.write(f"# Passive: {stats.get('passive_urls', 0)} ")
                            f.write(f"({stats.get('passive_duration', 0):.2f}s)\n")
                            f.write(f"# Active: {stats.get('active_urls', 0)} ")
                            f.write(f"({stats.get('active_duration', 0):.2f}s)\n")
                            f.write(f"# Overlap: {stats.get('overlap', 0)}\n\n")
                        
                        if categorized.get('priority'):
                            f.write("## Priority URLs\n")
                            for url in categorized['priority']:
                                f.write(f"{url}\n")
                        
                        if categorized.get('normal'):
                            f.write("\n## Normal URLs\n")
                            for url in categorized['normal']:
                                f.write(f"{url}\n")
                        
                        f.write("\n")
            
            self.logger.info(f"Results saved to: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            raise
    
    def get_statistics(self) -> Dict:
        """Get statistics about discovered URLs."""
        stats = {
            'total_domains': len(self.discovered_urls),
            'total_urls': sum(len(urls) for urls in self.discovered_urls.values()),
            'urls_per_domain': {},
            'categorized_counts': {},
            'errors_count': len(self.errors),
            'tools_used': {
                'passive': {
                    'gau': self.enable_gau,
                    'waybackurls': self.enable_waybackurls,
                    'wayurls': self.enable_wayurls
                },
                'active': {
                    'katana': self.enable_katana,
                    'katana_headless': self.katana_headless,
                    'katana_js_crawl': self.katana_js_crawl
                }
            }
        }
        
        for domain, urls in self.discovered_urls.items():
            stats['urls_per_domain'][domain] = len(urls)
            
            if domain in self.categorized_urls:
                stats['categorized_counts'][domain] = {
                    category: len(urls)
                    for category, urls in self.categorized_urls[domain].items()
                }
        
        return stats