"""
Enhanced Static Content Fetcher with URL-based Filename Support

Key improvements:
1. URL-based filename support from main scanner
2. Better error handling and retry logic
3. Smart content type detection
4. Enhanced JavaScript extraction
5. Better handling of different response types
6. Improved performance with connection pooling
"""

import os
import time
import hashlib
import mimetypes
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Set
from urllib.parse import urlparse, urljoin
import logging
import json
import re
from collections import defaultdict

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
import jsbeautifier
import chardet

# Suppress SSL warnings if needed
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class StaticFetcher:
    """Enhanced static content fetcher with URL-based filename support."""
    
    def __init__(self, config: Dict, logger: Optional[logging.Logger] = None):
        """
        Initialize Static Fetcher.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # URL to filename mapping (set by content fetcher)
        self.url_filename_map = {}
        
        # Configuration
        self.timeout = config.get('timeout', 30000) / 1000  # Convert to seconds
        self.max_retries = config.get('max_retries', 3)
        self.user_agent = config.get('user_agent', 
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
        self.verify_ssl = config.get('verify_ssl_certificates', True)
        self.max_file_size = config.get('scan_file_size_limit', 10 * 1024 * 1024)  # 10MB
        self.beautify_js = config.get('beautify_javascript', True)
        self.follow_redirects = config.get('follow_redirects', True)
        self.max_redirects = config.get('max_redirects', 10)
        
        # Headers configuration
        self.default_headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,application/javascript,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Session setup with connection pooling
        self.session = self._create_session()
        
        # Content type handlers
        self.content_handlers = {
            'text/html': self._handle_html_response,
            'application/javascript': self._handle_javascript_response,
            'text/javascript': self._handle_javascript_response,
            'application/x-javascript': self._handle_javascript_response,
            'application/json': self._handle_json_response,
            'text/plain': self._handle_text_response,
            'application/xml': self._handle_xml_response,
            'text/xml': self._handle_xml_response
        }
        
        # JavaScript patterns for detection
        self.js_patterns = [
            re.compile(r'\.js$', re.IGNORECASE),
            re.compile(r'\.js[?#]', re.IGNORECASE),
            re.compile(r'/js/', re.IGNORECASE),
            re.compile(r'/javascript/', re.IGNORECASE),
            re.compile(r'/static/.*\.js', re.IGNORECASE),
            re.compile(r'/assets/.*\.js', re.IGNORECASE),
            re.compile(r'/dist/.*\.js', re.IGNORECASE),
            re.compile(r'/build/.*\.js', re.IGNORECASE)
        ]
        
        # Statistics
        self.stats = {
            'requests_made': 0,
            'successful': 0,
            'failed': 0,
            'timeouts': 0,
            'size_exceeded': 0,
            'ssl_errors': 0,
            'content_types': defaultdict(int)
        }
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with enhanced retry logic and connection pooling."""
        session = requests.Session()
        
        # Enhanced retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST"],
            respect_retry_after_header=True,
            raise_on_status=False
        )
        
        # Adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20,
            pool_block=False
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update(self.default_headers)
        
        # Custom headers from environment
        custom_headers = os.getenv('CUSTOM_HEADERS')
        if custom_headers:
            try:
                headers = json.loads(custom_headers)
                session.headers.update(headers)
            except json.JSONDecodeError:
                self.logger.warning("Failed to parse custom headers")
        
        # Proxy configuration
        proxy_url = self.config.get('proxy_url')
        if proxy_url:
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            session.proxies.update(proxies)
            self.logger.info(f"Using proxy: {proxy_url}")
        
        return session
    
    def fetch_url_with_filename(self, url: str, output_dir: str, filename: str) -> bool:
        """
        Fetch content from a URL using a specific filename.
        
        Args:
            url: URL to fetch
            output_dir: Directory to save content
            filename: Specific filename to use
            
        Returns:
            True if successful, False otherwise
        """
        # Temporarily store the filename mapping
        self.url_filename_map[url] = filename
        result = self.fetch_url(url, output_dir)
        # Clean up temporary mapping
        del self.url_filename_map[url]
        return result
    
    def fetch_url(self, url: str, output_dir: str) -> bool:
        """
        Fetch content from a single URL with enhanced error handling.
        
        Args:
            url: URL to fetch
            output_dir: Directory to save content
            
        Returns:
            True if successful, False otherwise
        """
        self.stats['requests_made'] += 1
        start_time = time.time()
        
        try:
            self.logger.debug(f"Fetching: {url}")
            
            # Make request with streaming for large files
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=self.follow_redirects,
                stream=True
            )
            
            # Log response details
            self.logger.debug(f"Response: {response.status_code} for {url}")
            
            # Check response status
            if response.status_code >= 400:
                self.logger.warning(f"HTTP {response.status_code} for {url}")
                if response.status_code == 404:
                    self._save_error(url, output_dir, f"404 Not Found", response.status_code)
                elif response.status_code == 403:
                    self._save_error(url, output_dir, f"403 Forbidden", response.status_code)
                else:
                    self._save_error(url, output_dir, f"HTTP {response.status_code}", response.status_code)
                self.stats['failed'] += 1
                return False
            
            # Check content size
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > self.max_file_size:
                self.logger.warning(f"Content too large: {url} ({content_length} bytes)")
                self.stats['size_exceeded'] += 1
                self._save_error(url, output_dir, f"Content too large: {content_length} bytes", None)
                return False
            
            # Read content with size limit
            content = b''
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > self.max_file_size:
                    self.logger.warning(f"Content exceeded size limit while downloading: {url}")
                    self.stats['size_exceeded'] += 1
                    self._save_error(url, output_dir, f"Content exceeded {self.max_file_size} bytes", None)
                    return False
            
            # Detect content type and encoding
            content_type = response.headers.get('content-type', '').lower()
            encoding = response.encoding
            
            # If no encoding specified, try to detect it
            if not encoding or encoding == 'ISO-8859-1':
                detected = chardet.detect(content)
                if detected['confidence'] > 0.7:
                    encoding = detected['encoding']
            
            # Process based on content type
            success = self._process_response(url, content, content_type, encoding, response, output_dir)
            
            if success:
                self.stats['successful'] += 1
                self.stats['content_types'][content_type.split(';')[0]] += 1
                
                # Log timing
                duration = time.time() - start_time
                self.logger.debug(f"Successfully fetched {url} in {duration:.2f}s")
            else:
                self.stats['failed'] += 1
            
            return success
            
        except requests.exceptions.Timeout:
            self.logger.warning(f"Timeout fetching: {url}")
            self.stats['timeouts'] += 1
            self._save_error(url, output_dir, "Timeout", None)
            return False
            
        except requests.exceptions.SSLError as e:
            self.logger.warning(f"SSL error for {url}: {e}")
            self.stats['ssl_errors'] += 1
            self._save_error(url, output_dir, f"SSL Error: {str(e)}", None)
            return False
            
        except requests.exceptions.ConnectionError as e:
            self.logger.warning(f"Connection error for {url}: {e}")
            self.stats['failed'] += 1
            self._save_error(url, output_dir, f"Connection Error: {str(e)}", None)
            return False
            
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Request failed for {url}: {e}")
            self.stats['failed'] += 1
            self._save_error(url, output_dir, f"Request Error: {str(e)}", None)
            return False
            
        except Exception as e:
            self.logger.error(f"Unexpected error fetching {url}: {e}")
            self.stats['failed'] += 1
            self._save_error(url, output_dir, f"Unexpected Error: {str(e)}", None)
            return False
    
    def _process_response(self, url: str, content: bytes, content_type: str, 
                         encoding: str, response: requests.Response, output_dir: str) -> bool:
        """Process response based on content type."""
        try:
            # Clean content type
            main_type = content_type.split(';')[0].strip()
            
            # Check if URL appears to be JavaScript regardless of content type
            is_js_url = any(pattern.search(url) for pattern in self.js_patterns)
            
            # Try specific handler first
            if main_type in self.content_handlers:
                return self.content_handlers[main_type](url, content, encoding, response, output_dir)
            
            # If URL looks like JS but has different content type
            elif is_js_url:
                self.logger.debug(f"URL appears to be JavaScript despite content-type: {content_type}")
                return self._handle_javascript_response(url, content, encoding, response, output_dir)
            
            # Try to detect content type from content
            else:
                detected_type = self._detect_content_type(content, url)
                if detected_type and detected_type in self.content_handlers:
                    self.logger.debug(f"Detected content type: {detected_type}")
                    return self.content_handlers[detected_type](url, content, encoding, response, output_dir)
                
                # Default to text handling
                return self._handle_text_response(url, content, encoding, response, output_dir)
                
        except Exception as e:
            self.logger.error(f"Error processing response for {url}: {e}")
            return False
    
    def _detect_content_type(self, content: bytes, url: str) -> Optional[str]:
        """Detect content type from content."""
        try:
            # Try to decode first part
            sample = content[:1000].decode('utf-8', errors='ignore').lower()
            
            # HTML detection
            if any(tag in sample for tag in ['<!doctype html', '<html', '<head', '<body']):
                return 'text/html'
            
            # JavaScript detection
            js_indicators = ['function', 'var ', 'let ', 'const ', 'return ', '=>', 'require(', 'import ']
            if any(indicator in sample for indicator in js_indicators):
                return 'application/javascript'
            
            # JSON detection
            if sample.strip().startswith(('{', '[')):
                try:
                    json.loads(content.decode('utf-8', errors='ignore'))
                    return 'application/json'
                except:
                    pass
            
            # XML detection
            if sample.strip().startswith('<?xml') or '<' in sample and '>' in sample:
                return 'application/xml'
            
        except:
            pass
        
        return None
    
    def _handle_html_response(self, url: str, content: bytes, encoding: str, 
                             response: requests.Response, output_dir: str) -> bool:
        """Handle HTML response."""
        try:
            # Decode content
            text = content.decode(encoding or 'utf-8', errors='replace')
            
            # Save HTML
            html_path = self._get_output_path(url, output_dir, 'html', '.html')
            html_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(text)
            
            # Extract and save inline scripts
            inline_scripts = self._extract_inline_scripts(text)
            if inline_scripts:
                self._save_inline_scripts(url, inline_scripts, output_dir)
            
            # Extract JavaScript URLs
            js_urls = self._extract_javascript_urls(text, url)
            
            # Save metadata
            self._save_metadata(url, output_dir, {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(content),
                'encoding': encoding,
                'js_urls': js_urls,
                'inline_scripts_count': len(inline_scripts),
                'content_type': 'text/html'
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to handle HTML from {url}: {e}")
            return False
    
    def _handle_javascript_response(self, url: str, content: bytes, encoding: str,
                                   response: requests.Response, output_dir: str) -> bool:
        """Handle JavaScript response."""
        try:
            # Decode content
            text = content.decode(encoding or 'utf-8', errors='replace')
            
            # Beautify if configured
            if self.beautify_js:
                try:
                    options = {
                        'indent_size': 2,
                        'indent_char': ' ',
                        'max_preserve_newlines': 2,
                        'preserve_newlines': True,
                        'keep_array_indentation': False,
                        'break_chained_methods': False,
                        'indent_scripts': 'normal',
                        'brace_style': 'collapse',
                        'space_before_conditional': True,
                        'unescape_strings': False,
                        'wrap_line_length': 0,
                        'wrap_attributes': 'auto',
                        'wrap_attributes_indent_size': 2
                    }
                    text = jsbeautifier.beautify(text, options)
                except Exception as e:
                    self.logger.debug(f"Failed to beautify JS from {url}: {e}")
            
            # Save JavaScript
            js_path = self._get_output_path(url, output_dir, 'js', '.js')
            js_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(js_path, 'w', encoding='utf-8') as f:
                f.write(text)
            
            # Extract interesting patterns from JS
            patterns_found = self._extract_js_patterns(text)
            
            # Save metadata
            self._save_metadata(url, output_dir, {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(content),
                'encoding': encoding,
                'content_type': 'application/javascript',
                'beautified': self.beautify_js,
                'patterns_found': patterns_found
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to handle JavaScript from {url}: {e}")
            return False
    
    def _handle_json_response(self, url: str, content: bytes, encoding: str,
                             response: requests.Response, output_dir: str) -> bool:
        """Handle JSON response."""
        try:
            # Decode and parse JSON
            text = content.decode(encoding or 'utf-8', errors='replace')
            
            # Try to parse and pretty-print
            try:
                data = json.loads(text)
                text = json.dumps(data, indent=2, ensure_ascii=False)
            except json.JSONDecodeError:
                # If not valid JSON, save as-is
                pass
            
            # Save JSON
            json_path = self._get_output_path(url, output_dir, 'json', '.json')
            json_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(json_path, 'w', encoding='utf-8') as f:
                f.write(text)
            
            # Save metadata
            self._save_metadata(url, output_dir, {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(content),
                'encoding': encoding,
                'content_type': 'application/json',
                'valid_json': True
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to handle JSON from {url}: {e}")
            return False
    
    def _handle_text_response(self, url: str, content: bytes, encoding: str,
                             response: requests.Response, output_dir: str) -> bool:
        """Handle plain text response."""
        try:
            # Decode content
            text = content.decode(encoding or 'utf-8', errors='replace')
            
            # Determine file extension
            ext = self._guess_extension(url, response.headers.get('content-type', ''))
            
            # Save text
            text_path = self._get_output_path(url, output_dir, 'other', ext)
            text_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write(text)
            
            # Save metadata
            self._save_metadata(url, output_dir, {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(content),
                'encoding': encoding,
                'content_type': response.headers.get('content-type', 'text/plain')
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to handle text from {url}: {e}")
            return False
    
    def _handle_xml_response(self, url: str, content: bytes, encoding: str,
                            response: requests.Response, output_dir: str) -> bool:
        """Handle XML response."""
        return self._handle_text_response(url, content, encoding, response, output_dir)
    
    def _extract_inline_scripts(self, html: str) -> List[Dict]:
        """Extract inline scripts from HTML with context."""
        scripts = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for i, script in enumerate(soup.find_all('script', src=False)):
                script_content = script.get_text(strip=True)
                
                # Skip empty or very short scripts
                if script_content and len(script_content) > 10:
                    # Get script attributes
                    attrs = dict(script.attrs) if script.attrs else {}
                    
                    # Check for interesting patterns
                    has_secrets = any(pattern in script_content.lower() for pattern in 
                                    ['api', 'key', 'token', 'secret', 'password', 'auth'])
                    
                    scripts.append({
                        'content': script_content,
                        'index': i,
                        'length': len(script_content),
                        'attributes': attrs,
                        'has_potential_secrets': has_secrets
                    })
                    
        except Exception as e:
            self.logger.debug(f"Error extracting inline scripts: {e}")
        
        return scripts
    
    def _save_inline_scripts(self, url: str, scripts: List[Dict], output_dir: str):
        """Save inline scripts to separate files."""
        for script in scripts:
            try:
                # Beautify if configured
                content = script['content']
                if self.beautify_js:
                    try:
                        content = jsbeautifier.beautify(content)
                    except:
                        pass
                
                # Get base filename for inline scripts
                if url in self.url_filename_map:
                    base_filename = Path(self.url_filename_map[url]).stem
                    script_filename = f"{base_filename}_inline_{script['index']}.js"
                else:
                    # Fallback to hash-based name
                    script_filename = None
                
                # Save inline script
                script_path = self._get_output_path(
                    url, output_dir, 'inline-scripts', 
                    f'_inline_{script["index"]}.js',
                    override_filename=script_filename
                )
                script_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(script_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Save script metadata
                meta_path = script_path.with_suffix('.meta.json')
                with open(meta_path, 'w') as f:
                    json.dump({
                        'source_url': url,
                        'index': script['index'],
                        'length': script['length'],
                        'attributes': script['attributes'],
                        'has_potential_secrets': script['has_potential_secrets']
                    }, f, indent=2)
                    
            except Exception as e:
                self.logger.debug(f"Failed to save inline script {script['index']}: {e}")
    
    def _extract_javascript_urls(self, html: str, base_url: str) -> List[str]:
        """Extract JavaScript URLs from HTML."""
        js_urls = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find script tags with src
            for script in soup.find_all('script', src=True):
                js_url = urljoin(base_url, script['src'])
                js_urls.append(js_url)
            
            # Find data-src attributes (lazy loading)
            for element in soup.find_all(attrs={'data-src': True}):
                src = element.get('data-src', '')
                if src and any(pattern in src for pattern in ['.js', '/js/', 'javascript']):
                    js_url = urljoin(base_url, src)
                    js_urls.append(js_url)
            
            # Look for JavaScript in link preload/prefetch
            for link in soup.find_all('link', rel=['preload', 'prefetch']):
                href = link.get('href', '')
                if href and '.js' in href:
                    js_url = urljoin(base_url, href)
                    js_urls.append(js_url)
                    
        except Exception as e:
            self.logger.debug(f"Failed to extract JS URLs: {e}")
        
        return list(set(js_urls))  # Remove duplicates
    
    def _extract_js_patterns(self, js_content: str) -> Dict[str, int]:
        """Extract interesting patterns from JavaScript content."""
        patterns = {
            'api_endpoints': len(re.findall(r'["\']/(api|v\d+)/[^"\']*["\']', js_content)),
            'potential_keys': len(re.findall(r'["\'][\w-]{20,}["\']', js_content)),
            'urls': len(re.findall(r'https?://[^\s"\']+', js_content)),
            'base64': len(re.findall(r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']', js_content)),
            'config_objects': len(re.findall(r'config\s*[=:]\s*{', js_content, re.IGNORECASE)),
            'environment_vars': len(re.findall(r'process\.env\.\w+', js_content))
        }
        
        return patterns
    
    def _save_metadata(self, url: str, output_dir: str, metadata: Dict):
        """Save metadata for a fetched URL."""
        try:
            metadata.update({
                'url': url,
                'timestamp': time.time(),
                'fetcher': 'static',
                'fetcher_version': '2.0'
            })
            
            # Get metadata filename
            if url in self.url_filename_map:
                base_filename = Path(self.url_filename_map[url]).stem
                meta_filename = f"{base_filename}_meta.json"
            else:
                meta_filename = None
            
            metadata_path = self._get_output_path(
                url, output_dir, 'metadata', '.json',
                override_filename=meta_filename
            )
            metadata_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
                
        except Exception as e:
            self.logger.debug(f"Failed to save metadata for {url}: {e}")
    
    def _save_error(self, url: str, output_dir: str, error_message: str, status_code: Optional[int]):
        """Save error information for failed URL."""
        try:
            error_data = {
                'url': url,
                'error': error_message,
                'status_code': status_code,
                'timestamp': time.time(),
                'fetcher': 'static'
            }
            
            # Get error filename
            if url in self.url_filename_map:
                base_filename = Path(self.url_filename_map[url]).stem
                error_filename = f"{base_filename}_error.json"
            else:
                error_filename = None
            
            error_path = self._get_output_path(
                url, output_dir, 'errors', '.json',
                override_filename=error_filename
            )
            error_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(error_path, 'w') as f:
                json.dump(error_data, f, indent=2)
                
        except Exception as e:
            self.logger.debug(f"Failed to save error for {url}: {e}")
    
    def _get_output_path(self, url: str, output_dir: str, subdir: str, 
                        extension: str, override_filename: Optional[str] = None) -> Path:
        """Generate output path for a URL using URL-based filename if available."""
        # Check if we have a URL-based filename
        if url in self.url_filename_map:
            filename = self.url_filename_map[url]
            
            # Ensure correct extension
            if not filename.endswith(extension) and extension:
                # Remove existing extension if any
                base = filename.rsplit('.', 1)[0]
                filename = base + extension
            
            return Path(output_dir) / subdir / filename
        
        # Check for override filename (for inline scripts, metadata, etc.)
        if override_filename:
            return Path(output_dir) / subdir / override_filename
        
        # Fallback to hash-based filename
        url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()
        
        # Try to create meaningful filename
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split('/') if p]
        
        if path_parts:
            last_part = path_parts[-1]
            # Remove extension from last part if present
            if '.' in last_part:
                base = Path(last_part).stem
            else:
                base = last_part
            # Sanitize for filesystem
            base = re.sub(r'[^\w\-_]', '_', base)[:50]  # Limit length
            filename = f"{base}_{url_hash[:8]}{extension}"
        else:
            filename = f"{parsed.netloc.replace('.', '_')}_{url_hash[:8]}{extension}"
        
        return Path(output_dir) / subdir / filename
    
    def _guess_extension(self, url: str, content_type: str) -> str:
        """Guess file extension from URL or content type."""
        # Try from URL first
        parsed_path = urlparse(url).path
        if '.' in parsed_path:
            ext = Path(parsed_path).suffix
            if ext and len(ext) <= 5:  # Reasonable extension length
                return ext
        
        # Try from content type
        if content_type:
            ext = mimetypes.guess_extension(content_type.split(';')[0])
            if ext:
                return ext
        
        # Default
        return '.txt'
    
    def get_statistics(self) -> Dict:
        """Get fetching statistics."""
        total = self.stats['requests_made']
        success_rate = (self.stats['successful'] / total * 100) if total > 0 else 0
        
        return {
            **self.stats,
            'success_rate': round(success_rate, 2),
            'average_success_time': self._calculate_average_success_time()
        }
    
    def _calculate_average_success_time(self) -> float:
        """Calculate average time for successful requests."""
        # This would require tracking times, simplified for now
        return 0.0