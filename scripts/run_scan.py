#!/usr/bin/env python3
"""
Enhanced Automated Secrets Scanner - Main Entry Point

Key improvements:
1. Integration with .env configuration and config_helper
2. Support for Katana in URL discovery
3. Better error handling and recovery
4. Progress monitoring
5. Scan resumption capability
6. Enhanced reporting
7. Performance optimizations
"""

import os
import sys
import json
import time
import argparse
import logging
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import subprocess
import yaml
from dotenv import load_dotenv
import signal
import threading
import shutil
import hashlib

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Add scripts directory to path for config_helper
sys.path.insert(0, str(PROJECT_ROOT / 'scripts'))

# Import config helper
try:
    from config_helper import ConfigHelper
except ImportError:
    print("Warning: config_helper.py not found. Using basic configuration.")
    ConfigHelper = None

# Import modules
from modules.url_discovery.discovery import URLDiscovery
from modules.content_fetcher.fetcher import ContentFetcher
from modules.secret_scanner.scanner_wrapper import SecretScanner
from modules.validator.auto_validator import AutoValidator as SecretValidator
from modules.reporter.html_generator import HTMLReportGenerator as HTMLReporter
from modules.reporter.slack_notifier import SlackNotifier

# Load environment variables
load_dotenv(override=True)

# Configure logging
from loguru import logger


class SecretsScanner:
    """Enhanced main orchestrator for the secrets scanning pipeline."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the scanner with configuration."""
        # Initialize configuration using config helper
        self._initialize_configuration()
        
        self.config = self._load_config(config_path)
        self.scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"
        self.start_time = time.time()
        
        # Setup logging
        self._setup_logging()
        
        # Initialize components
        self.url_discovery = None
        self.content_fetcher = None
        self.secret_scanner = None
        self.validator = None
        self.html_reporter = None
        self.slack_notifier = None
        
        # Progress tracking
        self.progress = {
            'current_phase': 'initialization',
            'phases_completed': [],
            'current_progress': 0,
            'total_progress': 100,
            'status': 'starting'
        }
        
        # Scan state for resumption
        self.scan_state_file = Path(self.config['data_storage_path']) / 'scans' / 'state' / f'{self.scan_id}_state.json'
        self.scan_state = {
            'scan_id': self.scan_id,
            'start_time': datetime.now().isoformat(),
            'phases': {
                'url_discovery': {'status': 'pending', 'data': {}},
                'content_fetching': {'status': 'pending', 'data': {}},
                'secret_scanning': {'status': 'pending', 'data': {}},
                'validation': {'status': 'pending', 'data': {}},
                'reporting': {'status': 'pending', 'data': {}}
            }
        }
        
        # Results storage
        self.results = {
            'scan_id': self.scan_id,
            'start_time': datetime.now().isoformat(),
            'domains': [],
            'urls_discovered': 0,
            'urls_by_category': {},
            'content_fetched': 0,
            'content_fetch_failed': 0,
            'raw_secrets_found': 0,
            'validated_secrets': 0,
            'new_secrets': 0,
            'errors': [],
            'warnings': [],
            'performance_metrics': {}
        }
        
        # Signal handlers for graceful shutdown
        self._setup_signal_handlers()
        
        logger.info(f"Initialized enhanced scanner with ID: {self.scan_id}")
    
    def _initialize_configuration(self):
        """Initialize configuration using config helper."""
        if ConfigHelper:
            try:
                # Validate environment
                if not ConfigHelper.validate_env():
                    logger.warning("Configuration validation failed - using defaults")
                
                # Generate runtime config
                ConfigHelper.write_runtime_config()
                logger.info("Runtime configuration generated successfully")
                
                # Load runtime config
                runtime_config_path = Path('./config/runtime_config.json')
                if runtime_config_path.exists():
                    with open(runtime_config_path) as f:
                        self.runtime_config = json.load(f)
                else:
                    self.runtime_config = {}
            except Exception as e:
                logger.warning(f"Failed to initialize configuration with helper: {e}")
                self.runtime_config = {}
        else:
            self.runtime_config = {}
    
    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from file or environment."""
        config = {
            # Default configuration
            'scan_depth': 3,
            'concurrent_requests': 5,
            'timeout': 30000,
            'enable_validation': True,
            'enable_trufflehog': True,
            'enable_gitleaks': True,
            'enable_custom_patterns': True,
            'use_static_fallback': True,
            'include_problematic_urls': False,
            'crawler_batch_size': 50,
            'max_urls_per_domain': 10000,
            'scan_file_size_limit': 10 * 1024 * 1024,
            'entropy_threshold': 4.0,
            'min_secret_length': 8,
            'verify_secrets': True,
            'save_intermediate_results': True,
            'enable_progress_monitoring': True,
            # Katana settings
            'enable_katana': True,
            'katana_headless': True,
            'katana_depth': 3,
            'katana_js_crawl': True,
            'katana_timeout': 10000,
            'katana_parallelism': 10
        }
        
        # Load from file if provided
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f) or {}
                config.update(file_config)
        
        # Override with environment variables - Updated mapping
        env_mapping = {
            # Basic settings
            'SCAN_DEPTH': ('scan_depth', int),
            'CONCURRENT_REQUESTS': ('concurrent_requests', int),
            'SCAN_TIMEOUT': ('timeout', int),
            'ENABLE_VALIDATION': ('enable_validation', lambda x: x.lower() == 'true'),
            'ENABLE_AUTO_VALIDATION': ('enable_validation', lambda x: x.lower() == 'true'),
            
            # Tool settings
            'ENABLE_TRUFFLEHOG': ('enable_trufflehog', lambda x: x.lower() == 'true'),
            'ENABLE_GITLEAKS': ('enable_gitleaks', lambda x: x.lower() == 'true'),
            'ENABLE_CUSTOM_PATTERNS': ('enable_custom_patterns', lambda x: x.lower() == 'true'),
            
            # Katana settings
            'ENABLE_KATANA': ('enable_katana', lambda x: x.lower() == 'true'),
            'KATANA_HEADLESS': ('katana_headless', lambda x: x.lower() == 'true'),
            'KATANA_DEPTH': ('katana_depth', int),
            'KATANA_JS_CRAWL': ('katana_js_crawl', lambda x: x.lower() == 'true'),
            'KATANA_TIMEOUT': ('katana_timeout', int),
            'KATANA_PARALLELISM': ('katana_parallelism', int),
            
            # URL discovery
            'ENABLE_GAU': ('enable_gau', lambda x: x.lower() == 'true'),
            'ENABLE_WAYBACKURLS': ('enable_waybackurls', lambda x: x.lower() == 'true'),
            'ENABLE_WAYURLS': ('enable_wayurls', lambda x: x.lower() == 'true'),
            'MAX_URLS_PER_DOMAIN': ('max_urls_per_domain', int),
            
            # Paths and URLs
            'SLACK_WEBHOOK_URL': ('slack_webhook_url', str),
            'RAW_SECRETS_PATH': ('raw_secrets_path', str),
            'DATA_STORAGE_PATH': ('data_storage_path', str),
            'REPORTS_PATH': ('reports_path', str),
            'BASELINE_FILE': ('baseline_file', str),
            
            # Logging
            'LOG_LEVEL': ('log_level', str),
            'LOG_FILE_PATH': ('log_file_path', str),
            
            # Features
            'DRY_RUN': ('dry_run', lambda x: x.lower() == 'true'),
            'CRAWLER_BATCH_SIZE': ('crawler_batch_size', int),
            'VERIFY_SECRETS': ('verify_secrets', lambda x: x.lower() == 'true'),
            'INCLUDE_PROBLEMATIC_URLS': ('include_problematic_urls', lambda x: x.lower() == 'true'),
            'USE_STATIC_FALLBACK': ('use_static_fallback', lambda x: x.lower() == 'true'),
            'SAVE_INTERMEDIATE_RESULTS': ('save_intermediate_results', lambda x: x.lower() == 'true'),
            'ENABLE_PROGRESS_MONITORING': ('enable_progress_monitoring', lambda x: x.lower() == 'true'),
            
            # Scanning settings
            'ENTROPY_THRESHOLD': ('entropy_threshold', float),
            'MIN_SECRET_LENGTH': ('min_secret_length', int),
            'MAX_SECRET_LENGTH': ('max_secret_length', int),
            'SCAN_FILE_SIZE_LIMIT': ('scan_file_size_limit', int),
            
            # Performance
            'MAX_WORKERS': ('max_workers', int),
            'REQUESTS_PER_SECOND': ('requests_per_second', int),
            
            # Slack settings
            'ENABLE_SLACK': ('enable_slack', lambda x: x.lower() == 'true'),
            'SLACK_CHANNEL': ('slack_channel', str),
            'SLACK_USERNAME': ('slack_username', str),
            'SLACK_ALERT_ON_CRITICAL': ('alert_on_critical', lambda x: x.lower() == 'true'),
            'SLACK_ALERT_ON_HIGH': ('alert_on_high', lambda x: x.lower() == 'true'),
            'SLACK_ALERT_ON_MEDIUM': ('alert_on_medium', lambda x: x.lower() == 'true'),
            'SLACK_ALERT_ON_LOW': ('alert_on_low', lambda x: x.lower() == 'true'),
        }
        
        for env_key, (config_key, converter) in env_mapping.items():
            env_value = os.getenv(env_key)
            if env_value is not None:
                try:
                    config[config_key] = converter(env_value)
                except Exception as e:
                    logger.warning(f"Failed to convert {env_key}={env_value}: {e}")
        
        # Set default paths if not specified
        if 'data_storage_path' not in config:
            config['data_storage_path'] = os.getenv('DATA_STORAGE_PATH', './data')
        
        if 'raw_secrets_path' not in config:
            config['raw_secrets_path'] = os.getenv('RAW_SECRETS_PATH', 
                                                   os.path.join(config['data_storage_path'], 'scans', 'raw'))
        
        if 'reports_path' not in config:
            config['reports_path'] = os.getenv('REPORTS_PATH',
                                              os.path.join(config['data_storage_path'], 'reports'))
        
        if 'baseline_file' not in config:
            config['baseline_file'] = os.getenv('BASELINE_FILE',
                                               os.path.join(config['data_storage_path'], 'baselines', 'baseline_secrets.json'))
        
        # Add runtime config values
        if self.runtime_config:
            # Browser args
            if 'browser_args' in self.runtime_config:
                config['browser_args'] = self.runtime_config['browser_args']
            
            # File extensions
            if 'scan_file_extensions' in self.runtime_config:
                config['scan_file_extensions'] = self.runtime_config['scan_file_extensions']
            
            # Security settings
            if 'security' in self.runtime_config:
                config['blocked_domains'] = self.runtime_config['security'].get('blocked_domains', [])
                config['allowed_domains'] = self.runtime_config['security'].get('allowed_domains', [])
            
            # URL patterns
            if 'url_patterns' in self.runtime_config:
                config['url_exclude_patterns'] = self.runtime_config['url_patterns'].get('exclude', [])
                config['url_priority_patterns'] = self.runtime_config['url_patterns'].get('priority', [])
        
        return config
    
    def _setup_logging(self):
        """Configure enhanced logging with loguru."""
        log_level = self.config.get('log_level', os.getenv('LOG_LEVEL', 'INFO'))
        log_path = Path(self.config.get('log_file_path', os.getenv('LOG_FILE_PATH', './logs')))
        log_path.mkdir(parents=True, exist_ok=True)
        
        # Remove default logger
        logger.remove()
        
        # Console logging with color and progress
        logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
            level=log_level,
            colorize=True,
            filter=lambda record: "progress" not in record["extra"]
        )
        
        # File logging with rotation
        logger.add(
            log_path / f"scanner_{self.scan_id}.log",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            level="DEBUG",
            rotation="100 MB",
            retention="30 days",
            compression="zip",
            enqueue=True
        )
        
        # Separate progress log
        if self.config.get('enable_progress_monitoring'):
            logger.add(
                log_path / f"progress_{self.scan_id}.log",
                format="{time:YYYY-MM-DD HH:mm:ss} | PROGRESS | {message}",
                filter=lambda record: "progress" in record["extra"],
                level="INFO"
            )
        
        # Error logging with full diagnostics
        logger.add(
            log_path / "errors.log",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            level="ERROR",
            rotation="50 MB",
            retention="90 days",
            backtrace=True,
            diagnose=True
        )
        
        logger.info("Enhanced logging configured successfully")
        logger.info(f"Environment: {os.getenv('APP_ENV', 'production')}")
        logger.info(f"Debug mode: {self.config.get('debug', False)}")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            logger.warning(f"Received signal {signum}, initiating graceful shutdown...")
            self._save_scan_state()
            self.results['status'] = 'interrupted'
            self.results['interrupt_reason'] = f'Signal {signum}'
            
            # Send notification if configured
            if self.slack_notifier and self.config.get('enable_slack'):
                self.slack_notifier.send_message(
                    f"Scan {self.scan_id} interrupted by signal {signum}",
                    severity='warning'
                )
            
            sys.exit(1)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _initialize_components(self):
        """Initialize all scanner components with error handling."""
        try:
            logger.info("Initializing scanner components...")
            
            # URL Discovery
            self.url_discovery = URLDiscovery(
                config=self.config,
                logger=logger
            )
            
            # Content Fetcher
            self.content_fetcher = ContentFetcher(
                config=self.config,
                logger=logger
            )
            
            # Secret Scanner
            self.secret_scanner = SecretScanner(
                config=self.config,
                logger=logger
            )
            
            # Validator
            if self.config.get('enable_validation'):
                self.validator = SecretValidator(self.config)
            
            # Reporters
            self.html_reporter = HTMLReporter(self.config)
            
            if self.config.get('slack_webhook_url') and self.config.get('enable_slack', True):
                self.slack_notifier = SlackNotifier(self.config)
            
            logger.info("All components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {str(e)}")
            logger.exception(e)
            raise
    
    def _phase_url_discovery(self, domains: List[str], scan_type: str) -> Tuple[List[str], Dict]:
        """Phase 1: Discover URLs for the given domains."""
        logger.info("=== Phase 1: URL Discovery ===")
        self.results['current_phase'] = 'url_discovery'
        self.scan_state['phases']['url_discovery']['status'] = 'in_progress'
        self._update_progress('url_discovery', 0, 20)
        
        # Log enabled tools
        logger.info("URL Discovery tools enabled:")
        logger.info(f"  - GAU: {self.config.get('enable_gau', True)}")
        logger.info(f"  - Waybackurls: {self.config.get('enable_waybackurls', True)}")
        logger.info(f"  - Wayurls: {self.config.get('enable_wayurls', False)}")
        logger.info(f"  - Katana: {self.config.get('enable_katana', True)}")
        
        if scan_type == 'quick':
            logger.info("Quick scan mode - using limited URL discovery")
            # In quick mode, just use the main domain URLs
            urls = [f"https://{domain}" for domain in domains]
            categorized = {domain: {'priority': urls, 'normal': [], 'problematic': []} for domain in domains}
        else:
            try:
                all_urls = []
                all_categorized = {}
                
                for i, domain in enumerate(domains):
                    logger.info(f"Discovering URLs for: {domain}")
                    self._update_progress('url_discovery', (i / len(domains)) * 20, 20)
                    
                    # Check if domain is blocked
                    if hasattr(self, 'runtime_config') and 'security' in self.runtime_config:
                        blocked_domains = self.runtime_config['security'].get('blocked_domains', [])
                        if any(blocked in domain for blocked in blocked_domains):
                            logger.warning(f"Skipping blocked domain: {domain}")
                            continue
                    
                    if self.config.get('dry_run'):
                        logger.info("Dry run mode - simulating URL discovery")
                        discovered_urls = [
                            f"https://{domain}/",
                            f"https://{domain}/app.js",
                            f"https://{domain}/config.json",
                            f"https://{domain}/api/config",
                            f"https://{domain}/assets/main.js"
                        ]
                        categorized = {
                            'priority': [f"https://{domain}/app.js", f"https://{domain}/config.json"],
                            'normal': [f"https://{domain}/", f"https://{domain}/api/config"],
                            'problematic': []
                        }
                    else:
                        # Use enhanced URL discovery
                        discovered_urls = self.url_discovery.discover_urls(domain)
                        categorized = self.url_discovery.get_prioritized_urls(domain)
                    
                    all_urls.extend(discovered_urls)
                    all_categorized[domain] = categorized
                    
                    self.results['urls_by_category'][domain] = {
                        cat: len(urls) for cat, urls in categorized.items()
                    }
                    
                    logger.info(f"Found {len(discovered_urls)} URLs for {domain}")
                    logger.info(f"  Priority: {len(categorized.get('priority', []))}")
                    logger.info(f"  Normal: {len(categorized.get('normal', []))}")
                    logger.info(f"  Problematic: {len(categorized.get('problematic', []))}")
                
                # Apply URL patterns if configured
                if hasattr(self, 'runtime_config') and 'url_patterns' in self.runtime_config:
                    exclude_patterns = self.runtime_config['url_patterns'].get('exclude', [])
                    priority_patterns = self.runtime_config['url_patterns'].get('priority', [])
                    
                    if exclude_patterns:
                        logger.info(f"Applying {len(exclude_patterns)} exclude patterns")
                        # Apply exclude patterns
                        # TODO: Implement pattern matching
                    
                    if priority_patterns:
                        logger.info(f"Applying {len(priority_patterns)} priority patterns")
                        # Apply priority patterns
                        # TODO: Implement pattern matching
                
                # Remove duplicates while preserving order
                seen = set()
                unique_urls = []
                for url in all_urls:
                    if url not in seen:
                        seen.add(url)
                        unique_urls.append(url)
                
                urls = unique_urls
                categorized = all_categorized
                
                # Apply max URLs limit
                max_urls = self.config.get('max_urls_per_domain', 10000) * len(domains)
                if len(urls) > max_urls:
                    logger.warning(f"Limiting URLs from {len(urls)} to {max_urls}")
                    urls = urls[:max_urls]
                
                self.results['urls_discovered'] = len(urls)
                
                logger.info(f"Total unique URLs discovered: {len(urls)}")
                
                # Save URLs to file
                urls_file = Path(self.config['data_storage_path']) / 'urls' / f'urls_{self.scan_id}.json'
                urls_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(urls_file, 'w') as f:
                    json.dump({
                        'urls': urls,
                        'categorized': categorized,
                        'timestamp': datetime.now().isoformat(),
                        'discovery_tools': {
                            'gau': self.config.get('enable_gau', True),
                            'waybackurls': self.config.get('enable_waybackurls', True),
                            'wayurls': self.config.get('enable_wayurls', False),
                            'katana': self.config.get('enable_katana', True)
                        }
                    }, f, indent=2)
                
                # Update scan state
                self.scan_state['phases']['url_discovery']['status'] = 'completed'
                self.scan_state['phases']['url_discovery']['data'] = {
                    'urls': urls,
                    'categorized': categorized,
                    'urls_file': str(urls_file)
                }
                self._save_scan_state()
                
            except Exception as e:
                logger.error(f"URL discovery failed: {str(e)}")
                self.results['errors'].append({
                    'phase': 'url_discovery',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
                raise
        
        self._update_progress('url_discovery', 20, 20)
        return urls, categorized
    
    def scan_domains(self, domains: List[str], scan_type: str = 'full', resume_scan_id: Optional[str] = None) -> Dict:
        """
        Run the complete scanning pipeline on the given domains.
        
        Args:
            domains: List of domains to scan
            scan_type: Type of scan ('full', 'incremental', 'quick')
            resume_scan_id: Optional scan ID to resume from
            
        Returns:
            Dictionary containing scan results
        """
        try:
            logger.info(f"Starting {scan_type} scan for {len(domains)} domains")
            logger.info(f"Configuration: {os.getenv('APP_ENV', 'production')} environment")
            self.results['domains'] = domains
            self.results['scan_type'] = scan_type
            self.results['environment'] = os.getenv('APP_ENV', 'production')
            
            # Check if resuming
            if resume_scan_id:
                self._load_scan_state(resume_scan_id)
            
            # Initialize components
            self._initialize_components()
            
            # Send start notification
            if self.slack_notifier and not self.config.get('dry_run') and self.config.get('enable_slack'):
                self.slack_notifier.send_scan_started(
                    domains=domains,
                    scan_type=scan_type,
                    scan_id=self.scan_id
                )
            
            # Phase 1: URL Discovery
            if self.scan_state['phases']['url_discovery']['status'] != 'completed':
                urls, categorized = self._phase_url_discovery(domains, scan_type)
            else:
                logger.info("Skipping URL discovery (already completed)")
                urls = self.scan_state['phases']['url_discovery']['data'].get('urls', [])
                categorized = self.scan_state['phases']['url_discovery']['data'].get('categorized', {})
            
            # Phase 2: Content Fetching
            if self.scan_state['phases']['content_fetching']['status'] != 'completed':
                content_dir = self._phase_content_fetching(urls, categorized)
            else:
                logger.info("Skipping content fetching (already completed)")
                content_dir = self.scan_state['phases']['content_fetching']['data'].get('content_dir')
            
            # Phase 3: Secret Scanning
            if self.scan_state['phases']['secret_scanning']['status'] != 'completed':
                raw_secrets_file = self._phase_secret_scanning(content_dir, scan_type)
            else:
                logger.info("Skipping secret scanning (already completed)")
                raw_secrets_file = self.scan_state['phases']['secret_scanning']['data'].get('raw_secrets_file')
            
            # Phase 4: Validation
            if self.scan_state['phases']['validation']['status'] != 'completed':
                validated_secrets_file = self._phase_validation(raw_secrets_file)
            else:
                logger.info("Skipping validation (already completed)")
                validated_secrets_file = self.scan_state['phases']['validation']['data'].get('validated_secrets_file')
            
            # Phase 5: Reporting
            self._phase_reporting(validated_secrets_file)
            
            # Calculate final metrics
            self._calculate_performance_metrics()
            
            # Save final results
            self._save_final_results()
            
            # Clean up scan state
            if self.scan_state_file.exists():
                self.scan_state_file.unlink()
            
            duration = time.time() - self.start_time
            self.results['duration_seconds'] = duration
            self.results['end_time'] = datetime.now().isoformat()
            self.results['status'] = 'completed'
            
            logger.success(f"Scan completed successfully in {duration:.2f} seconds")
            
            # Send completion notification
            if self.slack_notifier and not self.config.get('dry_run') and self.config.get('enable_slack'):
                # Prepare summary data for Slack
                summary_data = {
                    'scan_id': self.scan_id,
                    'duration': f"{duration:.2f} seconds",
                    'urls_scanned': self.results['urls_discovered'],
                    'domains_scanned': len(self.results['domains']),
                    'urls_processed': self.results['content_fetched'],
                    'total_secrets': self.results['validated_secrets'],
                    'new_secrets': self.results.get('new_secrets', 0),
                    'new_findings': self.results.get('new_secrets', 0),
                    'environment': self.results.get('environment', 'production')
                }
                self.slack_notifier.send_scan_completed(summary_data, scan_id=self.scan_id)
            
            return self.results
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            logger.exception(e)
            
            self.results['status'] = 'failed'
            self.results['error'] = str(e)
            self.results['traceback'] = traceback.format_exc()
            
            # Save state for potential resumption
            self._save_scan_state()
            
            # Send failure notification
            if self.slack_notifier and not self.config.get('dry_run') and self.config.get('enable_slack'):
                self.slack_notifier.send_scan_failed(
                    error=str(e),
                    scan_id=self.scan_id,
                    stage=self.results.get('current_phase', 'initialization')
                )
            
            raise
    
    def _phase_content_fetching(self, urls: List[str], categorized: Dict) -> str:
        """Phase 2: Fetch content from discovered URLs."""
        logger.info("=== Phase 2: Content Fetching ===")
        self.results['current_phase'] = 'content_fetching'
        self.scan_state['phases']['content_fetching']['status'] = 'in_progress'
        self._update_progress('content_fetching', 20, 40)
        
        try:
            content_dir = Path(self.config['data_storage_path']) / 'content' / self.scan_id
            content_dir.mkdir(parents=True, exist_ok=True)
            
            if self.config.get('dry_run'):
                logger.info("Dry run mode - simulating content fetching")
                # Create dummy content
                (content_dir / 'html').mkdir(exist_ok=True)
                (content_dir / 'js').mkdir(exist_ok=True)
                
                dummy_html = '<html><script>const API_KEY = "dummy_key_12345";</script></html>'
                dummy_js = 'const SECRET_TOKEN = "dummy_token_67890";\nconst config = { apiKey: "test_key" };'
                
                (content_dir / 'html' / 'example.html').write_text(dummy_html)
                (content_dir / 'js' / 'app.js').write_text(dummy_js)
                
                fetched_count = 2
            else:
                # Flatten categorized URLs for content fetcher
                categorized_flat = {'priority': [], 'normal': [], 'problematic': []}
                for domain, cats in categorized.items():
                    if isinstance(cats, dict):
                        for category in ['priority', 'normal', 'problematic']:
                            if category in cats:
                                categorized_flat[category].extend(cats[category])
                
                # Monitor progress
                def progress_monitor():
                    while hasattr(self.content_fetcher, 'get_progress'):
                        progress = self.content_fetcher.get_progress()
                        if progress['total'] > 0:
                            pct = (progress['current'] / progress['total']) * 20 + 20
                            self._update_progress('content_fetching', pct, 40)
                        time.sleep(2)
                
                # Start progress monitoring in background
                if self.config.get('enable_progress_monitoring'):
                    monitor_thread = threading.Thread(target=progress_monitor, daemon=True)
                    monitor_thread.start()
                
                fetched_count = self.content_fetcher.fetch_content(
                    urls, 
                    str(content_dir),
                    categorized_urls=categorized_flat
                )
                
                # Get statistics
                fetcher_stats = self.content_fetcher.stats
                self.results['content_fetched'] = fetcher_stats.get('total_success', fetched_count)
                self.results['content_fetch_failed'] = fetcher_stats.get('total_failed', 0)
                
                # Add warnings for failed URLs
                if fetcher_stats.get('failed_urls'):
                    self.results['warnings'].append({
                        'phase': 'content_fetching',
                        'message': f"{len(fetcher_stats['failed_urls'])} URLs failed to fetch",
                        'failed_urls': fetcher_stats['failed_urls'][:10],  # First 10
                        'timestamp': datetime.now().isoformat()
                    })
                
                logger.info(f"Fetched content from {fetched_count} URLs")
            
            # Validate content
            validation_report = self.content_fetcher.validate_content(str(content_dir))
            self.results['content_validation'] = validation_report
            
            # Update scan state
            self.scan_state['phases']['content_fetching']['status'] = 'completed'
            self.scan_state['phases']['content_fetching']['data'] = {
                'content_dir': str(content_dir),
                'fetched_count': fetched_count,
                'validation_report': validation_report
            }
            self._save_scan_state()
            
            self._update_progress('content_fetching', 40, 40)
            return str(content_dir)
            
        except Exception as e:
            logger.error(f"Content fetching failed: {str(e)}")
            self.results['errors'].append({
                'phase': 'content_fetching',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            raise
    
    def _phase_secret_scanning(self, content_dir: str, scan_type: str) -> str:
        """Phase 3: Scan content for secrets."""
        logger.info("=== Phase 3: Secret Scanning ===")
        self.results['current_phase'] = 'secret_scanning'
        self.scan_state['phases']['secret_scanning']['status'] = 'in_progress'
        self._update_progress('secret_scanning', 40, 70)
        
        try:
            raw_secrets_dir = Path(self.config['raw_secrets_path'])
            raw_secrets_dir.mkdir(parents=True, exist_ok=True)
            
            raw_secrets_file = raw_secrets_dir / f'raw_secrets_{self.scan_id}.json'
            
            if self.config.get('dry_run'):
                logger.info("Dry run mode - simulating secret scanning")
                # Create dummy raw secrets
                dummy_secrets = {
                    'scan_id': self.scan_id,
                    'timestamp': datetime.now().isoformat(),
                    'scan_type': scan_type,
                    'findings': [
                        {
                            'id': 'dummy_001',
                            'type': 'aws_access_key',
                            'detector': 'trufflehog',
                            'file': 'example.js',
                            'line': 5,
                            'confidence': 'high',
                            'severity': 'critical',
                            'raw': 'AKIAIOSFODNN7EXAMPLE',
                            'redacted': 'AKIA****************',
                            'verified': False
                        },
                        {
                            'id': 'dummy_002',
                            'type': 'generic_api_key',
                            'detector': 'custom_pattern',
                            'file': 'config.json',
                            'line': 12,
                            'confidence': 'medium',
                            'severity': 'high',
                            'raw': '',
                            'redacted': 'sk_test_************************',
                            'verified': False
                        }
                    ]
                }
                with open(raw_secrets_file, 'w') as f:
                    json.dump(dummy_secrets, f, indent=2)
                self.results['raw_secrets_found'] = 2
            else:
                # Perform scanning
                findings = self.secret_scanner.scan_directory(content_dir, scan_type)
                self.results['raw_secrets_found'] = len(findings)
                
                # Get scanner statistics
                scanner_stats = self.secret_scanner.get_statistics()
                self.results['scanner_stats'] = scanner_stats
                
                # Save raw findings
                scan_results = {
                    'scan_id': self.scan_id,
                    'timestamp': datetime.now().isoformat(),
                    'content_directory': content_dir,
                    'scan_type': scan_type,
                    'statistics': scanner_stats,
                    'findings': findings
                }
                
                with open(raw_secrets_file, 'w') as f:
                    json.dump(scan_results, f, indent=2)
                
                logger.info(f"Found {len(findings)} potential secrets")
                logger.info(f"Raw secrets saved to: {raw_secrets_file}")
                
                # Save intermediate results if configured
                if self.config.get('save_intermediate_results'):
                    self._save_intermediate_results('raw_secrets', scan_results)
            
            # Update scan state
            self.scan_state['phases']['secret_scanning']['status'] = 'completed'
            self.scan_state['phases']['secret_scanning']['data'] = {
                'raw_secrets_file': str(raw_secrets_file),
                'secrets_found': self.results['raw_secrets_found']
            }
            self._save_scan_state()
            
            self._update_progress('secret_scanning', 70, 70)
            return str(raw_secrets_file)
            
        except Exception as e:
            logger.error(f"Secret scanning failed: {str(e)}")
            self.results['errors'].append({
                'phase': 'secret_scanning',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            raise
    
    def _phase_validation(self, raw_secrets_file: str) -> str:
        """Phase 4: Validate discovered secrets."""
        logger.info("=== Phase 4: Validation ===")
        self.results['current_phase'] = 'validation'
        self.scan_state['phases']['validation']['status'] = 'in_progress'
        self._update_progress('validation', 70, 85)
        
        if not self.config.get('enable_validation') or not self.validator:
            logger.info("Validation disabled - using raw secrets as validated")
            self._update_progress('validation', 85, 85)
            return raw_secrets_file
        
        try:
            validated_dir = Path(self.config['data_storage_path']) / 'scans' / 'validated'
            validated_dir.mkdir(parents=True, exist_ok=True)
            
            validated_file = validated_dir / f'validated_secrets_{self.scan_id}.json'
            
            if self.config.get('dry_run'):
                logger.info("Dry run mode - simulating validation")
                # Copy raw secrets as validated
                shutil.copy(raw_secrets_file, validated_file)
                self.results['validated_secrets'] = self.results['raw_secrets_found']
            else:
                validated_findings = self.validator.validate_secrets(raw_secrets_file)
                self.results['validated_secrets'] = len(validated_findings)
                
                # Calculate validation statistics
                with open(raw_secrets_file, 'r') as f:
                    raw_data = json.load(f)
                    raw_count = len(raw_data.get('findings', []))
                
                validation_rate = (len(validated_findings) / raw_count * 100) if raw_count > 0 else 0
                
                # Save validated findings
                validated_data = {
                    'scan_id': self.scan_id,
                    'timestamp': datetime.now().isoformat(),
                    'raw_secrets_file': raw_secrets_file,
                    'validation_statistics': {
                        'raw_secrets': raw_count,
                        'validated_secrets': len(validated_findings),
                        'validation_rate': f"{validation_rate:.2f}%",
                        'false_positives_removed': raw_count - len(validated_findings)
                    },
                    'findings': validated_findings
                }
                
                with open(validated_file, 'w') as f:
                    json.dump(validated_data, f, indent=2)
                
                logger.info(f"Validated {len(validated_findings)} secrets ({validation_rate:.2f}% validation rate)")
                logger.info(f"Validated secrets saved to: {validated_file}")
                
                # Save intermediate results
                if self.config.get('save_intermediate_results'):
                    self._save_intermediate_results('validated_secrets', validated_data)
            
            # Update scan state
            self.scan_state['phases']['validation']['status'] = 'completed'
            self.scan_state['phases']['validation']['data'] = {
                'validated_secrets_file': str(validated_file),
                'validated_count': self.results['validated_secrets']
            }
            self._save_scan_state()
            
            self._update_progress('validation', 85, 85)
            return str(validated_file)
            
        except Exception as e:
            logger.error(f"Validation failed: {str(e)}")
            self.results['errors'].append({
                'phase': 'validation',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            # Continue with raw secrets if validation fails
            return raw_secrets_file
    
    def _phase_reporting(self, validated_file: str):
        """Phase 5: Generate reports and send alerts."""
        logger.info("=== Phase 5: Reporting & Alerting ===")
        self.results['current_phase'] = 'reporting'
        self._update_progress('reporting', 85, 100)
        
        try:
            # Initialize BaselineManager
            from modules.validator.baseline_manager import BaselineManager
            baseline_manager = BaselineManager(self.config)
            
            # Load findings from the validated file
            with open(validated_file, 'r') as f:
                validated_data = json.load(f)
                current_findings = validated_data.get('findings', [])
            
            # Process findings to ensure proper structure
            processed_findings = []
            for finding in current_findings:
                # Get the URL from scanner metadata if available
                url = None
                if 'metadata' in finding and 'url' in finding['metadata']:
                    url = finding['metadata']['url']
                elif 'source_metadata' in finding and 'url' in finding['source_metadata']:
                    url = finding['source_metadata']['url']
                elif 'SourceMetadata' in finding and 'Data' in finding['SourceMetadata']:
                    # TruffleHog format
                    if 'URL' in finding['SourceMetadata']['Data']:
                        url = finding['SourceMetadata']['Data']['URL']
                    elif 'url' in finding['SourceMetadata']['Data']:
                        url = finding['SourceMetadata']['Data']['url']
                
                # If no URL found, try to construct from file path
                if not url and 'file' in finding:
                    # Try to extract domain from file path
                    file_path = finding['file']
                    if 'content/' in file_path and '/' in file_path:
                        parts = file_path.split('/')
                        if len(parts) > 3:
                            domain = None
                            for i, part in enumerate(parts):
                                if part == 'content' and i + 2 < len(parts):
                                    domain = parts[i + 2]
                                    break
                            if domain:
                                remaining_path = '/'.join(parts[parts.index(domain) + 1:])
                                url = f"https://{domain}/{remaining_path}"
                
                processed_finding = {
                    'id': finding.get('id', hashlib.sha256(f"{finding.get('type')}:{finding.get('file')}:{finding.get('line')}".encode()).hexdigest()[:16]),
                    'type': finding.get('type', 'unknown'),
                    'severity': finding.get('severity', 'medium'),
                    'file_path': finding.get('file', finding.get('file_path', 'unknown')),
                    'url': url or finding.get('url', ''),
                    'line_number': finding.get('line', finding.get('line_number')),
                    'confidence': finding.get('confidence', 'medium'),
                    'tool': finding.get('detector', finding.get('tool', 'unknown')),
                    'secret': finding.get('raw', finding.get('secret', '')),
                    'secret_display': finding.get('raw', finding.get('secret', '')),
                    'verified': finding.get('verified', False),
                    'validation_result': finding.get('validation_result', {}),
                    'validation_status': self._get_validation_status(finding.get('validation_result', {}))
                }
                
                # Add any additional metadata
                if 'metadata' in finding:
                    processed_finding['metadata'] = finding['metadata']
                
                processed_findings.append(processed_finding)
            
            # Load baseline for the domain (use first domain if multiple)
            domain = self.results['domains'][0] if self.results['domains'] else None
            baseline_manager.load_baseline(domain)
            
            # Compare findings with baseline
            comparison_results = baseline_manager.compare_findings(processed_findings)
            
            # Process comparison results - mark ALL findings with their status
            all_findings_with_status = []
            new_findings = []
            
            # Add new findings
            for finding in comparison_results.get('new', []):
                finding['baseline_status'] = 'new'
                all_findings_with_status.append(finding)
                new_findings.append(finding)
            
            # Add recurring findings
            for finding in comparison_results.get('recurring', []):
                finding['baseline_status'] = 'recurring'
                all_findings_with_status.append(finding)
            
            # Add false positives (optional - you might want to exclude these from reports)
            for finding in comparison_results.get('false_positives', []):
                finding['baseline_status'] = 'false_positive'
                # Optionally include in report: all_findings_with_status.append(finding)
            
            # Update results
            self.results['new_secrets'] = len(new_findings)
            self.results['recurring_secrets'] = len(comparison_results.get('recurring', []))
            self.results['resolved_secrets'] = len(comparison_results.get('resolved', []))
            
            logger.info(f"Baseline comparison: {self.results['new_secrets']} new, "
                       f"{self.results['recurring_secrets']} recurring, "
                       f"{self.results['resolved_secrets']} resolved")
            
            if not self.config.get('dry_run'):
                # Generate HTML report with ALL findings (showing their status)
                report_path = self.html_reporter.generate_report(
                    all_findings_with_status,
                    report_type='full',
                    comparison_data=comparison_results,
                    scan_id=self.scan_id  # Add this line
                )
                self.results['html_report'] = str(report_path)
                logger.info(f"HTML report generated: {report_path}")
                
                # Send Slack notifications for NEW findings only
                # Send Slack notifications for NEW findings only
                if self.slack_notifier and self.config.get('enable_slack'):
                    # Prepare summary data with scan_id and ensure consistency
                    summary_data = {
                        'scan_id': self.scan_id,
                        'domains_scanned': len(self.results['domains']),
                        'urls_processed': self.results['content_fetched'],
                        'urls_scanned': self.results['urls_discovered'],  # Add this
                        'new_findings': len(new_findings),
                        'total_findings': len(all_findings_with_status),
                        'new_secrets': len(new_findings),
                        'recurring_secrets': self.results.get('recurring_secrets', 0),
                        'resolved_secrets': self.results.get('resolved_secrets', 0),
                        'duration': f"{time.time() - self.start_time:.2f} seconds",  # Add duration
                        'domain': self.results['domains'][0] if self.results['domains'] else 'Unknown'  # Add domain
                    }
                    
                    if new_findings:
                        logger.warning(f"Found {len(new_findings)} new secrets!")
                        
                        # Send findings notification for new secrets only with summary data
                        self.slack_notifier.send_findings_notification(
                            new_findings,
                            notification_type='new',
                            summary_data=summary_data
                        )
                        
                        # Send individual alerts for critical/high severity new secrets
                        for secret in new_findings:
                            severity = secret.get('severity', 'medium').lower()
                            
                            should_alert = False
                            if severity == 'critical' and self.config.get('alert_on_critical', True):
                                should_alert = True
                            elif severity == 'high' and self.config.get('alert_on_high', True):
                                should_alert = True
                            elif severity == 'medium' and self.config.get('alert_on_medium', False):
                                should_alert = True
                            elif severity == 'low' and self.config.get('alert_on_low', False):
                                should_alert = True
                            
                            if should_alert and secret.get('verified'):
                                self.slack_notifier.send_secret_alert(secret)
                    else:
                        logger.info("No new secrets found")
                        self.slack_notifier.send_message(
                            f"✅ Scan {self.scan_id} completed. No new secrets found. "
                            f"({self.results['recurring_secrets']} recurring, "
                            f"{self.results['resolved_secrets']} resolved)",
                            severity='info'
                        )
                
                # Update baseline with current findings
                baseline_manager.update_baseline(all_findings_with_status)
                logger.info("Baseline updated")
            
            # Update scan state
            self.scan_state['phases']['reporting']['status'] = 'completed'
            self._save_scan_state()
            
            self._update_progress('reporting', 100, 100)
                
        except Exception as e:
            logger.error(f"Reporting failed: {str(e)}")
            self.results['errors'].append({
                'phase': 'reporting',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            # Don't raise - reporting failures shouldn't fail the scan
    
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
            return secret[:5] + '*' * 20 + secret[-5:]
    
    def _get_validation_status(self, val_result: Dict[str, Any]) -> str:
        """Get validation status display."""
        if val_result.get('valid') is True:
            return 'Verified Active'
        elif val_result.get('valid') is False:
            return 'Invalid/Inactive'
        else:
            return 'Not Verified'
    
    def _find_new_secrets(self, current: List[Dict], baseline: List[Dict]) -> List[Dict]:
        """Find secrets that are in current but not in baseline."""
        # Create unique identifiers for baseline secrets
        baseline_ids = set()
        for secret in baseline:
            # Use the ID if available, otherwise create one
            if 'id' in secret:
                baseline_ids.add(secret['id'])
            else:
                # Fallback to creating ID from properties
                secret_id = f"{secret.get('type')}:{secret.get('file_path', secret.get('file'))}:{secret.get('line_number', secret.get('line'))}:{secret.get('secret', secret.get('raw', ''))[:20]}"
                baseline_ids.add(hashlib.sha256(secret_id.encode()).hexdigest()[:16])
        
        # Find new secrets
        new_secrets = []
        for secret in current:
            secret_id = secret.get('id')
            if not secret_id:
                # Fallback to creating ID
                secret_id = f"{secret.get('type')}:{secret.get('file_path')}:{secret.get('line_number')}:{secret.get('secret', '')[:20]}"
                secret_id = hashlib.sha256(secret_id.encode()).hexdigest()[:16]
            
            if secret_id not in baseline_ids:
                # Mark as new
                secret['baseline_status'] = 'new'
                new_secrets.append(secret)
        
        return new_secrets
    
    def _update_progress(self, phase: str, current: float, total: float):
        """Update progress tracking."""
        self.progress['current_phase'] = phase
        self.progress['current_progress'] = current
        self.progress['total_progress'] = total
        
        if self.config.get('enable_progress_monitoring'):
            logger.bind(progress=True).info(
                f"Progress: {phase} - {current:.1f}/{total:.1f} ({(current/total*100):.1f}%)"
            )
    
    def _save_scan_state(self):
        """Save current scan state for potential resumption."""
        try:
            self.scan_state_file.parent.mkdir(parents=True, exist_ok=True)
            
            state_data = {
                **self.scan_state,
                'last_updated': datetime.now().isoformat(),
                'results': self.results,
                'config': self.config
            }
            
            with open(self.scan_state_file, 'w') as f:
                json.dump(state_data, f, indent=2)
                
        except Exception as e:
            logger.warning(f"Failed to save scan state: {e}")
    
    def _load_scan_state(self, scan_id: str):
        """Load scan state for resumption."""
        state_file = Path(self.config['data_storage_path']) / 'scans' / 'state' / f'{scan_id}_state.json'
        
        if not state_file.exists():
            logger.warning(f"No state file found for scan {scan_id}")
            return
        
        try:
            with open(state_file, 'r') as f:
                state_data = json.load(f)
            
            self.scan_state = state_data
            self.scan_id = scan_id
            self.results = state_data.get('results', self.results)
            
            logger.info(f"Resumed scan {scan_id} from saved state")
            
        except Exception as e:
            logger.error(f"Failed to load scan state: {e}")
    
    def _save_intermediate_results(self, result_type: str, data: Dict):
        """Save intermediate results for debugging and analysis."""
        try:
            intermediate_dir = Path(self.config['data_storage_path']) / 'scans' / 'intermediate' / self.scan_id
            intermediate_dir.mkdir(parents=True, exist_ok=True)
            
            filename = f'{result_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            filepath = intermediate_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.warning(f"Failed to save intermediate results: {e}")
    
    def _calculate_performance_metrics(self):
        """Calculate and store performance metrics."""
        duration = time.time() - self.start_time
        
        self.results['performance_metrics'] = {
            'total_duration_seconds': duration,
            'urls_per_second': self.results['urls_discovered'] / duration if duration > 0 else 0,
            'files_per_second': self.results.get('scanner_stats', {}).get('files_scanned', 0) / duration if duration > 0 else 0,
            'phases': {
                'url_discovery': self.scan_state['phases']['url_discovery'].get('duration', 0),
                'content_fetching': self.scan_state['phases']['content_fetching'].get('duration', 0),
                'secret_scanning': self.scan_state['phases']['secret_scanning'].get('duration', 0),
                'validation': self.scan_state['phases']['validation'].get('duration', 0),
                'reporting': self.scan_state['phases']['reporting'].get('duration', 0)
            }
        }
    
    def _save_final_results(self):
        """Save final scan results."""
        try:
            results_dir = Path(self.config['data_storage_path']) / 'scans' / 'results'
            results_dir.mkdir(parents=True, exist_ok=True)
            
            results_file = results_dir / f'scan_results_{self.scan_id}.json'
            
            with open(results_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            logger.info(f"Final results saved to: {results_file}")
            
        except Exception as e:
            logger.error(f"Failed to save final results: {e}")


def main():
    """Enhanced main entry point."""
    parser = argparse.ArgumentParser(
        description='Enhanced Automated Secrets Scanner - Detect exposed secrets in web applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single domain
  %(prog)s --domain example.com
  
  # Scan multiple domains from file
  %(prog)s --domains domains.txt
  
  # Quick scan with custom patterns only
  %(prog)s --domain example.com --scan-type quick
  
  # Full scan with validation and Slack notifications
  %(prog)s --domains domains.txt --validate --slack
  
  # Resume a previous scan
  %(prog)s --resume scan_20240115_143022_12345
        """
    )
    
    # Domain input options
    domain_group = parser.add_mutually_exclusive_group()
    domain_group.add_argument(
        '--domains',
        type=str,
        help='Path to domains file or comma-separated list of domains'
    )
    domain_group.add_argument(
        '--domain',
        type=str,
        help='Single domain to scan'
    )
    
    # Scan options
    parser.add_argument(
        '--scan-type',
        choices=['full', 'incremental', 'quick'],
        default='full',
        help='Type of scan to perform (default: full)'
    )
    
    parser.add_argument(
        '--resume',
        type=str,
        metavar='SCAN_ID',
        help='Resume a previous scan using its ID'
    )
    
    # Configuration options
    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--patterns',
        type=str,
        help='Path to custom patterns file'
    )
    
    # Feature toggles
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Enable secret validation'
    )
    
    parser.add_argument(
        '--slack',
        action='store_true',
        help='Send Slack notifications'
    )
    
    parser.add_argument(
        '--skip-crawler',
        action='store_true',
        help='Skip crawler and use static fetcher only'
    )
    
    parser.add_argument(
        '--include-problematic',
        action='store_true',
        help='Include problematic URLs in scan'
    )
    
    # Output options
    parser.add_argument(
        '--output-format',
        choices=['json', 'html', 'both'],
        default='both',
        help='Output format for results (default: both)'
    )
    
    parser.add_argument(
        '--output-file',
        type=str,
        help='Path to save results'
    )
    
    # Execution options
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run in dry-run mode (no actual scanning)'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--quiet',
        '-q',
        action='store_true',
        help='Minimal output (errors only)'
    )
    
    # Performance options
    parser.add_argument(
        '--concurrency',
        type=int,
        metavar='N',
        help='Number of concurrent requests'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        metavar='SECONDS',
        help='Request timeout in seconds'
    )
    
    parser.add_argument(
        '--batch-size',
        type=int,
        metavar='N',
        help='Crawler batch size'
    )
    
    # Tool options
    parser.add_argument(
        '--disable-katana',
        action='store_true',
        help='Disable Katana for URL discovery'
    )
    
    parser.add_argument(
        '--disable-gau',
        action='store_true',
        help='Disable GAU for URL discovery'
    )
    
    parser.add_argument(
        '--disable-waybackurls',
        action='store_true',
        help='Disable waybackurls for URL discovery'
    )
    
    args = parser.parse_args()
    
    # Set environment variables from arguments
    if args.dry_run:
        os.environ['DRY_RUN'] = 'true'
    
    if args.verbose:
        os.environ['LOG_LEVEL'] = 'DEBUG'
    elif args.quiet:
        os.environ['LOG_LEVEL'] = 'ERROR'
    
    if args.validate:
        os.environ['ENABLE_AUTO_VALIDATION'] = 'true'
    
    if args.slack:
        os.environ['ENABLE_SLACK'] = 'true'
    
    if args.skip_crawler:
        os.environ['SKIP_CRAWLER'] = 'true'
    
    if args.include_problematic:
        os.environ['INCLUDE_PROBLEMATIC_URLS'] = 'true'
    
    if args.concurrency:
        os.environ['CONCURRENT_REQUESTS'] = str(args.concurrency)
    
    if args.timeout:
        os.environ['SCAN_TIMEOUT'] = str(args.timeout)
    
    if args.batch_size:
        os.environ['CRAWLER_BATCH_SIZE'] = str(args.batch_size)
    
    if args.patterns:
        os.environ['CUSTOM_PATTERNS_PATH'] = args.patterns
    
    # Tool toggles
    if args.disable_katana:
        os.environ['ENABLE_KATANA'] = 'false'
    
    if args.disable_gau:
        os.environ['ENABLE_GAU'] = 'false'
    
    if args.disable_waybackurls:
        os.environ['ENABLE_WAYBACKURLS'] = 'false'
    
    # Determine domains to scan
    domains = []
    
    if args.resume:
        # Resume mode - domains will be loaded from saved state
        logger.info(f"Resuming scan {args.resume}")
    elif args.domain:
        domains = [args.domain]
    elif args.domains:
        if ',' in args.domains:
            # Comma-separated list
            domains = [d.strip() for d in args.domains.split(',')]
        else:
            # File path
            domains_file = Path(args.domains)
            if domains_file.exists():
                with open(domains_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and not line.startswith('!'):
                            # Support domain:port format
                            if ':' in line and not line.startswith('http'):
                                domain, port = line.split(':', 1)
                                if port.isdigit():
                                    domains.append(domain)
                                else:
                                    domains.append(line)
                            else:
                                domains.append(line)
            else:
                logger.error(f"Domains file not found: {args.domains}")
                sys.exit(1)
    else:
        # Use default domains file
        default_domains_file = PROJECT_ROOT / 'config' / 'domains.txt'
        if default_domains_file.exists():
            with open(default_domains_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and not line.startswith('!'):
                        domains.append(line)
        else:
            logger.error("No domains specified and default domains file not found")
            parser.print_help()
            sys.exit(1)
    
    if not args.resume and not domains:
        logger.error("No valid domains found to scan")
        sys.exit(1)
    
    try:
        # Create scanner instance
        scanner = SecretsScanner(config_path=args.config)
        
        # Run scan
        if args.resume:
            results = scanner.scan_domains([], scan_type=args.scan_type, resume_scan_id=args.resume)
        else:
            results = scanner.scan_domains(domains, scan_type=args.scan_type)
        
        # Save results if requested
        if args.output_file:
            output_path = Path(args.output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if args.output_format in ['json', 'both']:
                json_path = output_path.with_suffix('.json')
                with open(json_path, 'w') as f:
                    json.dump(results, f, indent=2)
                logger.info(f"JSON results saved to: {json_path}")
            
            if args.output_format in ['html', 'both'] and 'html_report' in results:
                html_path = output_path.with_suffix('.html')
                shutil.copy(results['html_report'], html_path)
                logger.info(f"HTML report saved to: {html_path}")
        
        # Print summary
        if not args.quiet:
            print("\n" + "="*60)
            print("SCAN SUMMARY")
            print("="*60)
            print(f"Scan ID: {results['scan_id']}")
            print(f"Status: {results['status']}")
            print(f"Environment: {results.get('environment', 'production')}")
            print(f"Scan Type: {results.get('scan_type', 'unknown')}")
            print(f"Domains: {', '.join(results['domains'])}")
            print(f"URLs Discovered: {results['urls_discovered']}")
            print(f"Content Fetched: {results['content_fetched']} ({results.get('content_fetch_failed', 0)} failed)")
            print(f"Raw Secrets Found: {results['raw_secrets_found']}")
            print(f"Validated Secrets: {results['validated_secrets']}")
            print(f"New Secrets: {results.get('new_secrets', 'N/A')}")
            print(f"Duration: {results.get('duration_seconds', 0):.2f} seconds")
            
            if results.get('errors'):
                print(f"\nErrors: {len(results['errors'])}")
                for error in results['errors'][:3]:  # Show first 3 errors
                    print(f"  - {error['phase']}: {error['error']}")
            
            if results.get('warnings'):
                print(f"\nWarnings: {len(results['warnings'])}")
            
            print("="*60)
        
        # Exit with appropriate code
        if results['status'] == 'completed':
            if results.get('new_secrets', 0) > 0:
                sys.exit(2)  # New secrets found
            else:
                sys.exit(0)  # Success, no new secrets
        else:
            sys.exit(1)  # Scan failed
            
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Scan failed with error: {str(e)}")
        if args.verbose:
            logger.exception(e)
        sys.exit(1)


if __name__ == '__main__':
    main()