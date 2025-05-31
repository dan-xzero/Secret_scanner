#!/usr/bin/env python3
"""
Example of using environment variables in the scanner
"""

import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env file
load_dotenv()

class Config:
    """Configuration class that reads from environment variables"""
    
    # Application settings
    APP_NAME = os.getenv('APP_NAME', 'automated-secrets-scanner')
    APP_ENV = os.getenv('APP_ENV', 'production')
    DEBUG = os.getenv('APP_DEBUG', 'false').lower() == 'true'
    
    # URL Discovery
    ENABLE_GAU = os.getenv('ENABLE_GAU', 'true').lower() == 'true'
    ENABLE_WAYBACKURLS = os.getenv('ENABLE_WAYBACKURLS', 'true').lower() == 'true'
    ENABLE_KATANA = os.getenv('ENABLE_KATANA', 'true').lower() == 'true'
    
    # Katana settings
    KATANA_HEADLESS = os.getenv('KATANA_HEADLESS', 'true').lower() == 'true'
    KATANA_DEPTH = int(os.getenv('KATANA_DEPTH', '3'))
    KATANA_JS_CRAWL = os.getenv('KATANA_JS_CRAWL', 'true').lower() == 'true'
    KATANA_PARALLELISM = int(os.getenv('KATANA_PARALLELISM', '10'))
    
    # Scanner settings
    ENABLE_TRUFFLEHOG = os.getenv('ENABLE_TRUFFLEHOG', 'true').lower() == 'true'
    ENABLE_GITLEAKS = os.getenv('ENABLE_GITLEAKS', 'true').lower() == 'true'
    
    # Slack settings
    SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL')
    SLACK_CHANNEL = os.getenv('SLACK_CHANNEL', '#security-alerts')
    
    # Paths
    DATA_STORAGE_PATH = Path(os.getenv('DATA_STORAGE_PATH', './data'))
    RAW_SECRETS_PATH = Path(os.getenv('RAW_SECRETS_PATH', './data/scans/raw'))
    REPORTS_PATH = Path(os.getenv('REPORTS_PATH', './data/reports'))
    
    @classmethod
    def get_scan_extensions(cls):
        """Get list of file extensions to scan"""
        extensions = os.getenv('SCAN_FILE_EXTENSIONS', '')
        if extensions:
            return [ext.strip() for ext in extensions.split(',')]
        return ['.js', '.json', '.html', '.htm', '.xml', '.yml', '.yaml']
    
    @classmethod
    def validate(cls):
        """Validate configuration"""
        errors = []
        
        if cls.SLACK_WEBHOOK_URL and 'YOUR/WEBHOOK/URL' in cls.SLACK_WEBHOOK_URL:
            errors.append("Slack webhook URL not configured properly")
        
        if cls.APP_ENV == 'production' and cls.DEBUG:
            errors.append("Debug mode enabled in production")
        
        # Create required directories
        for path in [cls.DATA_STORAGE_PATH, cls.RAW_SECRETS_PATH, cls.REPORTS_PATH]:
            path.mkdir(parents=True, exist_ok=True)
        
        return errors


# Example usage in scanner
def run_url_discovery(domain):
    """Run URL discovery tools based on configuration"""
    urls = set()
    
    if Config.ENABLE_GAU:
        print(f"Running gau for {domain}...")
        # Run gau command
        
    if Config.ENABLE_WAYBACKURLS:
        print(f"Running waybackurls for {domain}...")
        # Run waybackurls command
        
    if Config.ENABLE_KATANA:
        print(f"Running Katana for {domain}...")
        # Build Katana command with settings
        katana_cmd = [
            'katana',
            '-u', domain,
            '-d', str(Config.KATANA_DEPTH),
            '-c', str(Config.KATANA_PARALLELISM)
        ]
        
        if Config.KATANA_HEADLESS:
            katana_cmd.append('-headless')
            
        if Config.KATANA_JS_CRAWL:
            katana_cmd.append('-js-crawl')
        
        # Run katana command
    
    return urls


# Example main function
def main():
    # Validate configuration
    errors = Config.validate()
    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"  - {error}")
        return
    
    print(f"Starting {Config.APP_NAME} in {Config.APP_ENV} mode")
    print(f"Debug: {Config.DEBUG}")
    print(f"Scan file extensions: {Config.get_scan_extensions()}")
    
    # Your scanner logic here
    domain = "example.com"
    urls = run_url_discovery(domain)


if __name__ == "__main__":
    main()