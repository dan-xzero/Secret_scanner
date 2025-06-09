#!/usr/bin/env python3
"""
Initialize database and test scanner
"""

import sqlite3
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from scripts.run_scan import SecretScanner
from loguru import logger

def init_database():
    """Ensure database is properly initialized"""
    
    db_path = Path('./data/scanner.db')
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create a minimal config to initialize the scanner
    config = {
        'domains': ['example.com'],
        'data_storage_path': './data',
        'scan': {'type': 'test'}
    }
    
    try:
        # Initialize scanner - this will create all tables
        logger.info("Initializing scanner and database...")
        scanner = SecretScanner(config)
        
        # Verify tables exist
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' 
                ORDER BY name
            """)
            tables = [row[0] for row in cursor.fetchall()]
            
            logger.info(f"Database tables created: {tables}")
            
            # Check if all required tables exist
            required_tables = ['urls', 'secrets', 'findings', 'scan_runs', 'baselines']
            missing = set(required_tables) - set(tables)
            
            if missing:
                logger.error(f"Missing tables: {missing}")
                return False
            
            logger.success("✓ Database initialized successfully!")
            return True
            
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return False

def test_url_discovery():
    """Test URL discovery with a known domain"""
    
    logger.info("\nTesting URL discovery with example.com...")
    
    config = {
        'domains': ['example.com'],
        'data_storage_path': './data',
        'scan': {
            'type': 'test',
            'phases': ['url_discovery']
        },
        'url_discovery': {
            'max_urls': 10,
            'tools': {
                'gau': {'enabled': True},
                'waybackurls': {'enabled': True}
            }
        }
    }
    
    try:
        scanner = SecretScanner(config)
        results = scanner.scan_domains(['example.com'])
        
        if results and 'example.com' in results:
            url_count = results['example.com'].get('phase_stats', {}).get('url_discovery', {}).get('urls_discovered', 0)
            logger.info(f"Found {url_count} URLs for example.com")
            return url_count > 0
        
        return False
        
    except Exception as e:
        logger.error(f"URL discovery test failed: {e}")
        return False

if __name__ == "__main__":
    # Initialize database
    if not init_database():
        logger.error("Database initialization failed!")
        sys.exit(1)
    
    # Test URL discovery
    if test_url_discovery():
        logger.success("\n✓ Scanner is ready to use!")
        logger.info("\nYou can now run:")
        logger.info("python scripts/run_scan.py --domain influencers.quince.com --scan-type full")
    else:
        logger.warning("\n⚠ URL discovery test returned no results")
        logger.info("This might be normal if example.com has no archived URLs")
        logger.info("\nTry running your scan anyway:")
        logger.info("python scripts/run_scan.py --domain influencers.quince.com --scan-type full")