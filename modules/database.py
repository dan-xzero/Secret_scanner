#!/usr/bin/env python3
"""
Database management module for the secrets scanner.
"""

import sqlite3
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Handle all database operations."""
    
    def __init__(self, db_path: str):
        """Initialize database connection."""
        self.db_path = db_path
        self.conn = None
        self._ensure_db_exists()
    
    def _ensure_db_exists(self):
        """Ensure database and tables exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_schema()
    
    def _create_schema(self):
        """Create database schema."""
        tables_created = []
        
        try:
            with self.conn:
                # URLs table
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS urls (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT UNIQUE NOT NULL,
                        domain TEXT NOT NULL,
                        file_path TEXT,
                        content_type TEXT,
                        crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'active',
                        scan_id TEXT,
                        category TEXT DEFAULT 'normal'
                    )
                """)
                tables_created.append('urls')
                
                # Secrets table (unique secrets)
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS secrets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        secret_hash TEXT UNIQUE NOT NULL,
                        secret_type TEXT NOT NULL,
                        detector_name TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_verified BOOLEAN DEFAULT 0,
                        is_active BOOLEAN DEFAULT 1,
                        severity TEXT DEFAULT 'medium',
                        confidence TEXT DEFAULT 'medium'
                    )
                """)
                tables_created.append('secrets')
                
                # Findings table (occurrences of secrets in URLs)
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        secret_id INTEGER NOT NULL,
                        url_id INTEGER NOT NULL,
                        line_number INTEGER,
                        snippet TEXT,
                        found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        scan_run_id TEXT NOT NULL,
                        file_path TEXT,
                        validation_status TEXT DEFAULT 'pending',
                        validation_result TEXT,
                        FOREIGN KEY (secret_id) REFERENCES secrets(id),
                        FOREIGN KEY (url_id) REFERENCES urls(id),
                        UNIQUE(secret_id, url_id, line_number)
                    )
                """)
                tables_created.append('findings')
                
                # Scan runs table
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_runs (
                        id TEXT PRIMARY KEY,
                        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP,
                        total_urls_scanned INTEGER DEFAULT 0,
                        total_secrets_found INTEGER DEFAULT 0,
                        new_secrets_count INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'running',
                        domains TEXT,
                        scan_type TEXT DEFAULT 'full'
                    )
                """)
                tables_created.append('scan_runs')
                
                # Baselines table
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS baselines (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        secret_id INTEGER NOT NULL,
                        domain TEXT NOT NULL,
                        marked_as_baseline_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        reason TEXT,
                        marked_by TEXT DEFAULT 'system',
                        FOREIGN KEY (secret_id) REFERENCES secrets(id),
                        UNIQUE(secret_id, domain)
                    )
                """)
                tables_created.append('baselines')
                
                # Create indexes
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_urls_domain ON urls(domain)")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_urls_scan_id ON urls(scan_id)")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_run ON findings(scan_run_id)")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_secret ON findings(secret_id)")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_secrets_hash ON secrets(secret_hash)")
                self.conn.execute("CREATE INDEX IF NOT EXISTS idx_baselines_domain ON baselines(domain)")
                
                logger.info(f"Database tables created: {tables_created}")
                return tables_created
                
        except Exception as e:
            logger.error(f"Failed to create schema: {str(e)}")
            raise
    
    def get_tables(self):
        """Get list of existing tables in the database."""
        cursor = self.conn.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
        """)
        return [row[0] for row in cursor.fetchall()]
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()


def init_database(db_path: Optional[str] = None) -> DatabaseManager:
    """Initialize the database with the given path."""
    if not db_path:
        db_path = './data/secrets_scanner.db'
    
    db = DatabaseManager(db_path)
    return db