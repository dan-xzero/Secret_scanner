"""
Content Organizer Module

Organizes fetched content into a structured directory layout
and provides utilities for content management.
"""

import os
import shutil
import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict
import logging
import re
from urllib.parse import urlparse

from loguru import logger


class ContentOrganizer:
    """Organizes and manages fetched web content."""
    
    def __init__(self, config: Dict, logger: Optional[logging.Logger] = None):
        """
        Initialize Content Organizer.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Configuration
        self.data_storage_path = Path(config.get('data_storage_path', './data'))
        self.archive_old_content = config.get('archive_old_content', True)
        self.archive_after_days = config.get('archive_after_days', 30)
        self.max_storage_size_gb = config.get('max_storage_size_gb', 50)
        self.organize_by_domain = config.get('organize_by_domain', True)
        self.deduplicate_content = config.get('deduplicate_content', True)
        
        # Content tracking
        self.content_index = {}
        self.content_hashes = set()
        self.duplicate_count = 0
    
    def organize_content(self, source_dir: str, scan_id: str) -> Dict:
        """
        Organize content from a crawl into structured directories.
        
        Args:
            source_dir: Directory containing raw fetched content
            scan_id: Unique scan identifier
            
        Returns:
            Organization report
        """
        self.logger.info(f"Organizing content from {source_dir}")
        
        source_path = Path(source_dir)
        if not source_path.exists():
            raise ValueError(f"Source directory does not exist: {source_dir}")
        
        # Create organized structure
        organized_dir = self.data_storage_path / 'content' / scan_id
        organized_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        stats = {
            'total_files': 0,
            'organized_files': 0,
            'duplicates_skipped': 0,
            'errors': 0,
            'total_size_mb': 0,
            'by_type': defaultdict(int),
            'by_domain': defaultdict(int)
        }
        
        # Process each content type
        for content_type in ['html', 'js', 'json', 'inline-scripts']:
            type_dir = source_path / content_type
            if type_dir.exists():
                self.logger.info(f"Processing {content_type} files...")
                
                for file_path in type_dir.glob('*'):
                    if file_path.is_file():
                        stats['total_files'] += 1
                        
                        try:
                            # Skip if duplicate
                            if self.deduplicate_content and self._is_duplicate(file_path):
                                stats['duplicates_skipped'] += 1
                                continue
                            
                            # Organize file
                            new_path = self._organize_file(
                                file_path, organized_dir, content_type
                            )
                            
                            if new_path:
                                stats['organized_files'] += 1
                                stats['by_type'][content_type] += 1
                                
                                # Track by domain
                                domain = self._extract_domain_from_metadata(
                                    file_path, source_path
                                )
                                if domain:
                                    stats['by_domain'][domain] += 1
                                
                                # Calculate size
                                size_mb = file_path.stat().st_size / (1024 * 1024)
                                stats['total_size_mb'] += size_mb
                                
                        except Exception as e:
                            self.logger.error(f"Failed to organize {file_path}: {e}")
                            stats['errors'] += 1
        
        # Process metadata
        metadata_dir = source_path / 'metadata'
        if metadata_dir.exists():
            self._organize_metadata(metadata_dir, organized_dir)
        
        # Create index
        self._create_content_index(organized_dir)
        
        # Round statistics
        stats['total_size_mb'] = round(stats['total_size_mb'], 2)
        stats['by_type'] = dict(stats['by_type'])
        stats['by_domain'] = dict(stats['by_domain'])
        
        # Save organization report
        report_path = organized_dir / 'organization_report.json'
        with open(report_path, 'w') as f:
            json.dump({
                'scan_id': scan_id,
                'timestamp': time.time(),
                'source_dir': str(source_dir),
                'organized_dir': str(organized_dir),
                'statistics': stats,
                'duplicate_count': self.duplicate_count
            }, f, indent=2)
        
        self.logger.info(
            f"Content organization complete: {stats['organized_files']}/{stats['total_files']} files"
        )
        
        return stats
    
    def _organize_file(self, file_path: Path, target_dir: Path, content_type: str) -> Optional[Path]:
        """
        Organize a single file into the target directory structure.
        
        Args:
            file_path: Path to file to organize
            target_dir: Target directory root
            content_type: Type of content (html, js, etc.)
            
        Returns:
            New file path if successful, None otherwise
        """
        try:
            # Determine organization structure
            if self.organize_by_domain:
                # Try to get domain from metadata
                domain = self._extract_domain_from_metadata(
                    file_path, file_path.parent.parent
                )
                
                if domain:
                    # Organize by domain
                    new_dir = target_dir / 'by_domain' / domain / content_type
                else:
                    # Fallback to unknown domain
                    new_dir = target_dir / 'by_domain' / 'unknown' / content_type
            else:
                # Organize by type only
                new_dir = target_dir / 'by_type' / content_type
            
            # Create directory
            new_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate new filename with timestamp
            timestamp = int(time.time())
            new_filename = f"{timestamp}_{file_path.name}"
            new_path = new_dir / new_filename
            
            # Copy file
            shutil.copy2(file_path, new_path)
            
            # Update index
            self.content_index[str(new_path)] = {
                'original_path': str(file_path),
                'content_type': content_type,
                'size': file_path.stat().st_size,
                'organized_at': timestamp
            }
            
            return new_path
            
        except Exception as e:
            self.logger.error(f"Failed to organize file {file_path}: {e}")
            return None
    
    def _organize_metadata(self, metadata_dir: Path, target_dir: Path):
        """Organize metadata files."""
        try:
            target_metadata_dir = target_dir / 'metadata'
            target_metadata_dir.mkdir(parents=True, exist_ok=True)
            
            for metadata_file in metadata_dir.glob('*.json'):
                try:
                    # Read metadata to get URL/domain
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                    
                    url = metadata.get('url', '')
                    if url:
                        domain = urlparse(url).netloc
                        
                        if self.organize_by_domain and domain:
                            new_dir = target_metadata_dir / domain
                            new_dir.mkdir(parents=True, exist_ok=True)
                            new_path = new_dir / metadata_file.name
                        else:
                            new_path = target_metadata_dir / metadata_file.name
                        
                        shutil.copy2(metadata_file, new_path)
                    else:
                        # Copy to root metadata dir
                        shutil.copy2(metadata_file, target_metadata_dir / metadata_file.name)
                        
                except Exception as e:
                    self.logger.error(f"Failed to organize metadata {metadata_file}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Failed to organize metadata directory: {e}")
    
    def _extract_domain_from_metadata(self, file_path: Path, content_root: Path) -> Optional[str]:
        """Extract domain from associated metadata file."""
        try:
            # Get file hash (assuming hash-based naming)
            file_stem = file_path.stem
            hash_match = re.search(r'[a-f0-9]{8,}', file_stem)
            
            if hash_match:
                file_hash = hash_match.group()
                
                # Look for corresponding metadata
                metadata_dir = content_root / 'metadata'
                if metadata_dir.exists():
                    for metadata_file in metadata_dir.glob('*.json'):
                        if file_hash in metadata_file.stem:
                            with open(metadata_file, 'r') as f:
                                metadata = json.load(f)
                            
                            url = metadata.get('url', '')
                            if url:
                                return urlparse(url).netloc
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Failed to extract domain for {file_path}: {e}")
            return None
    
    def _is_duplicate(self, file_path: Path) -> bool:
        """Check if file content is a duplicate."""
        try:
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            if file_hash in self.content_hashes:
                self.duplicate_count += 1
                return True
            
            self.content_hashes.add(file_hash)
            return False
            
        except Exception as e:
            self.logger.debug(f"Failed to check duplicate for {file_path}: {e}")
            return False
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file content."""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def _create_content_index(self, organized_dir: Path):
        """Create an index of organized content."""
        index_path = organized_dir / 'content_index.json'
        
        try:
            with open(index_path, 'w') as f:
                json.dump({
                    'created_at': time.time(),
                    'total_files': len(self.content_index),
                    'duplicate_count': self.duplicate_count,
                    'files': self.content_index
                }, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to create content index: {e}")
    
    def cleanup_old_content(self, days: Optional[int] = None):
        """
        Archive or remove old content based on age.
        
        Args:
            days: Number of days after which content is considered old
        """
        days = days or self.archive_after_days
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        
        self.logger.info(f"Cleaning up content older than {days} days")
        
        content_dir = self.data_storage_path / 'content'
        if not content_dir.exists():
            return
        
        archived = 0
        removed = 0
        
        for scan_dir in content_dir.iterdir():
            if scan_dir.is_dir():
                # Check modification time
                mtime = scan_dir.stat().st_mtime
                
                if mtime < cutoff_time:
                    if self.archive_old_content:
                        # Archive the content
                        archive_dir = self.data_storage_path / 'archive' / scan_dir.name
                        archive_dir.parent.mkdir(parents=True, exist_ok=True)
                        
                        try:
                            shutil.move(str(scan_dir), str(archive_dir))
                            archived += 1
                            self.logger.info(f"Archived: {scan_dir.name}")
                        except Exception as e:
                            self.logger.error(f"Failed to archive {scan_dir}: {e}")
                    else:
                        # Remove the content
                        try:
                            shutil.rmtree(scan_dir)
                            removed += 1
                            self.logger.info(f"Removed: {scan_dir.name}")
                        except Exception as e:
                            self.logger.error(f"Failed to remove {scan_dir}: {e}")
        
        self.logger.info(f"Cleanup complete: {archived} archived, {removed} removed")
    
    def check_storage_usage(self) -> Dict:
        """Check current storage usage."""
        total_size = 0
        file_count = 0
        size_by_type = defaultdict(int)
        
        content_dir = self.data_storage_path / 'content'
        if content_dir.exists():
            for root, dirs, files in os.walk(content_dir):
                for file in files:
                    file_path = Path(root) / file
                    size = file_path.stat().st_size
                    total_size += size
                    file_count += 1
                    
                    # Track by extension
                    ext = file_path.suffix.lower()
                    size_by_type[ext] += size
        
        # Convert to GB
        total_gb = total_size / (1024 ** 3)
        
        # Check if limit exceeded
        limit_exceeded = total_gb > self.max_storage_size_gb
        
        return {
            'total_size_gb': round(total_gb, 2),
            'total_files': file_count,
            'limit_gb': self.max_storage_size_gb,
            'limit_exceeded': limit_exceeded,
            'usage_percentage': round((total_gb / self.max_storage_size_gb) * 100, 2),
            'size_by_type': {
                ext: round(size / (1024 ** 2), 2)  # MB
                for ext, size in size_by_type.items()
            }
        }
    
    def find_content_by_domain(self, domain: str) -> List[Path]:
        """Find all content files for a specific domain."""
        content_files = []
        
        if self.organize_by_domain:
            domain_dir = self.data_storage_path / 'content' / 'by_domain' / domain
            if domain_dir.exists():
                for root, dirs, files in os.walk(domain_dir):
                    for file in files:
                        content_files.append(Path(root) / file)
        else:
            # Search through metadata
            for scan_dir in (self.data_storage_path / 'content').iterdir():
                if scan_dir.is_dir():
                    metadata_dir = scan_dir / 'metadata'
                    if metadata_dir.exists():
                        for metadata_file in metadata_dir.glob('*.json'):
                            try:
                                with open(metadata_file, 'r') as f:
                                    metadata = json.load(f)
                                
                                if domain in metadata.get('url', ''):
                                    # Find associated content files
                                    file_hash = metadata_file.stem
                                    for content_file in scan_dir.rglob(f'*{file_hash}*'):
                                        if content_file.is_file() and content_file.parent.name != 'metadata':
                                            content_files.append(content_file)
                                            
                            except Exception:
                                continue
        
        return content_files