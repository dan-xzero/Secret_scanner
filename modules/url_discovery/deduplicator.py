"""
URL Deduplicator Module

Handles deduplication of discovered URLs using various strategies:
- Exact match deduplication
- Parameter normalization
- Fragment removal
- Case normalization
"""

import re
import hashlib
from typing import List, Set, Dict, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from collections import defaultdict
import logging

from loguru import logger


class URLDeduplicator:
    """Deduplicates URLs using various normalization strategies."""
    
    def __init__(self, config: Optional[Dict] = None, logger: Optional[logging.Logger] = None):
        """
        Initialize URL Deduplicator.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config or {}
        self.logger = logger or logging.getLogger(__name__)
        
        # Deduplication settings
        self.normalize_case = self.config.get('normalize_case', True)
        self.remove_fragments = self.config.get('remove_fragments', True)
        self.sort_parameters = self.config.get('sort_parameters', True)
        self.remove_empty_parameters = self.config.get('remove_empty_parameters', True)
        self.parameter_blacklist = set(self.config.get('parameter_blacklist', [
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'fbclid', 'gclid', 'dclid', 'msclkid',
            '_ga', '_gid', '_gat',
            'ref', 'referrer',
            'timestamp', 'ts', 't',
            'cb', 'cache', 'v', 'ver', 'version'
        ]))
        
        # Statistics
        self.stats = {
            'total_processed': 0,
            'duplicates_removed': 0,
            'normalized_urls': 0
        }
    
    def deduplicate(self, urls: List[str]) -> List[str]:
        """
        Deduplicate a list of URLs.
        
        Args:
            urls: List of URLs to deduplicate
            
        Returns:
            List of unique URLs
        """
        self.logger.info(f"Starting deduplication of {len(urls)} URLs")
        self.stats['total_processed'] = len(urls)
        
        # First pass: exact deduplication
        unique_urls = list(set(urls))
        exact_duplicates = len(urls) - len(unique_urls)
        
        if exact_duplicates > 0:
            self.logger.debug(f"Removed {exact_duplicates} exact duplicates")
        
        # Second pass: normalized deduplication
        normalized_map = {}
        final_urls = []
        
        for url in unique_urls:
            try:
                normalized_url = self.normalize_url(url)
                url_hash = self._hash_url(normalized_url)
                
                if url_hash not in normalized_map:
                    normalized_map[url_hash] = url
                    final_urls.append(url)
                else:
                    self.stats['duplicates_removed'] += 1
                    
            except Exception as e:
                self.logger.warning(f"Error normalizing URL '{url}': {e}")
                # Keep the URL if normalization fails
                final_urls.append(url)
        
        self.logger.info(
            f"Deduplication complete: {len(urls)} → {len(final_urls)} URLs "
            f"({len(urls) - len(final_urls)} removed)"
        )
        
        return final_urls
    
    def normalize_url(self, url: str) -> str:
        """
        Normalize a URL for deduplication.
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        try:
            # Parse URL
            parsed = urlparse(url)
            
            # Normalize scheme and netloc
            scheme = parsed.scheme.lower() if self.normalize_case else parsed.scheme
            netloc = parsed.netloc.lower() if self.normalize_case else parsed.netloc
            
            # Normalize path
            path = self._normalize_path(parsed.path)
            
            # Process query parameters
            params = self._normalize_parameters(parsed.query)
            
            # Handle fragment
            fragment = '' if self.remove_fragments else parsed.fragment
            
            # Reconstruct URL
            normalized = urlunparse((
                scheme,
                netloc,
                path,
                parsed.params,
                params,
                fragment
            ))
            
            self.stats['normalized_urls'] += 1
            return normalized
            
        except Exception as e:
            self.logger.debug(f"Failed to normalize URL '{url}': {e}")
            return url
    
    def _normalize_path(self, path: str) -> str:
        """Normalize URL path."""
        if not path:
            return '/'
        
        # Remove duplicate slashes
        path = re.sub(r'/+', '/', path)
        
        # Remove trailing slash (except for root)
        if path != '/' and path.endswith('/'):
            path = path.rstrip('/')
        
        # Resolve relative paths
        parts = []
        for part in path.split('/'):
            if part == '..':
                if parts and parts[-1] != '..':
                    parts.pop()
                else:
                    parts.append(part)
            elif part and part != '.':
                parts.append(part)
        
        return '/' + '/'.join(parts) if parts else '/'
    
    def _normalize_parameters(self, query_string: str) -> str:
        """Normalize query parameters."""
        if not query_string:
            return ''
        
        try:
            # Parse parameters
            params = parse_qs(query_string, keep_blank_values=not self.remove_empty_parameters)
            
            # Remove blacklisted parameters
            filtered_params = {}
            for key, values in params.items():
                key_lower = key.lower()
                if key_lower not in self.parameter_blacklist:
                    filtered_params[key] = values
            
            if not filtered_params:
                return ''
            
            # Sort parameters if requested
            if self.sort_parameters:
                sorted_params = sorted(filtered_params.items())
            else:
                sorted_params = list(filtered_params.items())
            
            # Reconstruct query string
            query_parts = []
            for key, values in sorted_params:
                for value in values:
                    if value:
                        query_parts.append(f"{key}={value}")
                    elif not self.remove_empty_parameters:
                        query_parts.append(key)
            
            return '&'.join(query_parts)
            
        except Exception as e:
            self.logger.debug(f"Failed to normalize parameters '{query_string}': {e}")
            return query_string
    
    def _hash_url(self, url: str) -> str:
        """Generate a hash for a URL."""
        return hashlib.md5(url.encode('utf-8')).hexdigest()
    
    def find_similar_urls(self, urls: List[str], similarity_threshold: float = 0.8) -> Dict[str, List[str]]:
        """
        Find groups of similar URLs.
        
        Args:
            urls: List of URLs to analyze
            similarity_threshold: Minimum similarity score (0-1)
            
        Returns:
            Dictionary mapping representative URL to list of similar URLs
        """
        self.logger.info(f"Finding similar URLs among {len(urls)} URLs")
        
        # Group by domain and path pattern
        url_groups = defaultdict(list)
        
        for url in urls:
            try:
                parsed = urlparse(url)
                # Create a pattern from the path
                path_pattern = self._extract_path_pattern(parsed.path)
                group_key = f"{parsed.netloc}:{path_pattern}"
                url_groups[group_key].append(url)
            except Exception as e:
                self.logger.debug(f"Error processing URL '{url}': {e}")
        
        # Find similar URLs within each group
        similar_groups = {}
        
        for group_key, group_urls in url_groups.items():
            if len(group_urls) > 1:
                # Use the first URL as representative
                representative = group_urls[0]
                similar_groups[representative] = group_urls
        
        self.logger.info(f"Found {len(similar_groups)} groups of similar URLs")
        
        return similar_groups
    
    def _extract_path_pattern(self, path: str) -> str:
        """Extract a pattern from URL path for grouping."""
        # Replace common dynamic segments with placeholders
        pattern = path
        
        # Numbers (IDs, timestamps, etc.)
        pattern = re.sub(r'/\d+', '/{id}', pattern)
        
        # UUIDs
        pattern = re.sub(
            r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            '/{uuid}',
            pattern,
            flags=re.IGNORECASE
        )
        
        # Hashes (MD5, SHA1, SHA256, etc.)
        pattern = re.sub(r'/[a-f0-9]{32,64}', '/{hash}', pattern, flags=re.IGNORECASE)
        
        # File names with extensions
        pattern = re.sub(r'/[^/]+\.(jpg|jpeg|png|gif|pdf|doc|docx)', '/{file}', pattern)
        
        # Date patterns
        pattern = re.sub(r'/\d{4}-\d{2}-\d{2}', '/{date}', pattern)
        pattern = re.sub(r'/\d{4}/\d{2}/\d{2}', '/{date}', pattern)
        
        return pattern
    
    def merge_url_lists(self, *url_lists: List[str]) -> List[str]:
        """
        Merge multiple URL lists and deduplicate.
        
        Args:
            url_lists: Variable number of URL lists
            
        Returns:
            Merged and deduplicated list of URLs
        """
        all_urls = []
        
        for url_list in url_lists:
            all_urls.extend(url_list)
        
        self.logger.info(f"Merging {len(url_lists)} lists with total {len(all_urls)} URLs")
        
        return self.deduplicate(all_urls)
    
    def get_statistics(self) -> Dict:
        """Get deduplication statistics."""
        return {
            'total_processed': self.stats['total_processed'],
            'duplicates_removed': self.stats['duplicates_removed'],
            'normalized_urls': self.stats['normalized_urls'],
            'deduplication_rate': (
                self.stats['duplicates_removed'] / self.stats['total_processed']
                if self.stats['total_processed'] > 0 else 0
            )
        }
    
    def reset_statistics(self):
        """Reset statistics counters."""
        self.stats = {
            'total_processed': 0,
            'duplicates_removed': 0,
            'normalized_urls': 0
        }


class SmartDeduplicator(URLDeduplicator):
    """
    Advanced URL deduplicator with machine learning-like pattern recognition.
    """
    
    def __init__(self, config: Optional[Dict] = None, logger: Optional[logging.Logger] = None):
        """Initialize Smart Deduplicator."""
        super().__init__(config, logger)
        
        # Additional settings for smart deduplication
        self.learn_patterns = self.config.get('learn_patterns', True)
        self.pattern_threshold = self.config.get('pattern_threshold', 5)
        
        # Learned patterns
        self.learned_patterns = defaultdict(int)
        self.parameter_patterns = defaultdict(set)
    
    def deduplicate_smart(self, urls: List[str]) -> List[str]:
        """
        Perform smart deduplication with pattern learning.
        
        Args:
            urls: List of URLs to deduplicate
            
        Returns:
            List of unique URLs
        """
        # First, perform standard deduplication
        deduplicated = self.deduplicate(urls)
        
        if self.learn_patterns:
            # Learn patterns from the URLs
            self._learn_url_patterns(deduplicated)
            
            # Apply learned patterns for further deduplication
            deduplicated = self._apply_learned_patterns(deduplicated)
        
        return deduplicated
    
    def _learn_url_patterns(self, urls: List[str]):
        """Learn patterns from URLs."""
        for url in urls:
            try:
                parsed = urlparse(url)
                
                # Learn path patterns
                path_parts = [p for p in parsed.path.split('/') if p]
                for i, part in enumerate(path_parts):
                    if re.match(r'^\d+$', part):  # Numeric ID
                        pattern = f"position_{i}_numeric"
                        self.learned_patterns[pattern] += 1
                    elif re.match(r'^[a-f0-9]{32,}$', part, re.IGNORECASE):  # Hash
                        pattern = f"position_{i}_hash"
                        self.learned_patterns[pattern] += 1
                
                # Learn parameter patterns
                if parsed.query:
                    params = parse_qs(parsed.query)
                    param_set = frozenset(params.keys())
                    self.parameter_patterns[parsed.netloc].add(param_set)
                    
            except Exception as e:
                self.logger.debug(f"Error learning from URL '{url}': {e}")
    
    def _apply_learned_patterns(self, urls: List[str]) -> List[str]:
        """Apply learned patterns to further deduplicate URLs."""
        # Group URLs by learned patterns
        pattern_groups = defaultdict(list)
        
        for url in urls:
            pattern_key = self._get_url_pattern_key(url)
            pattern_groups[pattern_key].append(url)
        
        # Select representative URLs from each group
        final_urls = []
        
        for pattern_key, group_urls in pattern_groups.items():
            if len(group_urls) > self.pattern_threshold:
                # This looks like a pattern, keep only one representative
                final_urls.append(group_urls[0])
                self.stats['duplicates_removed'] += len(group_urls) - 1
            else:
                # Not enough examples to be sure, keep all
                final_urls.extend(group_urls)
        
        return final_urls
    
    def _get_url_pattern_key(self, url: str) -> str:
        """Generate a pattern key for a URL based on learned patterns."""
        try:
            parsed = urlparse(url)
            
            # Create pattern key
            path_pattern = self._extract_path_pattern(parsed.path)
            
            # Include parameter structure
            param_structure = 'no_params'
            if parsed.query:
                params = parse_qs(parsed.query)
                param_structure = '_'.join(sorted(params.keys()))
            
            return f"{parsed.netloc}:{path_pattern}:{param_structure}"
            
        except Exception:
            return url  # Use URL itself as key if pattern extraction failss