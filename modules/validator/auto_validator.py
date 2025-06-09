#!/usr/bin/env python3
"""
Automated Validator for Secret Scanner with Database Integration
Validates discovered secrets by testing them against their respective services
"""

import os
import re
import json
import time
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from loguru import logger

# Import service-specific libraries (optional)
try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False
    logger.warning("boto3 not installed, AWS validation will be limited")

try:
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account
    HAS_GOOGLE = True
except ImportError:
    HAS_GOOGLE = False
    logger.warning("google-auth not installed, Google validation will be limited")


class AutoValidator:
    """Automated validation of discovered secrets with database integration"""
    
    def __init__(self, config: Dict[str, Any], db_manager=None):
        """
        Initialize Auto Validator
        
        Args:
            config: Configuration dictionary
            db_manager: DatabaseManager instance
        """
        self.config = config
        self.db = db_manager
        
        # Validation settings
        self.max_workers = config.get('validation', {}).get('max_workers', 5)
        self.timeout = config.get('validation', {}).get('timeout', 10)
        self.rate_limit_delay = config.get('validation', {}).get('rate_limit_delay', 1)
        
        # Validators for different secret types
        self.validators = {
            'aws_access_key': self._validate_aws_key,
            'aws': self._validate_aws_key,
            'github_token': self._validate_github_token,
            'github': self._validate_github_token,
            'slack_webhook': self._validate_slack_webhook,
            'slack': self._validate_slack_webhook,
            'google_api_key': self._validate_google_api_key,
            'google': self._validate_google_api_key,
            'stripe_key': self._validate_stripe_key,
            'stripe': self._validate_stripe_key,
            'sendgrid_key': self._validate_sendgrid_key,
            'sendgrid': self._validate_sendgrid_key,
            'twilio': self._validate_twilio_key,
            'mailgun': self._validate_mailgun_key,
            'jwt_token': self._validate_jwt_token,
            'jwt': self._validate_jwt_token,
            'generic_api_key': self._validate_generic_api
        }
        
        # Current scan run ID
        self.current_scan_run_id = None
        
        # Statistics
        self.stats = {
            'total_validated': 0,
            'valid_secrets': 0,
            'invalid_secrets': 0,
            'validation_errors': [],
            'validation_times': {},
            'by_type': {}
        }
        
        logger.info(f"Auto Validator initialized with {len(self.validators)} validators")
    
    def validate_findings_from_db(self, scan_run_id: int = None, finding_ids: List[int] = None,
                                 secret_types: List[str] = None, parallel: bool = True) -> Dict[str, Any]:
        """
        Load findings from database and validate them
        
        Args:
            scan_run_id: Specific scan run to validate
            finding_ids: Specific finding IDs to validate
            secret_types: Filter by secret types
            parallel: Whether to validate in parallel
            
        Returns:
            Validation summary
        """
        if not self.db:
            logger.error("No database connection available")
            return {}
        
        try:
            # Load findings from database
            findings = self._load_findings_from_db(scan_run_id, finding_ids, secret_types)
            
            if not findings:
                logger.info("No findings to validate")
                return {
                    'total_findings': 0,
                    'validated': 0,
                    'errors': []
                }
            
            logger.info(f"Loaded {len(findings)} findings from database for validation")
            
            # Set current scan run ID
            self.current_scan_run_id = scan_run_id
            
            # Validate findings
            return self.validate_findings(findings, parallel)
            
        except Exception as e:
            logger.error(f"Error validating findings from database: {e}")
            return {
                'error': str(e),
                'total_findings': 0,
                'validated': 0
            }
    
    def _load_findings_from_db(self, scan_run_id: int = None, finding_ids: List[int] = None,
                              secret_types: List[str] = None) -> List[Dict[str, Any]]:
        """
        Load findings from database
        
        Args:
            scan_run_id: Filter by scan run
            finding_ids: Specific finding IDs
            secret_types: Filter by secret types
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Build query
                query = """
                    SELECT 
                        f.id as finding_id,
                        f.secret_id,
                        f.url_id,
                        f.line_number,
                        f.snippet,
                        f.file_path,
                        f.validation_status,
                        f.validation_result,
                        s.secret_hash,
                        s.secret_type,
                        s.detector_name,
                        s.severity,
                        s.confidence,
                        s.is_verified,
                        u.url
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    LEFT JOIN urls u ON f.url_id = u.id
                    WHERE 1=1
                """
                
                params = []
                
                if scan_run_id:
                    query += " AND f.scan_run_id = ?"
                    params.append(scan_run_id)
                
                if finding_ids:
                    placeholders = ','.join(['?' for _ in finding_ids])
                    query += f" AND f.id IN ({placeholders})"
                    params.extend(finding_ids)
                
                if secret_types:
                    placeholders = ','.join(['?' for _ in secret_types])
                    query += f" AND s.secret_type IN ({placeholders})"
                    params.extend(secret_types)
                
                # Only get findings that haven't been validated or need re-validation
                query += " AND (f.validation_status IS NULL OR f.validation_status = 'pending')"
                
                cursor.execute(query, params)
                
                rows = cursor.fetchall()
                
                for row in rows:
                    finding = {
                        'finding_id': row[0],
                        'secret_id': row[1],
                        'url_id': row[2],
                        'line': row[3],
                        'context': row[4],
                        'file_path': row[5],
                        'validation_status': row[6],
                        'validation_result': json.loads(row[7]) if row[7] else {},
                        'secret_hash': row[8],
                        'type': row[9],
                        'detector': row[10],
                        'severity': row[11],
                        'confidence': row[12],
                        'verified': row[13],
                        'url': row[14],
                        # Note: We don't store the actual secret value in findings
                        # For validation, we would need to retrieve it from a secure location
                        # or re-scan the original file
                        'secret': ''  # Placeholder
                    }
                    findings.append(finding)
                
                logger.info(f"Loaded {len(findings)} findings from database")
                
        except Exception as e:
            logger.error(f"Error loading findings from database: {e}")
        
        return findings
    
    def validate_findings(self, findings: List[Dict[str, Any]], 
                         parallel: bool = True) -> Dict[str, Any]:
        """
        Validate a list of findings
        
        Args:
            findings: List of findings to validate
            parallel: Whether to validate in parallel
            
        Returns:
            Validation summary
        """
        try:
            logger.info(f"Starting validation of {len(findings)} findings")
            start_time = time.time()
            
            if parallel and len(findings) > 1:
                validated_findings = self._validate_parallel(findings)
            else:
                validated_findings = self._validate_sequential(findings)
            
            # Update validation results in database
            self._update_validation_results_in_db(validated_findings)
            
            # Update statistics
            elapsed_time = time.time() - start_time
            logger.info(f"Validation completed in {elapsed_time:.2f} seconds")
            logger.info(f"Valid: {self.stats['valid_secrets']}, "
                       f"Invalid: {self.stats['invalid_secrets']}, "
                       f"Errors: {len(self.stats['validation_errors'])}")
            
            # Generate and return summary
            return self.generate_validation_report(validated_findings)
            
        except Exception as e:
            logger.error(f"Error during validation: {e}")
            logger.exception(e)
            return {
                'error': str(e),
                'total_findings': len(findings),
                'validated': 0
            }
    
    def _validate_parallel(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate findings in parallel
        
        Args:
            findings: List of findings
            
        Returns:
            List of validated findings
        """
        validated_findings = []
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit validation tasks
                future_to_finding = {
                    executor.submit(self._validate_single_finding, finding): finding
                    for finding in findings
                }
                
                # Collect results
                for future in as_completed(future_to_finding):
                    try:
                        validated_finding = future.result()
                        validated_findings.append(validated_finding)
                    except Exception as e:
                        finding = future_to_finding[future]
                        logger.error(f"Validation error for finding: {e}")
                        finding['validation_error'] = str(e)
                        validated_findings.append(finding)
            
        except Exception as e:
            logger.error(f"Error in parallel validation: {e}")
            return findings
        
        return validated_findings
    
    def _validate_sequential(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate findings sequentially
        
        Args:
            findings: List of findings
            
        Returns:
            List of validated findings
        """
        validated_findings = []
        
        for finding in findings:
            try:
                validated_finding = self._validate_single_finding(finding)
                validated_findings.append(validated_finding)
                
                # Rate limiting
                time.sleep(self.rate_limit_delay)
                
            except Exception as e:
                logger.error(f"Validation error: {e}")
                finding['validation_error'] = str(e)
                validated_findings.append(finding)
        
        return validated_findings
    
    def _validate_single_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a single finding
        
        Args:
            finding: Finding to validate
            
        Returns:
            Finding with validation results
        """
        try:
            finding_type = finding.get('type', '').lower()
            secret = finding.get('secret', '')
            
            # Skip if already validated
            if finding.get('validation_status') == 'completed':
                return finding
            
            # For database-based findings, we need to retrieve the actual secret
            # This is a placeholder - in production, you'd retrieve from secure storage
            if not secret and 'secret_hash' in finding:
                # In a real implementation, you would:
                # 1. Retrieve the actual secret from secure storage using the hash
                # 2. Or re-read from the original file using file_path and line number
                finding['validation_result'] = {
                    'valid': None,
                    'reason': 'Secret value not available for validation',
                    'validated_at': datetime.utcnow().isoformat()
                }
                return finding
            
            # Skip if no secret
            if not secret:
                finding['validation_result'] = {
                    'valid': False,
                    'reason': 'No secret found',
                    'validated_at': datetime.utcnow().isoformat()
                }
                return finding
            
            # Find appropriate validator
            validator = None
            for key, validator_func in self.validators.items():
                if key in finding_type:
                    validator = validator_func
                    break
            
            if not validator:
                # Try generic validation
                validator = self.validators.get('generic_api_key')
                logger.debug(f"No specific validator for type '{finding_type}', using generic")
            
            # Perform validation
            if validator:
                valid, details = validator(secret, finding)
                finding['validation_result'] = {
                    'valid': valid,
                    'details': details,
                    'validated_at': datetime.utcnow().isoformat(),
                    'validator': validator.__name__
                }
            else:
                finding['validation_result'] = {
                    'valid': None,
                    'reason': 'No validator available',
                    'validated_at': datetime.utcnow().isoformat()
                }
            
            # Update statistics
            self.stats['total_validated'] += 1
            if finding['validation_result']['valid'] is True:
                self.stats['valid_secrets'] += 1
            elif finding['validation_result']['valid'] is False:
                self.stats['invalid_secrets'] += 1
            
            # Track by type
            type_stats = self.stats['by_type'].get(finding_type, {
                'total': 0, 'valid': 0, 'invalid': 0
            })
            type_stats['total'] += 1
            if finding['validation_result']['valid'] is True:
                type_stats['valid'] += 1
            elif finding['validation_result']['valid'] is False:
                type_stats['invalid'] += 1
            self.stats['by_type'][finding_type] = type_stats
            
            return finding
            
        except Exception as e:
            logger.error(f"Error validating finding: {e}")
            finding['validation_error'] = str(e)
            self.stats['validation_errors'].append({
                'finding_type': finding.get('type'),
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
            return finding
    
    def _update_validation_results_in_db(self, validated_findings: List[Dict[str, Any]]) -> None:
        """
        Update validation results in database
        
        Args:
            validated_findings: List of validated findings
        """
        if not self.db:
            logger.warning("No database connection available")
            return
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                for finding in validated_findings:
                    if 'finding_id' not in finding:
                        continue
                    
                    validation_result = finding.get('validation_result', {})
                    validation_status = 'completed'
                    
                    if 'validation_error' in finding:
                        validation_status = 'error'
                        validation_result['error'] = finding['validation_error']
                    
                    # Update finding
                    cursor.execute("""
                        UPDATE findings
                        SET validation_status = ?,
                            validation_result = ?,
                            validated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """, (
                        validation_status,
                        json.dumps(validation_result),
                        finding['finding_id']
                    ))
                    
                    # Update secret verification status if validated
                    if validation_result.get('valid') is True and 'secret_id' in finding:
                        cursor.execute("""
                            UPDATE secrets
                            SET is_verified = 1
                            WHERE id = ?
                        """, (finding['secret_id'],))
                
                conn.commit()
                logger.info(f"Updated {len(validated_findings)} validation results in database")
                
        except Exception as e:
            logger.error(f"Error updating validation results in database: {e}")
    
    def _validate_aws_key(self, secret: str, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate AWS access key
        
        Args:
            secret: AWS access key
            finding: Full finding data
            
        Returns:
            Tuple of (is_valid, details)
        """
        try:
            # Extract secret key if available
            metadata = finding.get('metadata', {})
            extra_data = metadata.get('extra_data', {})
            
            # Look for secret key in various places
            secret_key = None
            if 'secret' in extra_data:
                secret_key = extra_data['secret']
            elif 'aws_secret' in metadata:
                secret_key = metadata['aws_secret']
            
            if not secret_key:
                # Try to find secret key near the access key
                # This is a simplified approach
                return False, {'reason': 'Secret key not found with access key'}
            
            if HAS_BOTO3:
                # Use boto3 to validate
                try:
                    sts_client = boto3.client(
                        'sts',
                        aws_access_key_id=secret,
                        aws_secret_access_key=secret_key
                    )
                    
                    # Try to get caller identity
                    response = sts_client.get_caller_identity()
                    
                    return True, {
                        'account': response.get('Account'),
                        'arn': response.get('Arn'),
                        'user_id': response.get('UserId')
                    }
                    
                except Exception as e:
                    return False, {'reason': str(e)}
            else:
                # Fallback to HTTP request
                # This is a simplified validation
                return None, {'reason': 'boto3 not available for full validation'}
                
        except Exception as e:
            logger.error(f"Error validating AWS key: {e}")
            return False, {'error': str(e)}
    
    def _validate_github_token(self, secret: str, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate GitHub token
        
        Args:
            secret: GitHub token
            finding: Full finding data
            
        Returns:
            Tuple of (is_valid, details)
        """
        try:
            headers = {
                'Authorization': f'token {secret}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            response = requests.get(
                'https://api.github.com/user',
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                user_data = response.json()
                return True, {
                    'user': user_data.get('login'),
                    'name': user_data.get('name'),
                    'scopes': response.headers.get('X-OAuth-Scopes', '').split(', ')
                }
            elif response.status_code == 401:
                return False, {'reason': 'Invalid token'}
            else:
                return False, {
                    'reason': f'Unexpected status code: {response.status_code}'
                }
                
        except requests.RequestException as e:
            logger.error(f"Error validating GitHub token: {e}")
            return False, {'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error validating GitHub token: {e}")
            return False, {'error': str(e)}
    
    def _validate_slack_webhook(self, secret: str, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate Slack webhook
        
        Args:
            secret: Slack webhook URL
            finding: Full finding data
            
        Returns:
            Tuple of (is_valid, details)
        """
        try:
            # Validate URL format
            if not re.match(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}', secret):
                return False, {'reason': 'Invalid webhook URL format'}
            
            # Test with a minimal payload
            test_payload = {
                'text': 'Security validation test - please ignore',
                'channel': '#security-test',
                'username': 'Security Scanner Validator'
            }
            
            response = requests.post(
                secret,
                json=test_payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200 and response.text == 'ok':
                return True, {'status': 'Active webhook'}
            else:
                return False, {
                    'reason': f'Invalid response: {response.status_code} - {response.text}'
                }
                
        except requests.RequestException as e:
            logger.error(f"Error validating Slack webhook: {e}")
            return False, {'error': str(e)}
        except Exception as e:
            logger.error(f"Unexpected error validating Slack webhook: {e}")
            return False, {'error': str(e)}
    
    def _validate_google_api_key(self, secret: str, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate Google API key
        
        Args:
            secret: Google API key
            finding: Full finding data
            
        Returns:
            Tuple of (is_valid, details)
        """
        try:
            # Test with Maps API (commonly used)
            test_url = 'https://maps.googleapis.com/maps/api/geocode/json'
            params = {
                'address': '1600 Amphitheatre Parkway, Mountain View, CA',
                'key': secret
            }
            
            response = requests.get(
                test_url,
                params=params,
                timeout=self.timeout
            )
            
            data = response.json()
            
            if response.status_code == 200 and data.get('status') == 'OK':
                return True, {'service': 'Google Maps API', 'status': 'Active'}
            elif data.get('error_message'):
                return False, {'reason': data['error_message']}
            else:
                return False, {'reason': f'API returned status: {data.get("status")}'}
                
        except Exception as e:
            logger.error(f"Error validating Google API key: {e}")
            return False, {'error': str(e)}
    
    def _validate_stripe_key(self, secret: str, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate Stripe API key
        
        Args:
            secret: Stripe API key
            finding: Full finding data
            
        Returns:
            Tuple of (is_valid, details)
        """
        try:
            # Check key format
            if secret.startswith('sk_test_'):
                key_type = 'test'
            elif secret.startswith('sk_live_'):
                key_type = 'live'
            else:
                return False, {'reason': 'Invalid Stripe key format'}
            
            # Test the key
            headers = {
                'Authorization': f'Bearer {secret}'
            }
            
            response = requests.get(
                'https://api.stripe.com/v1/charges?limit=1',
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return True, {'key_type': key_type, 'status': 'Active'}
            elif response.status_code == 401:
                return False, {'reason': 'Invalid API key'}
            else:
                return False, {'reason': f'Unexpected status: {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Error validating Stripe key: {e}")
            return False, {'error': str(e)}
    
    def _validate_sendgrid_key(self, secret: str, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate SendGrid API key
        
        Args:
            secret: SendGrid API key
            finding: Full finding data
            
        Returns:
            Tuple of (is_valid, details)
        """
        try:
            headers = {
                'Authorization': f'Bearer {secret}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                'https://api.sendgrid.com/v3/scopes',
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                return True, {
                    'scopes': data.get('scopes', []),
                    'status': 'Active'
                }
            elif response.status_code == 401:
                return False, {'reason': 'Invalid API key'}
            else:
                return False, {'reason': f'Unexpected status: {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Error validating SendGrid key: {e}")
            return False, {'error': str(e)}
    
    def _validate_twilio_key(self, secret: str, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate Twilio credentials
        
        Args:
            secret: Twilio Account SID or Auth Token
            finding: Full finding data
            
        Returns:
            Tuple of (is_valid, details)
        """
        try:
            # Twilio validation requires both Account SID and Auth Token
            # This is a simplified check
            if secret.startswith('AC') and len(secret) == 34:
                return None, {'reason': 'Account SID detected, Auth Token needed for validation'}
            elif secret.startswith('SK') and len(secret) == 32:
                return None, {'reason': 'API Key SID detected, API Key Secret needed for validation'}
            else:
                return False, {'reason': 'Unknown Twilio credential format'}
                
        except Exception as e:
            logger.error(f"Error validating Twilio key: {e}")
            return False, {'error': str(e)}
    
    def _validate_mailgun_key(self, secret: str, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate Mailgun API key
        
        Args:
            secret: Mailgun API key
            finding: Full finding data
            
        Returns:
            Tuple of (is_valid, details)
        """
        try:
            # Need domain for full validation
            # Using a test endpoint
            response = requests.get(
                'https://api.mailgun.net/v3/domains',
                auth=('api', secret),
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                return True, {
                    'domains_count': data.get('total_count', 0),
                    'status': 'Active'
                }
            elif response.status_code == 401:
                return False, {'reason': 'Invalid API key'}
            else:
                return False, {'reason': f'Unexpected status: {response.status_code}'}
                
        except Exception as e:
            logger.error(f"Error validating Mailgun key: {e}")
            return False, {'error': str(e)}
    
    def _validate_jwt_token(self, secret: str, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate JWT token structure
        
        Args:
            secret: JWT token
            finding: Full finding data
            
        Returns:
            Tuple of (is_valid, details)
        """
        try:
            # Basic JWT validation without verification
            parts = secret.split('.')
            if len(parts) != 3:
                return False, {'reason': 'Invalid JWT structure'}
            
            # Decode header and payload (without verification)
            import base64
            
            try:
                # Add padding if needed
                header_part = parts[0] + '=' * (4 - len(parts[0]) % 4)
                payload_part = parts[1] + '=' * (4 - len(parts[1]) % 4)
                
                header = json.loads(base64.urlsafe_b64decode(header_part))
                payload = json.loads(base64.urlsafe_b64decode(payload_part))
                
                # Check expiration
                exp = payload.get('exp')
                if exp and exp < time.time():
                    return False, {
                        'reason': 'Token expired',
                        'expired_at': datetime.fromtimestamp(exp).isoformat()
                    }
                
                return None, {
                    'reason': 'JWT structure valid but cannot verify signature',
                    'algorithm': header.get('alg'),
                    'issuer': payload.get('iss'),
                    'subject': payload.get('sub'),
                    'expiration': datetime.fromtimestamp(exp).isoformat() if exp else None
                }
                
            except Exception as e:
                return False, {'reason': f'Invalid JWT encoding: {e}'}
                
        except Exception as e:
            logger.error(f"Error validating JWT: {e}")
            return False, {'error': str(e)}
    
    def _validate_generic_api(self, secret: str, finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Generic API key validation
        
        Args:
            secret: API key
            finding: Full finding data
            
        Returns:
            Tuple of (is_valid, details)
        """
        try:
            # Basic format validation
            if len(secret) < 10:
                return False, {'reason': 'Key too short'}
            
            # Check for common test/example patterns
            test_patterns = [
                'test', 'example', 'demo', 'sample', 'xxx', '123', 
                'your_api_key', 'api_key_here', 'replace_me'
            ]
            
            secret_lower = secret.lower()
            for pattern in test_patterns:
                if pattern in secret_lower:
                    return False, {'reason': f'Appears to be a test/example key (contains "{pattern}")'}
            
            # Check entropy (simplified)
            unique_chars = len(set(secret))
            if unique_chars < 5:
                return False, {'reason': 'Low entropy (too few unique characters)'}
            
            return None, {'reason': 'Cannot validate generic API key without service context'}
            
        except Exception as e:
            logger.error(f"Error in generic validation: {e}")
            return False, {'error': str(e)}
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get validation statistics
        
        Returns:
            Statistics dictionary
        """
        return self.stats
    
    def generate_validation_report(self, validated_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a validation report
        
        Args:
            validated_findings: List of validated findings
            
        Returns:
            Validation report
        """
        try:
            report = {
                'summary': {
                    'total_findings': len(validated_findings),
                    'validated': sum(1 for f in validated_findings if 'validation_result' in f),
                    'valid_secrets': sum(1 for f in validated_findings 
                                       if f.get('validation_result', {}).get('valid') is True),
                    'invalid_secrets': sum(1 for f in validated_findings 
                                         if f.get('validation_result', {}).get('valid') is False),
                    'unknown_validity': sum(1 for f in validated_findings 
                                          if f.get('validation_result', {}).get('valid') is None),
                    'validation_errors': len(self.stats['validation_errors'])
                },
                'by_type': self.stats['by_type'],
                'critical_findings': [],
                'validation_errors': self.stats['validation_errors']
            }
            
            # Identify critical findings (valid secrets with high severity)
            for finding in validated_findings:
                if (finding.get('validation_result', {}).get('valid') is True and
                    finding.get('severity') in ['critical', 'high']):
                    report['critical_findings'].append({
                        'type': finding.get('type'),
                        'severity': finding.get('severity'),
                        'location': finding.get('file_path') or finding.get('url'),
                        'validated_at': finding.get('validation_result', {}).get('validated_at'),
                        'finding_id': finding.get('finding_id')
                    })
            
            # Update scan run statistics if we have a scan run ID
            if self.current_scan_run_id and self.db:
                self._update_scan_run_validation_stats(report)
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating validation report: {e}")
            return {}
    
    def _update_scan_run_validation_stats(self, report: Dict[str, Any]) -> None:
        """
        Update scan run with validation statistics
        
        Args:
            report: Validation report
        """
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE scan_runs
                    SET validation_stats = ?,
                        validated_secrets_count = ?,
                        valid_secrets_count = ?
                    WHERE id = ?
                """, (
                    json.dumps(report),
                    report['summary']['validated'],
                    report['summary']['valid_secrets'],
                    self.current_scan_run_id
                ))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error updating scan run validation stats: {e}")
    
    def validate_specific_secret(self, secret_hash: str) -> Dict[str, Any]:
        """
        Validate a specific secret by its hash
        
        Args:
            secret_hash: SHA256 hash of the secret
            
        Returns:
            Validation result
        """
        if not self.db:
            return {'error': 'No database connection'}
        
        try:
            # Get all findings for this secret
            findings = self._load_findings_for_secret_hash(secret_hash)
            
            if not findings:
                return {
                    'error': 'No findings for this secret hash',
                    'secret_hash': secret_hash
                }
            
            # Validate all findings for this secret
            validated = self.validate_findings(findings, parallel=False)
            
            return {
                'secret_hash': secret_hash,
                'findings_validated': len(findings),
                'validation_report': validated
            }
            
        except Exception as e:
            logger.error(f"Error validating specific secret: {e}")
            return {
                'error': str(e),
                'secret_hash': secret_hash
            }
    
    def _load_findings_for_secret_hash(self, secret_hash: str) -> List[Dict[str, Any]]:
        """
        Load all findings for a specific secret hash
        
        Args:
            secret_hash: SHA256 hash of the secret
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            with self.db.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT 
                        f.id as finding_id,
                        f.secret_id,
                        f.url_id,
                        f.line_number,
                        f.snippet,
                        f.file_path,
                        f.validation_status,
                        f.validation_result,
                        s.secret_type,
                        s.detector_name,
                        s.severity,
                        s.confidence,
                        s.is_verified,
                        u.url
                    FROM findings f
                    JOIN secrets s ON f.secret_id = s.id
                    LEFT JOIN urls u ON f.url_id = u.id
                    WHERE s.secret_hash = ?
                """, (secret_hash,))
                
                rows = cursor.fetchall()
                
                for row in rows:
                    finding = {
                        'finding_id': row[0],
                        'secret_id': row[1],
                        'url_id': row[2],
                        'line': row[3],
                        'context': row[4],
                        'file_path': row[5],
                        'validation_status': row[6],
                        'validation_result': json.loads(row[7]) if row[7] else {},
                        'type': row[8],
                        'detector': row[9],
                        'severity': row[10],
                        'confidence': row[11],
                        'verified': row[12],
                        'url': row[13],
                        'secret_hash': secret_hash,
                        'secret': ''  # Placeholder
                    }
                    findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error loading findings for secret hash: {e}")
        
        return findings