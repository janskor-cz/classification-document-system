#!/usr/bin/env python3
"""
Ephemeral DID Security Validator
Working Package 3 - Phase 5 - Task 5.2

Advanced security validation system for ephemeral DID operations.
Provides authenticity checking, reuse detection, session security validation, and usage reporting.
"""

import json
import re
import base58
import hashlib
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
import psycopg2
from psycopg2.extras import RealDictCursor

from config import Config


class EphemeralDIDSecurityValidator:
    """Advanced security validator for ephemeral DID operations (Task 5.2)"""
    
    def __init__(self, config: Config):
        """Initialize security validator with configuration"""
        self.config = config
        self.db_url = config.get_database_url()
        
        # Security validation thresholds
        self.max_did_reuse_attempts = 3
        self.suspicious_session_count_threshold = 10
        self.rapid_session_creation_threshold = 5  # sessions per minute
        self.max_concurrent_sessions_per_user = 3
        self.session_duration_warning_threshold = timedelta(hours=4)
        
        # DID format validation patterns
        self.did_key_pattern = re.compile(r'^did:key:z[1-9A-HJ-NP-Za-km-z]+$')
        self.multibase_z_pattern = re.compile(r'^z[1-9A-HJ-NP-Za-km-z]+$')
        
    def get_db_connection(self):
        """Get database connection with proper error handling"""
        try:
            conn = psycopg2.connect(
                self.db_url,
                cursor_factory=RealDictCursor
            )
            return conn
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return None
    
    def validate_ephemeral_did_authenticity(self, ephemeral_did: str,
                                          ephemeral_public_key: str = None,
                                          user_identity_hash: str = None) -> Dict[str, Any]:
        """
        Validate the authenticity and format of an ephemeral DID
        
        Args:
            ephemeral_did: DID to validate (e.g., did:key:z6Mk...)
            ephemeral_public_key: Optional public key to verify against DID
            user_identity_hash: Optional user context for validation
            
        Returns:
            Dict with validation results and security analysis
        """
        try:
            validation_results = {
                'did_format_valid': False,
                'did_structure_valid': False,
                'public_key_consistent': False,
                'multibase_encoding_valid': False,
                'key_material_valid': False,
                'security_warnings': [],
                'validation_details': {}
            }
            
            # 1. Basic DID format validation
            if not ephemeral_did or not isinstance(ephemeral_did, str):
                validation_results['validation_details']['error'] = 'Invalid DID format: DID must be a non-empty string'
                return {
                    'success': True,
                    'valid': False,
                    'validation': validation_results
                }
            
            # 2. DID:key format pattern matching
            if not self.did_key_pattern.match(ephemeral_did):
                validation_results['validation_details']['format_error'] = 'DID does not match did:key format'
            else:
                validation_results['did_format_valid'] = True
            
            # 3. Extract and validate multibase-encoded key material
            if ephemeral_did.startswith('did:key:'):
                key_material = ephemeral_did[8:]  # Remove 'did:key:' prefix
                
                if self.multibase_z_pattern.match(key_material):
                    validation_results['multibase_encoding_valid'] = True
                    validation_results['did_structure_valid'] = True
                    
                    try:
                        # Attempt to decode the multibase-encoded key material
                        decoded_key = base58.b58decode(key_material[1:])  # Remove 'z' prefix
                        validation_results['key_material_valid'] = len(decoded_key) >= 32  # Minimum key length
                        validation_results['validation_details']['key_length'] = len(decoded_key)
                        
                    except Exception as decode_error:
                        validation_results['security_warnings'].append(
                            f'Key material decoding failed: {str(decode_error)}'
                        )
                else:
                    validation_results['security_warnings'].append('Invalid multibase encoding format')
            
            # 4. Public key consistency check (if provided)
            if ephemeral_public_key:
                # This is a placeholder for actual cryptographic validation
                # In production, this would verify the public key matches the DID
                validation_results['public_key_consistent'] = True
                validation_results['validation_details']['public_key_provided'] = True
            
            # 5. Check for security concerns
            security_warnings = []
            
            # Check DID length (too short might indicate weak entropy)
            if len(ephemeral_did) < 50:
                security_warnings.append('DID appears unusually short - potential weak entropy')
            
            # Check for sequential patterns (basic entropy check)
            if self._has_sequential_patterns(ephemeral_did):
                security_warnings.append('DID contains sequential patterns - potential weak randomness')
            
            validation_results['security_warnings'].extend(security_warnings)
            
            # 6. Database-based validation (if user context provided)
            if user_identity_hash:
                db_validation = self._validate_against_database(ephemeral_did, user_identity_hash)
                validation_results['validation_details']['database_checks'] = db_validation
                validation_results['security_warnings'].extend(db_validation.get('warnings', []))
            
            # 7. Overall validation result
            is_valid = (
                validation_results['did_format_valid'] and
                validation_results['did_structure_valid'] and
                validation_results['multibase_encoding_valid'] and
                validation_results['key_material_valid'] and
                len(validation_results['security_warnings']) == 0
            )
            
            return {
                'success': True,
                'valid': is_valid,
                'validation': validation_results,
                'security_score': self._calculate_security_score(validation_results),
                'recommendations': self._generate_security_recommendations(validation_results)
            }
            
        except Exception as e:
            print(f"❌ Error validating ephemeral DID authenticity: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'DID authenticity validation failed: {str(e)}',
                'valid': False
            }
    
    def detect_ephemeral_did_reuse(self, ephemeral_did: str,
                                 user_identity_hash: str = None,
                                 time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Detect potential reuse of ephemeral DIDs across sessions or users
        
        Args:
            ephemeral_did: DID to check for reuse
            user_identity_hash: Optional user context
            time_window_hours: Time window to check for reuse
            
        Returns:
            Dict with reuse detection results and security analysis
        """
        try:
            conn = self.get_db_connection()
            if not conn:
                return {
                    'success': False,
                    'error': 'Database connection failed'
                }
            
            try:
                with conn.cursor() as cursor:
                    since_time = datetime.now() - timedelta(hours=time_window_hours)
                    
                    # Check for DID reuse across all sessions
                    cursor.execute("""
                        SELECT das.user_identity_hash, das.session_token, das.created_at,
                               das.expires_at, das.status, u.email, u.full_name,
                               d.title as document_title, d.classification_level
                        FROM document_access_sessions das
                        LEFT JOIN users u ON das.user_identity_hash = u.identity_hash
                        LEFT JOIN documents d ON das.document_id = d.id
                        WHERE das.ephemeral_did = %s
                        AND das.created_at >= %s
                        ORDER BY das.created_at DESC
                    """, (ephemeral_did, since_time))
                    
                    reuse_instances = cursor.fetchall()
                    total_reuse_count = len(reuse_instances)
                    
                    # Analyze reuse patterns
                    reuse_analysis = {
                        'total_reuse_count': total_reuse_count,
                        'unique_users': len(set(r['user_identity_hash'] for r in reuse_instances)),
                        'unique_documents': len(set(r['document_title'] for r in reuse_instances if r['document_title'])),
                        'cross_user_reuse': False,
                        'rapid_reuse': False,
                        'current_user_reuse_count': 0,
                        'security_risk_level': 'low'
                    }
                    
                    if total_reuse_count > 0:
                        # Check for cross-user reuse (major security concern)
                        if reuse_analysis['unique_users'] > 1:
                            reuse_analysis['cross_user_reuse'] = True
                            reuse_analysis['security_risk_level'] = 'critical'
                        
                        # Check for rapid reuse (potential bot/automated attack)
                        if total_reuse_count > self.max_did_reuse_attempts:
                            reuse_analysis['rapid_reuse'] = True
                            reuse_analysis['security_risk_level'] = 'high'
                        
                        # Count reuse by current user (if specified)
                        if user_identity_hash:
                            reuse_analysis['current_user_reuse_count'] = sum(
                                1 for r in reuse_instances 
                                if r['user_identity_hash'] == user_identity_hash
                            )
                    
                    # Generate security warnings
                    security_warnings = []
                    
                    if reuse_analysis['cross_user_reuse']:
                        security_warnings.append('CRITICAL: DID reuse detected across different users')
                    
                    if reuse_analysis['rapid_reuse']:
                        security_warnings.append(f'HIGH: Excessive DID reuse ({total_reuse_count} times in {time_window_hours}h)')
                    
                    if reuse_analysis['current_user_reuse_count'] > 1:
                        security_warnings.append(f'MEDIUM: User has reused this DID {reuse_analysis["current_user_reuse_count"]} times')
                    
                    # Log the reuse detection attempt
                    cursor.execute("""
                        INSERT INTO ephemeral_did_audit_log (
                            user_identity_hash, document_id, ephemeral_did,
                            session_token, operation, result, operation_details
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        user_identity_hash, None, ephemeral_did, None,
                        'reuse_detection', 'completed',
                        json.dumps({
                            'reuse_analysis': reuse_analysis,
                            'time_window_hours': time_window_hours,
                            'security_warnings': security_warnings
                        })
                    ))
                    
                    conn.commit()
                    
                    return {
                        'success': True,
                        'reuse_detected': total_reuse_count > 0,
                        'reuse_analysis': reuse_analysis,
                        'security_warnings': security_warnings,
                        'reuse_instances': [
                            {
                                'user_identity_hash': instance['user_identity_hash'],
                                'user_email': instance['email'],
                                'user_name': instance['full_name'],
                                'session_token': instance['session_token'],
                                'document_title': instance['document_title'],
                                'classification_level': instance['classification_level'],
                                'created_at': instance['created_at'].isoformat(),
                                'expires_at': instance['expires_at'].isoformat(),
                                'status': instance['status']
                            } for instance in reuse_instances
                        ],
                        'time_window': {
                            'hours': time_window_hours,
                            'since': since_time.isoformat(),
                            'until': datetime.now().isoformat()
                        }
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error detecting ephemeral DID reuse: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'DID reuse detection failed: {str(e)}'
            }
    
    def validate_session_security(self, session_token: str) -> Dict[str, Any]:
        """
        Comprehensive security validation of an ephemeral session
        
        Args:
            session_token: Session token to validate
            
        Returns:
            Dict with comprehensive security validation results
        """
        try:
            conn = self.get_db_connection()
            if not conn:
                return {
                    'success': False,
                    'error': 'Database connection failed'
                }
            
            try:
                with conn.cursor() as cursor:
                    # Get session details with related information
                    cursor.execute("""
                        SELECT das.*, u.email, u.full_name, u.enterprise_account_name,
                               d.title as document_title, d.classification_level,
                               d.classification_label,
                               EXTRACT(EPOCH FROM (das.expires_at - NOW())) as seconds_until_expiry,
                               EXTRACT(EPOCH FROM (NOW() - das.created_at)) as session_age_seconds
                        FROM document_access_sessions das
                        LEFT JOIN users u ON das.user_identity_hash = u.identity_hash
                        LEFT JOIN documents d ON das.document_id = d.id
                        WHERE das.session_token = %s
                    """, (session_token,))
                    
                    session = cursor.fetchone()
                    if not session:
                        return {
                            'success': False,
                            'error': 'Session not found',
                            'valid': False
                        }
                    
                    # Initialize security analysis
                    security_analysis = {
                        'session_status_valid': session['status'] == 'active',
                        'session_not_expired': session['expires_at'] > datetime.now(),
                        'session_duration_reasonable': False,
                        'no_suspicious_activity': True,
                        'did_authenticity_valid': False,
                        'no_concurrent_sessions_exceeded': True,
                        'user_account_active': True,
                        'document_access_authorized': True,
                        'security_warnings': [],
                        'security_score': 0
                    }
                    
                    # 1. Session duration analysis
                    session_duration = session['expires_at'] - session['created_at']
                    security_analysis['session_duration_reasonable'] = (
                        session_duration <= self.session_duration_warning_threshold
                    )
                    
                    if not security_analysis['session_duration_reasonable']:
                        security_analysis['security_warnings'].append(
                            f'Unusually long session duration: {session_duration}'
                        )
                    
                    # 2. Validate ephemeral DID authenticity
                    did_validation = self.validate_ephemeral_did_authenticity(
                        session['ephemeral_did'],
                        session['ephemeral_public_key'],
                        session['user_identity_hash']
                    )
                    
                    security_analysis['did_authenticity_valid'] = did_validation.get('valid', False)
                    if not security_analysis['did_authenticity_valid']:
                        security_analysis['security_warnings'].extend(
                            did_validation.get('validation', {}).get('security_warnings', [])
                        )
                    
                    # 3. Check for DID reuse
                    reuse_detection = self.detect_ephemeral_did_reuse(
                        session['ephemeral_did'],
                        session['user_identity_hash']
                    )
                    
                    if reuse_detection.get('reuse_detected', False):
                        security_analysis['security_warnings'].extend(
                            reuse_detection.get('security_warnings', [])
                        )
                        
                        reuse_analysis = reuse_detection.get('reuse_analysis', {})
                        if reuse_analysis.get('cross_user_reuse', False):
                            security_analysis['no_suspicious_activity'] = False
                    
                    # 4. Check concurrent sessions for user
                    cursor.execute("""
                        SELECT COUNT(*) as concurrent_count
                        FROM document_access_sessions
                        WHERE user_identity_hash = %s
                        AND status = 'active'
                        AND expires_at > NOW()
                    """, (session['user_identity_hash'],))
                    
                    concurrent_sessions = cursor.fetchone()['concurrent_count']
                    security_analysis['no_concurrent_sessions_exceeded'] = (
                        concurrent_sessions <= self.max_concurrent_sessions_per_user
                    )
                    
                    if not security_analysis['no_concurrent_sessions_exceeded']:
                        security_analysis['security_warnings'].append(
                            f'Excessive concurrent sessions: {concurrent_sessions}'
                        )
                    
                    # 5. Check user account status
                    cursor.execute("""
                        SELECT is_active FROM users WHERE identity_hash = %s
                    """, (session['user_identity_hash'],))
                    
                    user_status = cursor.fetchone()
                    security_analysis['user_account_active'] = (
                        user_status and user_status['is_active']
                    )
                    
                    if not security_analysis['user_account_active']:
                        security_analysis['security_warnings'].append('User account is inactive')
                    
                    # 6. Validate document access authorization
                    cursor.execute("""
                        SELECT get_user_max_classification_level(%s) >= %s as authorized
                    """, (session['user_identity_hash'], session['classification_level']))
                    
                    authorization = cursor.fetchone()
                    security_analysis['document_access_authorized'] = bool(authorization['authorized'])
                    
                    if not security_analysis['document_access_authorized']:
                        security_analysis['security_warnings'].append(
                            'User no longer authorized for document classification level'
                        )
                    
                    # 7. Calculate overall security score (0-100)
                    security_checks = [
                        security_analysis['session_status_valid'],
                        security_analysis['session_not_expired'],
                        security_analysis['session_duration_reasonable'],
                        security_analysis['no_suspicious_activity'],
                        security_analysis['did_authenticity_valid'],
                        security_analysis['no_concurrent_sessions_exceeded'],
                        security_analysis['user_account_active'],
                        security_analysis['document_access_authorized']
                    ]
                    
                    security_analysis['security_score'] = int(
                        (sum(security_checks) / len(security_checks)) * 100
                    )
                    
                    # 8. Log security validation
                    cursor.execute("""
                        INSERT INTO ephemeral_did_audit_log (
                            user_identity_hash, document_id, ephemeral_did,
                            session_token, operation, result, operation_details
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        session['user_identity_hash'], session['document_id'],
                        session['ephemeral_did'], session_token,
                        'security_validation', 'completed',
                        json.dumps({
                            'security_analysis': security_analysis,
                            'concurrent_sessions': concurrent_sessions,
                            'session_duration_hours': session_duration.total_seconds() / 3600
                        })
                    ))
                    
                    conn.commit()
                    
                    # Overall session validity
                    is_valid = (
                        security_analysis['security_score'] >= 80 and
                        len(security_analysis['security_warnings']) == 0
                    )
                    
                    return {
                        'success': True,
                        'valid': is_valid,
                        'security_analysis': security_analysis,
                        'session_details': {
                            'session_token': session_token,
                            'user_email': session['email'],
                            'user_name': session['full_name'],
                            'document_title': session['document_title'],
                            'classification_level': session['classification_level'],
                            'created_at': session['created_at'].isoformat(),
                            'expires_at': session['expires_at'].isoformat(),
                            'seconds_until_expiry': float(session['seconds_until_expiry'] or 0),
                            'session_age_seconds': float(session['session_age_seconds'] or 0)
                        }
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error validating session security: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Session security validation failed: {str(e)}',
                'valid': False
            }
    
    def generate_ephemeral_did_usage_report(self, days_back: int = 7,
                                          include_security_analysis: bool = True) -> Dict[str, Any]:
        """
        Generate comprehensive usage report for ephemeral DID operations
        
        Args:
            days_back: Number of days to include in the report
            include_security_analysis: Include detailed security analysis
            
        Returns:
            Dict with comprehensive usage report and security insights
        """
        try:
            conn = self.get_db_connection()
            if not conn:
                return {
                    'success': False,
                    'error': 'Database connection failed'
                }
            
            try:
                with conn.cursor() as cursor:
                    since_date = datetime.now() - timedelta(days=days_back)
                    
                    # Overall usage statistics
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total_sessions,
                            COUNT(CASE WHEN status = 'active' AND expires_at > NOW() THEN 1 END) as active_sessions,
                            COUNT(CASE WHEN status = 'expired' THEN 1 END) as expired_sessions,
                            COUNT(DISTINCT user_identity_hash) as unique_users,
                            COUNT(DISTINCT document_id) as unique_documents,
                            COUNT(DISTINCT ephemeral_did) as unique_ephemeral_dids,
                            AVG(EXTRACT(EPOCH FROM (expires_at - created_at))) / 3600 as avg_session_duration_hours
                        FROM document_access_sessions
                        WHERE created_at >= %s
                    """, (since_date,))
                    
                    usage_stats = cursor.fetchone()
                    
                    # Security analysis statistics (if requested)
                    security_stats = {}
                    if include_security_analysis:
                        # DID reuse analysis
                        cursor.execute("""
                            SELECT ephemeral_did, COUNT(*) as usage_count,
                                   COUNT(DISTINCT user_identity_hash) as unique_users
                            FROM document_access_sessions
                            WHERE created_at >= %s
                            GROUP BY ephemeral_did
                            HAVING COUNT(*) > 1
                            ORDER BY usage_count DESC
                        """, (since_date,))
                        
                        did_reuse_instances = cursor.fetchall()
                        
                        # Suspicious activity detection
                        cursor.execute("""
                            SELECT user_identity_hash, u.email, u.full_name,
                                   COUNT(*) as session_count,
                                   COUNT(DISTINCT ephemeral_did) as unique_dids_used,
                                   MIN(created_at) as first_session,
                                   MAX(created_at) as last_session
                            FROM document_access_sessions das
                            LEFT JOIN users u ON das.user_identity_hash = u.identity_hash
                            WHERE das.created_at >= %s
                            GROUP BY user_identity_hash, u.email, u.full_name
                            HAVING COUNT(*) >= %s
                            ORDER BY session_count DESC
                        """, (since_date, self.suspicious_session_count_threshold))
                        
                        suspicious_users = cursor.fetchall()
                        
                        # Classification level access patterns
                        cursor.execute("""
                            SELECT d.classification_level, d.classification_label,
                                   COUNT(das.id) as access_count,
                                   COUNT(DISTINCT das.user_identity_hash) as unique_users,
                                   COUNT(DISTINCT das.ephemeral_did) as unique_dids
                            FROM document_access_sessions das
                            LEFT JOIN documents d ON das.document_id = d.id
                            WHERE das.created_at >= %s
                            GROUP BY d.classification_level, d.classification_label
                            ORDER BY access_count DESC
                        """, (since_date,))
                        
                        classification_patterns = cursor.fetchall()
                        
                        security_stats = {
                            'did_reuse_instances': len(did_reuse_instances),
                            'cross_user_reuse_count': sum(
                                1 for r in did_reuse_instances if r['unique_users'] > 1
                            ),
                            'suspicious_users_count': len(suspicious_users),
                            'max_sessions_per_user': max(
                                (u['session_count'] for u in suspicious_users), default=0
                            ),
                            'reuse_details': [
                                {
                                    'ephemeral_did': r['ephemeral_did'],
                                    'usage_count': r['usage_count'],
                                    'unique_users': r['unique_users'],
                                    'is_cross_user': r['unique_users'] > 1
                                } for r in did_reuse_instances[:20]  # Top 20
                            ],
                            'suspicious_users': [
                                {
                                    'user_identity_hash': u['user_identity_hash'],
                                    'user_email': u['email'],
                                    'user_name': u['full_name'],
                                    'session_count': u['session_count'],
                                    'unique_dids_used': u['unique_dids_used'],
                                    'first_session': u['first_session'].isoformat(),
                                    'last_session': u['last_session'].isoformat(),
                                    'sessions_per_hour': u['session_count'] / max(
                                        (u['last_session'] - u['first_session']).total_seconds() / 3600, 1
                                    )
                                } for u in suspicious_users
                            ],
                            'classification_patterns': [
                                {
                                    'classification_level': p['classification_level'],
                                    'classification_label': p['classification_label'],
                                    'access_count': p['access_count'],
                                    'unique_users': p['unique_users'],
                                    'unique_dids': p['unique_dids']
                                } for p in classification_patterns
                            ]
                        }
                    
                    # Daily usage breakdown
                    cursor.execute("""
                        SELECT DATE(created_at) as usage_date,
                               COUNT(*) as sessions_created,
                               COUNT(DISTINCT user_identity_hash) as unique_users,
                               COUNT(DISTINCT ephemeral_did) as unique_dids
                        FROM document_access_sessions
                        WHERE created_at >= %s
                        GROUP BY DATE(created_at)
                        ORDER BY usage_date DESC
                    """, (since_date,))
                    
                    daily_usage = cursor.fetchall()
                    
                    # Generate security recommendations
                    recommendations = self._generate_usage_recommendations(
                        usage_stats, security_stats, daily_usage
                    )
                    
                    return {
                        'success': True,
                        'report_metadata': {
                            'generated_at': datetime.now().isoformat(),
                            'period_days': days_back,
                            'period_start': since_date.isoformat(),
                            'period_end': datetime.now().isoformat(),
                            'includes_security_analysis': include_security_analysis
                        },
                        'usage_statistics': {
                            'total_sessions': usage_stats['total_sessions'] or 0,
                            'active_sessions': usage_stats['active_sessions'] or 0,
                            'expired_sessions': usage_stats['expired_sessions'] or 0,
                            'unique_users': usage_stats['unique_users'] or 0,
                            'unique_documents': usage_stats['unique_documents'] or 0,
                            'unique_ephemeral_dids': usage_stats['unique_ephemeral_dids'] or 0,
                            'avg_session_duration_hours': round(usage_stats['avg_session_duration_hours'] or 0, 2),
                            'did_reuse_rate': (
                                (usage_stats['total_sessions'] - usage_stats['unique_ephemeral_dids']) / 
                                max(usage_stats['total_sessions'], 1) * 100
                            ) if usage_stats['total_sessions'] else 0
                        },
                        'daily_usage': [
                            {
                                'date': day['usage_date'].isoformat(),
                                'sessions_created': day['sessions_created'],
                                'unique_users': day['unique_users'],
                                'unique_dids': day['unique_dids']
                            } for day in daily_usage
                        ],
                        'security_analysis': security_stats,
                        'recommendations': recommendations
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error generating ephemeral DID usage report: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Usage report generation failed: {str(e)}'
            }
    
    # Private helper methods
    
    def _has_sequential_patterns(self, did: str) -> bool:
        """Check for sequential patterns that might indicate weak randomness"""
        try:
            # Extract the key material from DID
            if did.startswith('did:key:z'):
                key_material = did[9:]  # Remove 'did:key:z' prefix
            else:
                return False
            
            # Check for repeated characters (weak entropy indicator)
            for char in key_material:
                if key_material.count(char) > len(key_material) * 0.1:  # More than 10% repetition
                    return True
            
            # Check for sequential patterns in hex representation
            try:
                decoded = base58.b58decode(key_material)
                hex_repr = decoded.hex()
                
                # Look for sequential hex patterns
                for i in range(len(hex_repr) - 3):
                    if hex_repr[i:i+4] in ['0123', '1234', '2345', '3456', '4567', '5678', '6789', 
                                           '789a', '89ab', '9abc', 'abcd', 'bcde', 'cdef']:
                        return True
                
            except Exception:
                pass  # Ignore decoding errors for this heuristic
            
            return False
            
        except Exception:
            return False
    
    def _validate_against_database(self, ephemeral_did: str, user_identity_hash: str) -> Dict[str, Any]:
        """Perform database-based validation checks"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return {'warnings': ['Database connection failed for validation']}
            
            try:
                with conn.cursor() as cursor:
                    # Check for recent usage of this DID
                    cursor.execute("""
                        SELECT COUNT(*) as recent_usage
                        FROM document_access_sessions
                        WHERE ephemeral_did = %s
                        AND created_at >= NOW() - INTERVAL '1 hour'
                    """, (ephemeral_did,))
                    
                    recent_usage = cursor.fetchone()['recent_usage']
                    
                    warnings = []
                    if recent_usage > 0:
                        warnings.append(f'DID used {recent_usage} times in the last hour')
                    
                    return {
                        'recent_usage': recent_usage,
                        'warnings': warnings
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            return {'warnings': [f'Database validation failed: {str(e)}']}
    
    def _calculate_security_score(self, validation_results: Dict[str, Any]) -> int:
        """Calculate overall security score (0-100) based on validation results"""
        score = 0
        
        # Base score for valid format and structure
        if validation_results['did_format_valid']:
            score += 20
        if validation_results['did_structure_valid']:
            score += 20
        if validation_results['multibase_encoding_valid']:
            score += 15
        if validation_results['key_material_valid']:
            score += 15
        if validation_results['public_key_consistent']:
            score += 10
        
        # Deduct points for security warnings
        warning_count = len(validation_results['security_warnings'])
        score -= min(warning_count * 10, 30)  # Max 30 point deduction
        
        return max(0, min(score, 100))
    
    def _generate_security_recommendations(self, validation_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on validation results"""
        recommendations = []
        
        if not validation_results['did_format_valid']:
            recommendations.append('Ensure DID follows proper did:key format')
        
        if not validation_results['key_material_valid']:
            recommendations.append('Use stronger key material with adequate entropy')
        
        if validation_results['security_warnings']:
            recommendations.append('Address identified security warnings before proceeding')
        
        if not validation_results['public_key_consistent']:
            recommendations.append('Verify public key consistency with DID')
        
        return recommendations
    
    def _generate_usage_recommendations(self, usage_stats: Dict, security_stats: Dict, 
                                      daily_usage: List[Dict]) -> List[str]:
        """Generate usage and security recommendations based on report data"""
        recommendations = []
        
        # Usage pattern recommendations
        if usage_stats['total_sessions'] > 1000:
            recommendations.append('High usage detected - consider implementing rate limiting')
        
        if security_stats.get('cross_user_reuse_count', 0) > 0:
            recommendations.append('CRITICAL: Cross-user DID reuse detected - investigate immediately')
        
        if security_stats.get('suspicious_users_count', 0) > 0:
            recommendations.append('Suspicious user activity detected - review user access patterns')
        
        # DID reuse recommendations
        did_reuse_rate = (
            (usage_stats['total_sessions'] - usage_stats['unique_ephemeral_dids']) / 
            max(usage_stats['total_sessions'], 1) * 100
        )
        
        if did_reuse_rate > 10:
            recommendations.append(f'High DID reuse rate ({did_reuse_rate:.1f}%) - enforce stricter DID uniqueness')
        
        # Session duration recommendations
        if usage_stats['avg_session_duration_hours'] > 4:
            recommendations.append('Long average session duration - consider shorter session timeouts')
        
        return recommendations