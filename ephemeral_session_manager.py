#!/usr/bin/env python3
"""
Ephemeral Session Manager
Working Package 3 - Phase 5 - Task 5.1

Comprehensive session management system for ephemeral DID-based document access.
Handles session lifecycle, validation, expiration, and cleanup with security monitoring.
"""

import json
import secrets
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import psycopg2
from psycopg2.extras import RealDictCursor

from config import Config


class EphemeralSessionManager:
    """Advanced ephemeral session management with security monitoring (Task 5.1)"""
    
    def __init__(self, config: Config):
        """Initialize ephemeral session manager with configuration"""
        self.config = config
        self.db_url = config.get_database_url()
        self.default_session_duration = timedelta(hours=1)  # Default 1-hour sessions
        self.max_concurrent_sessions_per_user = 3
        self.cleanup_batch_size = 100
        
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
    
    def create_ephemeral_session(self, user_identity_hash: str, document_id: int,
                               ephemeral_did: str, ephemeral_public_key: str,
                               session_duration: timedelta = None,
                               metadata: Dict = None) -> Dict[str, Any]:
        """
        Create a new ephemeral session for document access
        
        Args:
            user_identity_hash: User's cryptographic identity hash
            document_id: Document ID for access
            ephemeral_did: User-generated ephemeral DID
            ephemeral_public_key: Public key from ephemeral DID
            session_duration: Optional custom session duration
            metadata: Additional session metadata
            
        Returns:
            Dict with session creation result and session token
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
                    # Get user information
                    cursor.execute("""
                        SELECT id, email, full_name, enterprise_account_name 
                        FROM users WHERE identity_hash = %s AND is_active = true
                    """, (user_identity_hash,))
                    
                    user = cursor.fetchone()
                    if not user:
                        return {
                            'success': False,
                            'error': 'User not found or inactive'
                        }
                    
                    # Check document exists and user can access it
                    cursor.execute("""
                        SELECT d.*, 
                               get_user_max_classification_level(%s) >= d.classification_level as can_access
                        FROM documents d
                        WHERE d.id = %s
                    """, (user_identity_hash, document_id))
                    
                    document = cursor.fetchone()
                    if not document:
                        return {
                            'success': False,
                            'error': 'Document not found'
                        }
                    
                    if not document['can_access']:
                        return {
                            'success': False,
                            'error': 'Insufficient classification level for document access'
                        }
                    
                    # Check for existing active sessions (enforce concurrent session limit)
                    cursor.execute("""
                        SELECT COUNT(*) as active_count
                        FROM document_access_sessions
                        WHERE user_identity_hash = %s 
                        AND status = 'active' 
                        AND expires_at > NOW()
                    """, (user_identity_hash,))
                    
                    active_sessions = cursor.fetchone()['active_count']
                    if active_sessions >= self.max_concurrent_sessions_per_user:
                        return {
                            'success': False,
                            'error': f'Maximum concurrent sessions limit ({self.max_concurrent_sessions_per_user}) exceeded'
                        }
                    
                    # Check for DID reuse (security validation)
                    cursor.execute("""
                        SELECT COUNT(*) as reuse_count
                        FROM document_access_sessions
                        WHERE ephemeral_did = %s 
                        AND user_identity_hash != %s
                    """, (ephemeral_did, user_identity_hash))
                    
                    did_reuse = cursor.fetchone()['reuse_count']
                    if did_reuse > 0:
                        return {
                            'success': False,
                            'error': 'Ephemeral DID reuse detected - security violation'
                        }
                    
                    # Generate secure session token
                    session_token = secrets.token_urlsafe(32)
                    
                    # Calculate expiration time
                    duration = session_duration or self.default_session_duration
                    expires_at = datetime.now() + duration
                    
                    # Create session record
                    cursor.execute("""
                        INSERT INTO document_access_sessions (
                            session_token, user_identity_hash, document_id,
                            ephemeral_did, ephemeral_public_key, status,
                            created_at, expires_at, session_metadata
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (
                        session_token, user_identity_hash, document_id,
                        ephemeral_did, ephemeral_public_key, 'active',
                        datetime.now(), expires_at, json.dumps(metadata or {})
                    ))
                    
                    session_id = cursor.fetchone()['id']
                    
                    # Log session creation in audit log
                    cursor.execute("""
                        INSERT INTO ephemeral_did_audit_log (
                            user_identity_hash, document_id, ephemeral_did,
                            session_token, operation, result, operation_details
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        user_identity_hash, document_id, ephemeral_did,
                        session_token, 'session_created', 'success',
                        json.dumps({
                            'session_id': session_id,
                            'document_title': document['title'],
                            'classification_level': document['classification_level'],
                            'session_duration_hours': duration.total_seconds() / 3600,
                            'expires_at': expires_at.isoformat(),
                            'metadata': metadata or {}
                        })
                    ))
                    
                    conn.commit()
                    
                    print(f"✅ Ephemeral session created: {session_token[:8]}... for {user['email']} -> doc {document_id}")
                    
                    return {
                        'success': True,
                        'session': {
                            'session_id': session_id,
                            'session_token': session_token,
                            'ephemeral_did': ephemeral_did,
                            'document_id': document_id,
                            'document_title': document['title'],
                            'classification_level': document['classification_level'],
                            'user_email': user['email'],
                            'user_name': user['full_name'],
                            'created_at': datetime.now().isoformat(),
                            'expires_at': expires_at.isoformat(),
                            'duration_seconds': int(duration.total_seconds()),
                            'status': 'active'
                        }
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error creating ephemeral session: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Session creation failed: {str(e)}'
            }
    
    def validate_ephemeral_session(self, session_token: str,
                                 user_identity_hash: str = None,
                                 document_id: int = None) -> Dict[str, Any]:
        """
        Validate an ephemeral session and return session details
        
        Args:
            session_token: Session token to validate
            user_identity_hash: Optional user identity hash for additional validation
            document_id: Optional document ID for additional validation
            
        Returns:
            Dict with validation result and session details
        """
        try:
            conn = self.get_db_connection()
            if not conn:
                return {
                    'success': False,
                    'error': 'Database connection failed',
                    'valid': False
                }
            
            try:
                with conn.cursor() as cursor:
                    # Get session information with user and document details
                    cursor.execute("""
                        SELECT das.*, 
                               u.full_name, u.email, u.enterprise_account_name,
                               d.title as document_title, d.classification_level,
                               d.classification_label, d.file_path, d.file_size,
                               CASE 
                                   WHEN das.expires_at > NOW() AND das.status = 'active' THEN true
                                   ELSE false
                               END as is_valid,
                               EXTRACT(EPOCH FROM (das.expires_at - NOW())) as seconds_until_expiry
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
                    
                    # Additional validation checks
                    validation_errors = []
                    
                    if user_identity_hash and session['user_identity_hash'] != user_identity_hash:
                        validation_errors.append('User identity mismatch')
                    
                    if document_id and session['document_id'] != document_id:
                        validation_errors.append('Document ID mismatch')
                    
                    if session['status'] != 'active':
                        validation_errors.append(f'Session status is {session["status"]}')
                    
                    if session['expires_at'] <= datetime.now():
                        validation_errors.append('Session expired')
                    
                    is_valid = len(validation_errors) == 0 and bool(session['is_valid'])
                    
                    # Log validation attempt
                    cursor.execute("""
                        INSERT INTO ephemeral_did_audit_log (
                            user_identity_hash, document_id, ephemeral_did,
                            session_token, operation, result, operation_details
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        session['user_identity_hash'], session['document_id'],
                        session['ephemeral_did'], session_token,
                        'session_validation', 'success' if is_valid else 'failed',
                        json.dumps({
                            'validation_errors': validation_errors,
                            'seconds_until_expiry': float(session['seconds_until_expiry'] or 0),
                            'additional_user_check': user_identity_hash is not None,
                            'additional_document_check': document_id is not None
                        })
                    ))
                    
                    conn.commit()
                    
                    return {
                        'success': True,
                        'valid': is_valid,
                        'validation_errors': validation_errors,
                        'session': {
                            'session_id': session['id'],
                            'session_token': session_token,
                            'ephemeral_did': session['ephemeral_did'],
                            'ephemeral_public_key': session['ephemeral_public_key'],
                            'document_id': session['document_id'],
                            'document_title': session['document_title'],
                            'document_path': session['file_path'],
                            'document_size': session['file_size'],
                            'classification_level': session['classification_level'],
                            'classification_label': session['classification_label'],
                            'user_identity_hash': session['user_identity_hash'],
                            'user_name': session['full_name'],
                            'user_email': session['email'],
                            'enterprise_account': session['enterprise_account_name'],
                            'status': session['status'],
                            'created_at': session['created_at'].isoformat(),
                            'expires_at': session['expires_at'].isoformat(),
                            'seconds_until_expiry': float(session['seconds_until_expiry'] or 0),
                            'session_metadata': session['session_metadata'] or {}
                        }
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error validating ephemeral session: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Session validation failed: {str(e)}',
                'valid': False
            }
    
    def expire_ephemeral_session(self, session_token: str, 
                               reason: str = 'manual_expiration',
                               user_identity_hash: str = None) -> Dict[str, Any]:
        """
        Manually expire an ephemeral session
        
        Args:
            session_token: Session token to expire
            reason: Reason for expiration
            user_identity_hash: Optional user identity for authorization check
            
        Returns:
            Dict with expiration result
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
                    # Get session info for validation
                    cursor.execute("""
                        SELECT * FROM document_access_sessions WHERE session_token = %s
                    """, (session_token,))
                    
                    session = cursor.fetchone()
                    if not session:
                        return {
                            'success': False,
                            'error': 'Session not found'
                        }
                    
                    # Check user authorization if provided
                    if user_identity_hash and session['user_identity_hash'] != user_identity_hash:
                        return {
                            'success': False,
                            'error': 'User not authorized to expire this session'
                        }
                    
                    if session['status'] == 'expired':
                        return {
                            'success': True,
                            'message': 'Session was already expired'
                        }
                    
                    # Update session status
                    cursor.execute("""
                        UPDATE document_access_sessions 
                        SET status = 'expired', 
                            updated_at = CURRENT_TIMESTAMP,
                            session_metadata = COALESCE(session_metadata, '{}')::jsonb || %s::jsonb
                        WHERE session_token = %s
                    """, (
                        json.dumps({
                            'expiry_reason': reason,
                            'expired_at': datetime.now().isoformat(),
                            'manually_expired': True
                        }),
                        session_token
                    ))
                    
                    # Log expiration in audit log
                    cursor.execute("""
                        INSERT INTO ephemeral_did_audit_log (
                            user_identity_hash, document_id, ephemeral_did,
                            session_token, operation, result, operation_details
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        session['user_identity_hash'], session['document_id'],
                        session['ephemeral_did'], session_token,
                        'session_expired', 'success',
                        json.dumps({
                            'expiry_reason': reason,
                            'original_expires_at': session['expires_at'].isoformat(),
                            'manually_expired': True,
                            'expired_by_user': user_identity_hash
                        })
                    ))
                    
                    conn.commit()
                    
                    print(f"✅ Ephemeral session expired: {session_token[:8]}... (reason: {reason})")
                    
                    return {
                        'success': True,
                        'message': 'Session expired successfully',
                        'session_id': session['id'],
                        'reason': reason
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error expiring ephemeral session: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Session expiration failed: {str(e)}'
            }
    
    def cleanup_expired_sessions(self, batch_size: int = None) -> Dict[str, Any]:
        """
        Clean up expired ephemeral sessions and related data
        
        Args:
            batch_size: Number of sessions to process in one batch
            
        Returns:
            Dict with cleanup results and statistics
        """
        try:
            batch_size = batch_size or self.cleanup_batch_size
            
            conn = self.get_db_connection()
            if not conn:
                return {
                    'success': False,
                    'error': 'Database connection failed'
                }
            
            try:
                with conn.cursor() as cursor:
                    # Find expired sessions that are still marked as active
                    cursor.execute("""
                        SELECT session_token, user_identity_hash, document_id, ephemeral_did,
                               expires_at, created_at
                        FROM document_access_sessions 
                        WHERE status = 'active' 
                        AND expires_at <= NOW()
                        ORDER BY expires_at ASC
                        LIMIT %s
                    """, (batch_size,))
                    
                    expired_sessions = cursor.fetchall()
                    expired_count = len(expired_sessions)
                    
                    if expired_count == 0:
                        return {
                            'success': True,
                            'cleanup_results': {
                                'expired_sessions_found': 0,
                                'sessions_updated': 0,
                                'audit_logs_created': 0,
                                'message': 'No expired sessions found'
                            }
                        }
                    
                    # Update expired sessions
                    expired_tokens = [session['session_token'] for session in expired_sessions]
                    
                    cursor.execute("""
                        UPDATE document_access_sessions 
                        SET status = 'expired', 
                            updated_at = CURRENT_TIMESTAMP,
                            session_metadata = COALESCE(session_metadata, '{}')::jsonb || %s::jsonb
                        WHERE session_token = ANY(%s)
                    """, (
                        json.dumps({
                            'expiry_reason': 'automatic_cleanup',
                            'expired_at': datetime.now().isoformat(),
                            'automatically_expired': True
                        }),
                        expired_tokens
                    ))
                    
                    sessions_updated = cursor.rowcount
                    
                    # Create audit log entries for cleanup
                    audit_entries = []
                    for session in expired_sessions:
                        audit_entries.append((
                            session['user_identity_hash'], session['document_id'],
                            session['ephemeral_did'], session['session_token'],
                            'session_cleanup', 'success',
                            json.dumps({
                                'cleanup_reason': 'automatic_expiration',
                                'original_expires_at': session['expires_at'].isoformat(),
                                'session_age_hours': (datetime.now() - session['created_at']).total_seconds() / 3600,
                                'cleanup_batch_size': batch_size
                            })
                        ))
                    
                    cursor.executemany("""
                        INSERT INTO ephemeral_did_audit_log (
                            user_identity_hash, document_id, ephemeral_did,
                            session_token, operation, result, operation_details
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, audit_entries)
                    
                    audit_logs_created = cursor.rowcount
                    
                    # Clean up old ephemeral encryption metadata (older than 7 days)
                    cleanup_date = datetime.now() - timedelta(days=7)
                    cursor.execute("""
                        DELETE FROM document_ephemeral_encryption
                        WHERE created_at < %s
                        AND session_token = ANY(%s)
                    """, (cleanup_date, expired_tokens))
                    
                    encryption_records_cleaned = cursor.rowcount
                    
                    conn.commit()
                    
                    print(f"✅ Cleanup completed: {sessions_updated} sessions expired, {encryption_records_cleaned} encryption records cleaned")
                    
                    return {
                        'success': True,
                        'cleanup_results': {
                            'expired_sessions_found': expired_count,
                            'sessions_updated': sessions_updated,
                            'audit_logs_created': audit_logs_created,
                            'encryption_records_cleaned': encryption_records_cleaned,
                            'cleanup_timestamp': datetime.now().isoformat(),
                            'batch_size': batch_size
                        }
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error during session cleanup: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Session cleanup failed: {str(e)}'
            }
    
    def get_active_ephemeral_sessions(self, user_identity_hash: str = None,
                                    document_id: int = None,
                                    limit: int = 50) -> Dict[str, Any]:
        """
        Get active ephemeral sessions with filtering options
        
        Args:
            user_identity_hash: Optional filter by user
            document_id: Optional filter by document
            limit: Maximum number of sessions to return
            
        Returns:
            Dict with active sessions list and statistics
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
                    # Build query with optional filters
                    where_conditions = ["das.status = 'active'", "das.expires_at > NOW()"]
                    query_params = []
                    
                    if user_identity_hash:
                        where_conditions.append("das.user_identity_hash = %s")
                        query_params.append(user_identity_hash)
                    
                    if document_id:
                        where_conditions.append("das.document_id = %s")
                        query_params.append(document_id)
                    
                    query_params.append(limit)
                    
                    # Get active sessions with full details
                    cursor.execute(f"""
                        SELECT das.*, 
                               u.full_name, u.email, u.enterprise_account_name,
                               d.title as document_title, d.classification_level,
                               d.classification_label, d.file_size,
                               EXTRACT(EPOCH FROM (das.expires_at - NOW())) as seconds_until_expiry,
                               EXTRACT(EPOCH FROM (NOW() - das.created_at)) as session_age_seconds
                        FROM document_access_sessions das
                        LEFT JOIN users u ON das.user_identity_hash = u.identity_hash
                        LEFT JOIN documents d ON das.document_id = d.id
                        WHERE {' AND '.join(where_conditions)}
                        ORDER BY das.created_at DESC
                        LIMIT %s
                    """, query_params)
                    
                    sessions = cursor.fetchall()
                    
                    # Get statistics
                    cursor.execute(f"""
                        SELECT 
                            COUNT(*) as total_active_sessions,
                            COUNT(DISTINCT das.user_identity_hash) as unique_users,
                            COUNT(DISTINCT das.document_id) as unique_documents,
                            AVG(EXTRACT(EPOCH FROM (das.expires_at - NOW()))) as avg_time_until_expiry,
                            MIN(das.created_at) as oldest_session,
                            MAX(das.created_at) as newest_session
                        FROM document_access_sessions das
                        WHERE {' AND '.join(where_conditions[:-1])}  -- Exclude limit from stats
                    """, query_params[:-1])
                    
                    stats = cursor.fetchone()
                    
                    return {
                        'success': True,
                        'filter_criteria': {
                            'user_identity_hash': user_identity_hash,
                            'document_id': document_id,
                            'limit': limit
                        },
                        'statistics': {
                            'total_active_sessions': stats['total_active_sessions'] or 0,
                            'unique_users': stats['unique_users'] or 0,
                            'unique_documents': stats['unique_documents'] or 0,
                            'avg_time_until_expiry_minutes': (stats['avg_time_until_expiry'] or 0) / 60,
                            'oldest_session': stats['oldest_session'].isoformat() if stats['oldest_session'] else None,
                            'newest_session': stats['newest_session'].isoformat() if stats['newest_session'] else None
                        },
                        'sessions': [
                            {
                                'session_id': session['id'],
                                'session_token': session['session_token'],
                                'ephemeral_did': session['ephemeral_did'],
                                'document_id': session['document_id'],
                                'document_title': session['document_title'],
                                'classification_level': session['classification_level'],
                                'classification_label': session['classification_label'],
                                'document_size': session['file_size'],
                                'user_identity_hash': session['user_identity_hash'],
                                'user_name': session['full_name'],
                                'user_email': session['email'],
                                'enterprise_account': session['enterprise_account_name'],
                                'created_at': session['created_at'].isoformat(),
                                'expires_at': session['expires_at'].isoformat(),
                                'seconds_until_expiry': float(session['seconds_until_expiry'] or 0),
                                'session_age_seconds': float(session['session_age_seconds'] or 0),
                                'session_metadata': session['session_metadata'] or {}
                            } for session in sessions
                        ]
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error getting active ephemeral sessions: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Failed to retrieve active sessions: {str(e)}'
            }
    
    def get_session_statistics(self, days_back: int = 7) -> Dict[str, Any]:
        """
        Get comprehensive session statistics for monitoring and analytics
        
        Args:
            days_back: Number of days to include in statistics
            
        Returns:
            Dict with comprehensive session statistics
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
                    
                    # Overall session statistics
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total_sessions,
                            COUNT(CASE WHEN status = 'active' AND expires_at > NOW() THEN 1 END) as active_sessions,
                            COUNT(CASE WHEN status = 'expired' THEN 1 END) as expired_sessions,
                            COUNT(DISTINCT user_identity_hash) as unique_users,
                            COUNT(DISTINCT document_id) as unique_documents,
                            AVG(EXTRACT(EPOCH FROM (expires_at - created_at))) / 3600 as avg_session_duration_hours,
                            MIN(created_at) as first_session,
                            MAX(created_at) as latest_session
                        FROM document_access_sessions
                        WHERE created_at >= %s
                    """, (since_date,))
                    
                    overall_stats = cursor.fetchone()
                    
                    # Daily session creation statistics
                    cursor.execute("""
                        SELECT 
                            DATE(created_at) as session_date,
                            COUNT(*) as sessions_created,
                            COUNT(DISTINCT user_identity_hash) as unique_users_per_day
                        FROM document_access_sessions
                        WHERE created_at >= %s
                        GROUP BY DATE(created_at)
                        ORDER BY session_date DESC
                    """, (since_date,))
                    
                    daily_stats = cursor.fetchall()
                    
                    # Document access patterns
                    cursor.execute("""
                        SELECT 
                            d.classification_level,
                            d.classification_label,
                            COUNT(das.id) as access_count,
                            COUNT(DISTINCT das.user_identity_hash) as unique_users
                        FROM document_access_sessions das
                        LEFT JOIN documents d ON das.document_id = d.id
                        WHERE das.created_at >= %s
                        GROUP BY d.classification_level, d.classification_label
                        ORDER BY access_count DESC
                    """, (since_date,))
                    
                    classification_stats = cursor.fetchall()
                    
                    return {
                        'success': True,
                        'time_period': {
                            'days_back': days_back,
                            'since_date': since_date.isoformat(),
                            'until_date': datetime.now().isoformat()
                        },
                        'overall_statistics': {
                            'total_sessions': overall_stats['total_sessions'] or 0,
                            'active_sessions': overall_stats['active_sessions'] or 0,
                            'expired_sessions': overall_stats['expired_sessions'] or 0,
                            'unique_users': overall_stats['unique_users'] or 0,
                            'unique_documents': overall_stats['unique_documents'] or 0,
                            'avg_session_duration_hours': round(overall_stats['avg_session_duration_hours'] or 0, 2),
                            'first_session': overall_stats['first_session'].isoformat() if overall_stats['first_session'] else None,
                            'latest_session': overall_stats['latest_session'].isoformat() if overall_stats['latest_session'] else None
                        },
                        'daily_statistics': [
                            {
                                'date': stat['session_date'].isoformat(),
                                'sessions_created': stat['sessions_created'],
                                'unique_users': stat['unique_users_per_day']
                            } for stat in daily_stats
                        ],
                        'classification_statistics': [
                            {
                                'classification_level': stat['classification_level'],
                                'classification_label': stat['classification_label'],
                                'access_count': stat['access_count'],
                                'unique_users': stat['unique_users']
                            } for stat in classification_stats
                        ]
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error getting session statistics: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Failed to retrieve session statistics: {str(e)}'
            }