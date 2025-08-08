#!/usr/bin/env python3
"""
Classification Manager with Ephemeral DID Support
Working Package 3 - Phase 4 - Task 4.2

Enhanced classification system that integrates with ephemeral DID-based document access.
Provides comprehensive classification verification, access logging, and user history tracking.
"""

import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import psycopg2
from psycopg2.extras import RealDictCursor

from config import Config


class ClassificationManager:
    """Enhanced classification manager with ephemeral DID support (Task 4.2)"""
    
    def __init__(self, config: Config):
        """Initialize classification manager with configuration"""
        self.config = config
        self.db_url = config.get_database_url()
        
    def get_db_connection(self):
        """Get database connection"""
        try:
            conn = psycopg2.connect(
                self.db_url,
                cursor_factory=RealDictCursor
            )
            return conn
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            return None
    
    def verify_classification_for_ephemeral_access(self, user_identity_hash: str, 
                                                 document_id: int, 
                                                 requested_classification: str) -> Dict[str, Any]:
        """
        Verify if user can access document with ephemeral DID based on classification credentials
        
        Args:
            user_identity_hash: User's cryptographic identity hash
            document_id: Document ID to access
            requested_classification: Requested classification level
            
        Returns:
            Dict with verification result, user info, and access permissions
        """
        try:
            conn = self.get_db_connection()
            if not conn:
                return {
                    'success': False,
                    'error': 'Database connection failed',
                    'can_access': False
                }
            
            try:
                with conn.cursor() as cursor:
                    # Get user information and classification credentials
                    cursor.execute("""
                        SELECT u.id, u.email, u.full_name, u.enterprise_account_name,
                               MAX(ic.classification_level) as max_classification_level,
                               COUNT(ic.id) as credential_count
                        FROM users u
                        LEFT JOIN issued_credentials ic ON u.id = ic.user_id 
                                                        AND ic.status = 'issued'
                                                        AND (ic.expires_at IS NULL OR ic.expires_at > NOW())
                        WHERE u.identity_hash = %s AND u.is_active = true
                        GROUP BY u.id, u.email, u.full_name, u.enterprise_account_name
                    """, (user_identity_hash,))
                    
                    user = cursor.fetchone()
                    if not user:
                        return {
                            'success': False,
                            'error': 'User not found or inactive',
                            'can_access': False
                        }
                    
                    # Get document information
                    cursor.execute("""
                        SELECT id, title, classification_level, classification_label,
                               encrypted_with_ephemeral_did, original_encryption_method,
                               created_by_identity_hash
                        FROM documents
                        WHERE id = %s
                    """, (document_id,))
                    
                    document = cursor.fetchone()
                    if not document:
                        return {
                            'success': False,
                            'error': 'Document not found',
                            'can_access': False
                        }
                    
                    # Check classification level access
                    user_max_level = user['max_classification_level'] or 0
                    doc_level = document['classification_level']
                    requested_level = self.config.get_classification_level(requested_classification)
                    
                    # Verify user can access the document's classification level
                    can_access_document = user_max_level >= doc_level
                    can_access_requested = user_max_level >= requested_level
                    
                    # Get user's active credentials for detailed info
                    cursor.execute("""
                        SELECT credential_type, classification_level, issued_at, expires_at
                        FROM issued_credentials
                        WHERE user_id = %s AND status = 'issued'
                        AND (expires_at IS NULL OR expires_at > NOW())
                        ORDER BY classification_level DESC
                    """, (user['id'],))
                    
                    credentials = cursor.fetchall()
                    
                    return {
                        'success': True,
                        'can_access': can_access_document and can_access_requested,
                        'user': {
                            'id': user['id'],
                            'email': user['email'],
                            'full_name': user['full_name'],
                            'enterprise_account': user['enterprise_account_name'],
                            'max_classification_level': user_max_level,
                            'credential_count': user['credential_count']
                        },
                        'document': {
                            'id': document['id'],
                            'title': document['title'],
                            'classification_level': doc_level,
                            'classification_label': document['classification_label'],
                            'supports_ephemeral': document['encrypted_with_ephemeral_did'],
                            'encryption_method': document['original_encryption_method'],
                            'is_owner': document['created_by_identity_hash'] == user_identity_hash
                        },
                        'access_analysis': {
                            'requested_level': requested_level,
                            'required_level': doc_level,
                            'user_max_level': user_max_level,
                            'can_access_document': can_access_document,
                            'can_access_requested': can_access_requested,
                            'access_type': 'owner' if document['created_by_identity_hash'] == user_identity_hash else 'credential_based'
                        },
                        'credentials': [dict(cred) for cred in credentials]
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error verifying classification for ephemeral access: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Verification failed: {str(e)}',
                'can_access': False
            }
    
    def log_ephemeral_access_attempt(self, user_identity_hash: str, document_id: int,
                                   access_method: str, ephemeral_did: str = None,
                                   session_token: str = None, result: str = 'attempted',
                                   details: Dict = None) -> bool:
        """
        Log ephemeral DID access attempt for audit purposes
        
        Args:
            user_identity_hash: User's identity hash
            document_id: Document being accessed
            access_method: 'standard' or 'ephemeral_did'
            ephemeral_did: Ephemeral DID used (if applicable)
            session_token: Session token (if applicable)
            result: 'success', 'denied', 'error', 'attempted'
            details: Additional details for the log entry
            
        Returns:
            bool: True if logging successful, False otherwise
        """
        try:
            conn = self.get_db_connection()
            if not conn:
                return False
            
            try:
                with conn.cursor() as cursor:
                    # Get user ID for logging
                    cursor.execute("""
                        SELECT id FROM users WHERE identity_hash = %s
                    """, (user_identity_hash,))
                    
                    user_result = cursor.fetchone()
                    user_id = user_result['id'] if user_result else None
                    
                    # Log to document access log
                    cursor.execute("""
                        INSERT INTO document_access_log (
                            document_id, user_id, user_identity_hash, access_method,
                            access_result, access_details, ephemeral_did_used,
                            session_token_used, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        document_id, user_id, user_identity_hash, access_method,
                        result, details or {}, ephemeral_did, session_token,
                        datetime.now()
                    ))
                    
                    # If ephemeral DID access, also log to ephemeral audit log
                    if access_method == 'ephemeral_did' and ephemeral_did:
                        cursor.execute("""
                            INSERT INTO ephemeral_did_audit_log (
                                user_identity_hash, document_id, ephemeral_did,
                                session_token, operation, result, operation_details
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """, (
                            user_identity_hash, document_id, ephemeral_did,
                            session_token, 'document_access', result, details or {}
                        ))
                    
                    conn.commit()
                    return True
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error logging ephemeral access attempt: {e}")
            traceback.print_exc()
            return False
    
    def get_user_ephemeral_access_history(self, user_identity_hash: str,
                                        limit: int = 50,
                                        days_back: int = 30) -> Dict[str, Any]:
        """
        Get user's ephemeral DID access history for monitoring and analytics
        
        Args:
            user_identity_hash: User's identity hash
            limit: Maximum number of records to return
            days_back: How many days back to search
            
        Returns:
            Dict with access history, statistics, and patterns
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
                    # Get user info
                    cursor.execute("""
                        SELECT id, email, full_name FROM users 
                        WHERE identity_hash = %s
                    """, (user_identity_hash,))
                    
                    user = cursor.fetchone()
                    if not user:
                        return {
                            'success': False,
                            'error': 'User not found'
                        }
                    
                    since_date = datetime.now() - timedelta(days=days_back)
                    
                    # Get document access history
                    cursor.execute("""
                        SELECT dal.*, d.title, d.classification_label,
                               dal.created_at as access_time
                        FROM document_access_log dal
                        LEFT JOIN documents d ON dal.document_id = d.id
                        WHERE dal.user_identity_hash = %s
                        AND dal.created_at >= %s
                        ORDER BY dal.created_at DESC
                        LIMIT %s
                    """, (user_identity_hash, since_date, limit))
                    
                    access_history = cursor.fetchall()
                    
                    # Get ephemeral DID specific history
                    cursor.execute("""
                        SELECT eal.*, d.title, d.classification_label
                        FROM ephemeral_did_audit_log eal
                        LEFT JOIN documents d ON eal.document_id = d.id
                        WHERE eal.user_identity_hash = %s
                        AND eal.created_at >= %s
                        ORDER BY eal.created_at DESC
                        LIMIT %s
                    """, (user_identity_hash, since_date, limit))
                    
                    ephemeral_history = cursor.fetchall()
                    
                    # Get access statistics
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total_accesses,
                            COUNT(CASE WHEN access_method = 'ephemeral_did' THEN 1 END) as ephemeral_accesses,
                            COUNT(CASE WHEN access_method = 'standard' THEN 1 END) as standard_accesses,
                            COUNT(CASE WHEN access_result = 'success' THEN 1 END) as successful_accesses,
                            COUNT(CASE WHEN access_result = 'denied' THEN 1 END) as denied_accesses,
                            COUNT(DISTINCT document_id) as unique_documents_accessed
                        FROM document_access_log
                        WHERE user_identity_hash = %s
                        AND created_at >= %s
                    """, (user_identity_hash, since_date))
                    
                    stats = cursor.fetchone()
                    
                    # Get active ephemeral sessions
                    cursor.execute("""
                        SELECT das.*, d.title, d.classification_label
                        FROM document_access_sessions das
                        LEFT JOIN documents d ON das.document_id = d.id
                        WHERE das.user_identity_hash = %s
                        AND das.status = 'active'
                        AND das.expires_at > NOW()
                        ORDER BY das.expires_at DESC
                    """, (user_identity_hash,))
                    
                    active_sessions = cursor.fetchall()
                    
                    return {
                        'success': True,
                        'user': {
                            'id': user['id'],
                            'email': user['email'],
                            'full_name': user['full_name']
                        },
                        'time_period': {
                            'days_back': days_back,
                            'since_date': since_date.isoformat(),
                            'until_date': datetime.now().isoformat()
                        },
                        'statistics': {
                            'total_accesses': stats['total_accesses'] or 0,
                            'ephemeral_accesses': stats['ephemeral_accesses'] or 0,
                            'standard_accesses': stats['standard_accesses'] or 0,
                            'successful_accesses': stats['successful_accesses'] or 0,
                            'denied_accesses': stats['denied_accesses'] or 0,
                            'unique_documents': stats['unique_documents_accessed'] or 0,
                            'success_rate': (stats['successful_accesses'] / max(stats['total_accesses'], 1)) * 100,
                            'ephemeral_usage_rate': (stats['ephemeral_accesses'] / max(stats['total_accesses'], 1)) * 100
                        },
                        'access_history': [
                            {
                                'id': record['id'],
                                'document_id': record['document_id'],
                                'document_title': record['title'] or 'Unknown',
                                'classification': record['classification_label'] or 'Unknown',
                                'access_method': record['access_method'],
                                'result': record['access_result'],
                                'ephemeral_did_used': record['ephemeral_did_used'],
                                'access_time': record['access_time'].isoformat(),
                                'details': record['access_details'] or {}
                            } for record in access_history
                        ],
                        'ephemeral_history': [
                            {
                                'id': record['id'],
                                'document_id': record['document_id'],
                                'document_title': record['title'] or 'Unknown',
                                'classification': record['classification_label'] or 'Unknown',
                                'ephemeral_did': record['ephemeral_did'],
                                'session_token': record['session_token'],
                                'operation': record['operation'],
                                'result': record['result'],
                                'timestamp': record['created_at'].isoformat(),
                                'details': record['operation_details'] or {}
                            } for record in ephemeral_history
                        ],
                        'active_sessions': [
                            {
                                'session_token': session['session_token'],
                                'document_id': session['document_id'],
                                'document_title': session['title'] or 'Unknown',
                                'classification': session['classification_label'] or 'Unknown',
                                'created_at': session['created_at'].isoformat(),
                                'expires_at': session['expires_at'].isoformat(),
                                'ephemeral_did': session['ephemeral_did']
                            } for session in active_sessions
                        ]
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error getting user ephemeral access history: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'History retrieval failed: {str(e)}'
            }
    
    def get_document_access_patterns(self, document_id: int) -> Dict[str, Any]:
        """
        Analyze access patterns for a specific document
        
        Args:
            document_id: Document to analyze
            
        Returns:
            Dict with access patterns, user analytics, and security insights
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
                    # Get document info
                    cursor.execute("""
                        SELECT d.*, u.full_name as creator_name, u.email as creator_email
                        FROM documents d
                        LEFT JOIN users u ON d.created_by_user_id = u.id
                        WHERE d.id = %s
                    """, (document_id,))
                    
                    document = cursor.fetchone()
                    if not document:
                        return {
                            'success': False,
                            'error': 'Document not found'
                        }
                    
                    # Get access statistics
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total_access_attempts,
                            COUNT(DISTINCT user_identity_hash) as unique_users,
                            COUNT(CASE WHEN access_method = 'ephemeral_did' THEN 1 END) as ephemeral_accesses,
                            COUNT(CASE WHEN access_method = 'standard' THEN 1 END) as standard_accesses,
                            COUNT(CASE WHEN access_result = 'success' THEN 1 END) as successful_accesses,
                            COUNT(CASE WHEN access_result = 'denied' THEN 1 END) as denied_accesses,
                            MIN(created_at) as first_access,
                            MAX(created_at) as last_access
                        FROM document_access_log
                        WHERE document_id = %s
                    """, (document_id,))
                    
                    stats = cursor.fetchone()
                    
                    # Get user access breakdown
                    cursor.execute("""
                        SELECT dal.user_identity_hash, u.full_name, u.email,
                               COUNT(*) as access_count,
                               COUNT(CASE WHEN dal.access_method = 'ephemeral_did' THEN 1 END) as ephemeral_count,
                               COUNT(CASE WHEN dal.access_result = 'success' THEN 1 END) as success_count,
                               MAX(dal.created_at) as last_access
                        FROM document_access_log dal
                        LEFT JOIN users u ON dal.user_identity_hash = u.identity_hash
                        WHERE dal.document_id = %s
                        GROUP BY dal.user_identity_hash, u.full_name, u.email
                        ORDER BY access_count DESC
                        LIMIT 20
                    """, (document_id,))
                    
                    user_patterns = cursor.fetchall()
                    
                    return {
                        'success': True,
                        'document': {
                            'id': document['id'],
                            'title': document['title'],
                            'classification_level': document['classification_level'],
                            'classification_label': document['classification_label'],
                            'creator': document['creator_name'] or 'Unknown',
                            'creator_email': document['creator_email'],
                            'created_at': document['created_at'].isoformat(),
                            'supports_ephemeral': document['encrypted_with_ephemeral_did'],
                            'file_size': document['file_size']
                        },
                        'access_statistics': {
                            'total_attempts': stats['total_access_attempts'] or 0,
                            'unique_users': stats['unique_users'] or 0,
                            'ephemeral_accesses': stats['ephemeral_accesses'] or 0,
                            'standard_accesses': stats['standard_accesses'] or 0,
                            'successful_accesses': stats['successful_accesses'] or 0,
                            'denied_accesses': stats['denied_accesses'] or 0,
                            'success_rate': (stats['successful_accesses'] / max(stats['total_access_attempts'], 1)) * 100,
                            'ephemeral_usage_rate': (stats['ephemeral_accesses'] / max(stats['total_access_attempts'], 1)) * 100,
                            'first_access': stats['first_access'].isoformat() if stats['first_access'] else None,
                            'last_access': stats['last_access'].isoformat() if stats['last_access'] else None
                        },
                        'user_patterns': [
                            {
                                'user_identity_hash': pattern['user_identity_hash'],
                                'user_name': pattern['full_name'] or 'Unknown',
                                'user_email': pattern['email'] or 'Unknown',
                                'total_accesses': pattern['access_count'],
                                'ephemeral_accesses': pattern['ephemeral_count'],
                                'successful_accesses': pattern['success_count'],
                                'last_access': pattern['last_access'].isoformat(),
                                'success_rate': (pattern['success_count'] / pattern['access_count']) * 100
                            } for pattern in user_patterns
                        ]
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error analyzing document access patterns: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Pattern analysis failed: {str(e)}'
            }
    
    def cleanup_expired_ephemeral_sessions(self) -> Dict[str, Any]:
        """
        Clean up expired ephemeral DID sessions and related data
        
        Returns:
            Dict with cleanup results and statistics
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
                    # Get count of expired sessions before cleanup
                    cursor.execute("""
                        SELECT COUNT(*) as expired_count
                        FROM document_access_sessions
                        WHERE status = 'active' AND expires_at <= NOW()
                    """)
                    
                    expired_count = cursor.fetchone()['expired_count']
                    
                    # Mark expired sessions as expired
                    cursor.execute("""
                        UPDATE document_access_sessions
                        SET status = 'expired', updated_at = CURRENT_TIMESTAMP
                        WHERE status = 'active' AND expires_at <= NOW()
                    """)
                    
                    sessions_updated = cursor.rowcount
                    
                    # Clean up old ephemeral encryption metadata (older than 7 days)
                    cleanup_date = datetime.now() - timedelta(days=7)
                    cursor.execute("""
                        DELETE FROM document_ephemeral_encryption
                        WHERE created_at < %s
                        AND NOT EXISTS (
                            SELECT 1 FROM document_access_sessions das
                            WHERE das.session_token = document_ephemeral_encryption.session_token
                            AND das.status = 'active'
                        )
                    """, (cleanup_date,))
                    
                    encryption_records_cleaned = cursor.rowcount
                    
                    conn.commit()
                    
                    return {
                        'success': True,
                        'cleanup_results': {
                            'expired_sessions_found': expired_count,
                            'sessions_updated': sessions_updated,
                            'encryption_records_cleaned': encryption_records_cleaned,
                            'cleanup_date': cleanup_date.isoformat()
                        }
                    }
                    
            finally:
                conn.close()
                
        except Exception as e:
            print(f"❌ Error cleaning up expired ephemeral sessions: {e}")
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Cleanup failed: {str(e)}'
            }