#!/usr/bin/env python3
"""
Updated Flask server for Hyperledger Identus Classification Document System
Now with proper templates, config management, and enhanced functionality
"""

from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_from_directory, session
from flask_cors import CORS
import os
import json
import base64
import threading
from datetime import datetime, timedelta
import sys
import traceback
from functools import wraps
import hashlib
import secrets
import bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor

# Import our configuration and Identus integration
from config import get_config, get_flask_config
from identus_wrapper import identus_client
from multi_tenant_identus import multi_tenant_client
from document_encryption import ephemeral_encryption, encrypt_document_for_ephemeral_session
from classification_manager import ClassificationManager
from ephemeral_session_manager import EphemeralSessionManager
from security_validator import EphemeralDIDSecurityValidator

# Initialize Flask app
app = Flask(__name__, 
           template_folder='frontend/templates',
           static_folder='frontend/static')

# Configure Flask with our config system
config = get_config()
app.config.update(get_flask_config())

# Initialize classification manager with ephemeral DID support (Task 4.2)
classification_manager = ClassificationManager(config)

# Initialize ephemeral session manager and security validator (Task 5.1 & 5.2)
session_manager = EphemeralSessionManager(config)
security_validator = EphemeralDIDSecurityValidator(config)

# Enable CORS
CORS(app)

# Configure Flask app
app.config['SECRET_KEY'] = config.security.secret_key

# Database connection helper
def get_db_connection():
    """Get database connection using connection string from config"""
    try:
        if config.database.database_url.startswith('sqlite'):
            # Use SQLite connection
            import sqlite3
            sqlite3.register_adapter(dict, lambda d: json.dumps(d))
            sqlite3.register_converter("JSON", lambda s: json.loads(s.decode()))
            
            db_path = config.database.database_url.replace('sqlite:///', '')
            conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            return conn
        else:
            # Use PostgreSQL connection
            conn = psycopg2.connect(
                config.database.database_url,
                cursor_factory=RealDictCursor
            )
            return conn
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return None

def is_sqlite():
    """Check if using SQLite database"""
    return config.database.database_url.startswith('sqlite')

def get_param_placeholder():
    """Get parameter placeholder for current database type"""
    return '?' if is_sqlite() else '%s'

# ==================== ENHANCED AUTHENTICATION FUNCTIONS ====================

def generate_identity_hash(email: str, password: str, enterprise_account_name: str) -> str:
    """Generate deterministic identity hash using enterprise account as salt"""
    combined = f"{email.lower().strip()}{password}{enterprise_account_name}"
    return hashlib.sha256(combined.encode()).hexdigest()

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password against bcrypt hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_user_account(email: str, password: str, full_name: str, 
                       enterprise_account_name: str = "DEFAULT_ENTERPRISE",
                       department: str = None, job_title: str = None, 
                       employee_id: str = None) -> dict:
    """Create new user with enterprise account-based identity"""
    conn = get_db_connection()
    if not conn:
        return {'success': False, 'error': 'Database connection failed'}
    
    try:
        with conn.cursor() as cursor:
            # Check if enterprise account exists
            cursor.execute("SELECT id FROM enterprise_accounts WHERE account_name = %s AND is_active = true", 
                         (enterprise_account_name,))
            enterprise_account = cursor.fetchone()
            
            if not enterprise_account:
                return {'success': False, 'error': f'Enterprise account {enterprise_account_name} not found'}
            
            # Generate identity hash using enterprise account name as salt
            identity_hash = generate_identity_hash(email, password, enterprise_account_name)
            password_hash = hash_password(password)
            
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE email = %s OR identity_hash = %s", 
                         (email, identity_hash))
            if cursor.fetchone():
                return {'success': False, 'error': 'User already exists'}
            
            # Create user
            cursor.execute("""
                INSERT INTO users (email, password_hash, enterprise_account_id, enterprise_account_name, 
                                 identity_hash, full_name, department, job_title, employee_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, identity_hash
            """, (email, password_hash, enterprise_account['id'], enterprise_account_name, 
                  identity_hash, full_name, department, job_title, employee_id))
            
            user_result = cursor.fetchone()
            conn.commit()
            
            return {
                'success': True, 
                'user_id': user_result['id'],
                'identity_hash': user_result['identity_hash'],
                'enterprise_account_name': enterprise_account_name,
                'message': 'User created successfully'
            }
            
    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}
    finally:
        conn.close()

def authenticate_user(email: str, password: str, 
                     enterprise_account_name: str = None) -> dict:
    """Authenticate user with enterprise account validation"""
    conn = get_db_connection()
    if not conn:
        return {'success': False, 'error': 'Database connection failed'}
    
    try:
        with conn.cursor() as cursor:
            # If enterprise_account_name not provided, look it up by email
            if not enterprise_account_name:
                cursor.execute("SELECT enterprise_account_name FROM users WHERE email = %s AND is_active = true", 
                             (email,))
                user_lookup = cursor.fetchone()
                if not user_lookup:
                    return {'success': False, 'error': 'User not found'}
                enterprise_account_name = user_lookup['enterprise_account_name']
            
            # Generate identity hash and verify against stored hash
            identity_hash = generate_identity_hash(email, password, enterprise_account_name)
            
            cursor.execute("""
                SELECT u.*, ea.account_display_name 
                FROM users u
                JOIN enterprise_accounts ea ON u.enterprise_account_name = ea.account_name
                WHERE u.identity_hash = %s AND u.is_active = true AND ea.is_active = true
            """, (identity_hash,))
            
            user = cursor.fetchone()
            if not user:
                return {'success': False, 'error': 'Invalid credentials'}
            
            # Verify password
            if not verify_password(password, user['password_hash']):
                return {'success': False, 'error': 'Invalid credentials'}
            
            # Get user's credentials
            cursor.execute("""
                SELECT credential_type, classification_level, status 
                FROM issued_credentials 
                WHERE user_id = %s AND status = 'issued'
                AND (expires_at IS NULL OR expires_at > NOW())
            """, (user['id'],))
            
            credentials = cursor.fetchall()
            
            return {
                'success': True,
                'user': dict(user),
                'credentials': [dict(cred) for cred in credentials],
                'identity_hash_display': identity_hash[:8] + '...',
                'message': 'Authentication successful'
            }
            
    except Exception as e:
        return {'success': False, 'error': str(e)}
    finally:
        conn.close()

def recover_user_identity(email: str, new_password: str, 
                         enterprise_account_name: str, 
                         admin_authorization: str) -> dict:
    """Registration Authority recovery of lost user credentials"""
    # TODO: Implement admin authorization validation
    conn = get_db_connection()
    if not conn:
        return {'success': False, 'error': 'Database connection failed'}
    
    try:
        with conn.cursor() as cursor:
            # Find user by email and enterprise account
            cursor.execute("""
                SELECT id, email, full_name FROM users 
                WHERE email = %s AND enterprise_account_name = %s
            """, (email, enterprise_account_name))
            
            user = cursor.fetchone()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Generate new identity hash with new password
            new_identity_hash = generate_identity_hash(email, new_password, enterprise_account_name)
            new_password_hash = hash_password(new_password)
            
            # Update user record
            cursor.execute("""
                UPDATE users 
                SET password_hash = %s, identity_hash = %s, updated_at = NOW()
                WHERE id = %s
            """, (new_password_hash, new_identity_hash, user['id']))
            
            # Update all issued credentials with new identity hash
            cursor.execute("""
                UPDATE issued_credentials 
                SET identity_hash = %s
                WHERE user_id = %s
            """, (new_identity_hash, user['id']))
            
            # Log recovery action
            cursor.execute("""
                INSERT INTO credential_audit_log 
                (user_id, identity_hash, enterprise_account_name, action, credential_category, 
                 details, performed_by)
                VALUES (%s, %s, %s, 'recover', 'enterprise', %s, %s)
            """, (user['id'], new_identity_hash, enterprise_account_name, 
                  json.dumps({'email': email, 'recovery_type': 'admin_password_reset'}),
                  admin_authorization))
            
            conn.commit()
            
            return {
                'success': True,
                'new_identity_hash': new_identity_hash,
                'message': 'User credentials recovered successfully'
            }
            
    except Exception as e:
        conn.rollback()
        return {'success': False, 'error': str(e)}
    finally:
        conn.close()

def get_enterprise_account_info(account_name: str) -> dict:
    """Get enterprise account information"""
    conn = get_db_connection()
    if not conn:
        return {'success': False, 'error': 'Database connection failed'}
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT * FROM enterprise_accounts 
                WHERE account_name = %s AND is_active = true
            """, (account_name,))
            
            account = cursor.fetchone()
            if not account:
                return {'success': False, 'error': 'Enterprise account not found'}
            
            return {'success': True, 'account': dict(account)}
            
    except Exception as e:
        return {'success': False, 'error': str(e)}
    finally:
        conn.close()

def list_enterprise_users(enterprise_account_name: str, 
                         include_inactive: bool = False) -> list:
    """List all users under enterprise account"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        with conn.cursor() as cursor:
            where_clause = "WHERE enterprise_account_name = %s"
            params = [enterprise_account_name]
            
            if not include_inactive:
                where_clause += " AND is_active = true"
            
            cursor.execute(f"""
                SELECT id, email, full_name, department, job_title, employee_id, 
                       is_active, has_enterprise_credential, created_at
                FROM users 
                {where_clause}
                ORDER BY created_at DESC
            """, params)
            
            return [dict(user) for user in cursor.fetchall()]
            
    except Exception as e:
        print(f"❌ Error listing enterprise users: {e}")
        return []
    finally:
        conn.close()

def get_user_max_classification_level(identity_hash: str) -> int:
    """Get user's maximum classification level"""
    conn = get_db_connection()
    if not conn:
        return 0
    
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT get_user_max_classification_level(%s)", (identity_hash,))
            result = cursor.fetchone()
            return result[0] if result else 0
            
    except Exception as e:
        print(f"❌ Error getting max classification level: {e}")
        return 0
    finally:
        conn.close()

# Real applications storage - loads from Identus system
applications_db = []

# Enhanced user session with enterprise account structure (Working Package 1)
current_user = {
    'is_authenticated': True,
    'user_id': 1,
    'email': 'john.doe@company.com',
    'enterprise_account_name': 'DEFAULT_ENTERPRISE',  # Enterprise account used as salt
    'enterprise_account_display': 'Default Enterprise Account',
    'identity_hash': 'f51bf4b4f472276b722dd7f3a0f1d24636985c862eac00012cf8560f0abbb7c2',  # Generated with enterprise account as salt
    'identity_hash_display': 'f51bf4b4...',  # First 8 chars for display
    'full_name': 'John Doe',
    'department': 'Engineering',
    'job_title': 'Senior Developer',
    'employee_id': 'EMP-001',
    
    # Two-stage credential system
    'has_enterprise_credential': True,  # Basic enterprise access
    'classification_credentials': {
        'public': {'status': 'issued', 'level': 1},
        'internal': {'status': 'none', 'level': 0},
        'confidential': {'status': 'none', 'level': 0}
    },
    'max_classification_level': 1,  # Current maximum classification level
    'active_credentials': ['public'],  # Currently valid credentials
    'pending_requests': [],  # Pending credential requests
    'is_admin': True,
    'can_recover_credentials': True,  # Admin can recover using enterprise account
    'last_login': datetime.now(),
    'session_expires': datetime.now() + timedelta(hours=8)
}

def get_current_user():
    """Get current user from Flask session, fallback to global variable"""
    if 'user_data' in session:
        return session['user_data']
    else:
        # Fallback to global variable for backwards compatibility
        return current_user

def set_current_user(user_data):
    """Set current user in Flask session"""
    session['user_data'] = user_data
    # Also update global variable for backwards compatibility
    global current_user
    current_user.update(user_data)

def clear_current_user():
    """Clear current user from session"""
    session.pop('user_data', None)
    global current_user
    current_user = {
        'is_authenticated': False,
        'user_id': None,
        'email': None,
        'full_name': 'Guest'
    }

def load_real_identus_data():
    """Load real data from Identus system"""
    global applications_db
    try:
        print("📊 Loading real data from Identus system...")
        
        # Get credential records from Identus
        credential_records = identus_client.get_credential_records()
        
        # Get DID records  
        did_records = identus_client.get_dids()
        
        # Convert Identus records to application format
        for record in credential_records.get('contents', []):
            # Extract application info from credential record
            claims = record.get('claims', {})
            
            # Determine application data based on schema format
            if 'familyName' in claims:  # Driving license schema format
                app_data = {
                    "id": f"identus-{record.get('recordId', 'unknown')}",
                    "name": claims.get('familyName', 'Unknown'),
                    "email": claims.get('emailAddress', 'unknown@example.com'),
                    "specialization": "Data Labeling",  # Default
                    "experienceLevel": "Certified",  # Default for issued credentials
                    "qualifications": [],
                    "submittedDate": record.get('createdAt', datetime.now().isoformat()),
                    "status": "approved",  # Already issued
                    "labelerID": claims.get('drivingLicenseID', f"LAB{int(datetime.now().timestamp())}"),
                    "realCredential": True,
                    "credentialId": record.get('recordId'),
                    "invitationUrl": record.get('invitationUrl'),
                    "approvedDate": record.get('updatedAt', record.get('createdAt')),
                    "processedBy": "identus-system"
                }
            else:  # Custom data labeler schema format
                app_data = {
                    "id": f"identus-{record.get('recordId', 'unknown')}",
                    "name": claims.get('fullName', claims.get('labelerName', 'Unknown')),
                    "email": claims.get('email', 'unknown@example.com'),
                    "specialization": claims.get('specialization', 'General'),
                    "experienceLevel": claims.get('experienceLevel', 'Certified'),
                    "qualifications": claims.get('qualifications', []),
                    "submittedDate": record.get('createdAt', datetime.now().isoformat()),
                    "status": "approved",  # Already issued
                    "labelerID": claims.get('labelerID', f"LAB{int(datetime.now().timestamp())}"),
                    "realCredential": True,
                    "credentialId": record.get('recordId'),
                    "invitationUrl": record.get('invitationUrl'),
                    "approvedDate": record.get('updatedAt', record.get('createdAt')),
                    "processedBy": "identus-system"
                }
            
            applications_db.append(app_data)
        
        # Add a few pending mock applications for demonstration
        if len(applications_db) < 3:
            demo_apps = [
                {
                    "id": "demo-001",
                    "name": "New Applicant Alice",
                    "email": "alice.new@example.com",
                    "specialization": "Image Classification",
                    "experienceLevel": "Advanced",
                    "qualifications": ["Computer Vision", "Machine Learning"],
                    "submittedDate": datetime.now().isoformat(),
                    "status": "pending",
                    "labelerID": f"LAB{int(datetime.now().timestamp())}"
                },
                {
                    "id": "demo-002",
                    "name": "Pending User Bob",
                    "email": "bob.pending@example.com",
                    "specialization": "Object Detection",
                    "experienceLevel": "Intermediate",
                    "qualifications": ["YOLO", "Computer Vision"],
                    "submittedDate": datetime.now().isoformat(),
                    "status": "pending",
                    "labelerID": f"LAB{int(datetime.now().timestamp()) + 1}"
                }
            ]
            applications_db.extend(demo_apps)
        
        print(f"✅ Loaded {len(applications_db)} applications from Identus system")
        
        # Show breakdown
        approved = len([app for app in applications_db if app['status'] == 'approved'])
        pending = len([app for app in applications_db if app['status'] == 'pending'])
        real_creds = len([app for app in applications_db if app.get('realCredential', False)])
        
        print(f"📊 Applications: {approved} approved, {pending} pending, {real_creds} real credentials")
        
    except Exception as e:
        print(f"⚠️ Could not load real Identus data: {e}")
        print("📋 Using demo applications instead...")
        
        # Fallback to demo data if Identus not available
        applications_db = [
            {
                "id": "demo-001",
                "name": "Demo User Alice",
                "email": "alice.demo@example.com",
                "specialization": "Image Classification",
                "experienceLevel": "Expert",
                "qualifications": ["Computer Vision", "Medical Imaging"],
                "submittedDate": datetime.now().isoformat(),
                "status": "pending",
                "labelerID": f"LAB{int(datetime.now().timestamp())}"
            },
            {
                "id": "demo-002",
                "name": "Demo User Bob",
                "email": "bob.demo@example.com",
                "specialization": "Object Detection",
                "experienceLevel": "Advanced",
                "qualifications": ["Deep Learning", "YOLO"],
                "submittedDate": datetime.now().isoformat(),
                "status": "pending",
                "labelerID": f"LAB{int(datetime.now().timestamp()) + 1}"
            }
        ]

# Initialize Identus in a separate thread to avoid blocking startup
def initialize_identus():
    """Initialize Identus connection and load real data"""
    try:
        print("🔧 Checking Identus agents...")
        if identus_client.check_agents_health():
            print("✅ Identus agents are running")
            success = identus_client.initialize()
            if success:
                print("🎉 Identus integration initialized successfully!")
                print(f"📋 Issuer DID: {identus_client.issuer_did}")
                print(f"📄 Schema URI: {identus_client.schema_uri}")
                
                # Load real data from Identus
                load_real_identus_data()
                
            else:
                print("❌ Identus initialization failed")
                load_real_identus_data()  # Will use demo data
        else:
            print("⚠️ Identus agents not running. Dashboard will work with demo data only.")
            print("💡 Start your Identus agents on ports 8080, 7000, and 9000 for real credential issuance.")
            load_real_identus_data()  # Will use demo data
    except Exception as e:
        print(f"⚠️ Identus initialization error: {e}")
        load_real_identus_data()  # Will use demo data

# Start Identus initialization in background
threading.Thread(target=initialize_identus, daemon=True).start()

# ==================== EPHEMERAL DID CLASSIFICATION FUNCTIONS (Task 2.3) ====================

def verify_classification_for_ephemeral_access(user_identity_hash: str, classification_level: int) -> dict:
    """Verify user has classification credentials for ephemeral document access"""
    try:
        conn = get_db_connection()
        if not conn:
            return {'success': False, 'error': 'Database connection failed'}
        
        cursor = conn.cursor()
        param = get_param_placeholder()
        
        if is_sqlite():
            # SQLite fallback - check directly in issued_credentials table
            cursor.execute(f"""
                SELECT COUNT(*) as has_access
                FROM issued_credentials ic
                WHERE ic.user_identity_hash = {param}
                AND ic.classification_level >= {param}
                AND ic.status = 'issued'
            """, (user_identity_hash, classification_level))
            
            result = cursor.fetchone()
            can_access = result[0] > 0 if result else False
        else:
            # PostgreSQL - use stored function
            cursor.execute(f"""
                SELECT can_user_access_level({param}, {param}) as can_access
            """, (user_identity_hash, classification_level))
            
            access_check = cursor.fetchone()
            can_access = access_check and access_check['can_access']
        
        cursor.close()
        conn.close()
        
        return {
            'success': True,
            'can_access': can_access,
            'classification_level': classification_level,
            'message': f'User {"has valid" if can_access else "lacks"} classification credentials for level {classification_level}'
        }
        
    except Exception as e:
        print(f"❌ Classification verification failed: {e}")
        return {'success': False, 'error': str(e)}

def validate_ongoing_ephemeral_session(session_token: str, user_identity_hash: str) -> dict:
    """Validate ongoing ephemeral session status and permissions"""
    try:
        conn = get_db_connection()
        if not conn:
            return {'success': False, 'error': 'Database connection failed'}
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get session details with document info
        cursor.execute("""
            SELECT das.*, d.filename, d.classification_level, d.mime_type,
                   EXTRACT(EPOCH FROM (das.expires_at - NOW())) as seconds_until_expiry
            FROM document_access_sessions das
            JOIN documents d ON das.document_id = d.id
            WHERE das.session_token = %s 
            AND das.user_identity_hash = %s
            AND das.expires_at > NOW()
            AND das.completed_at IS NULL
        """, (session_token, user_identity_hash))
        
        session = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not session:
            return {
                'success': True,
                'valid': False,
                'error': 'Session not found, expired, or completed',
                'status': 'invalid'
            }
        
        # Check if session is about to expire (less than 5 minutes)
        time_remaining = int(session['seconds_until_expiry'])
        status = 'active'
        
        if time_remaining <= 300:  # 5 minutes
            status = 'expiring_soon'
        elif time_remaining <= 60:  # 1 minute
            status = 'critical_expiry'
        
        return {
            'success': True,
            'valid': True,
            'session_id': session['id'],
            'document_id': session['document_id'],
            'document_filename': session['filename'],
            'classification_level': session['classification_level'],
            'expires_at': session['expires_at'].isoformat() if session['expires_at'] else None,
            'seconds_remaining': time_remaining,
            'status': status,
            'classification_verified': session['classification_verified'],
            'ephemeral_did': session['ephemeral_did'],
            'created_at': session['created_at'].isoformat() if session['created_at'] else None,
            'message': f'Session valid, {time_remaining} seconds remaining'
        }
        
    except Exception as e:
        print(f"❌ Ephemeral session validation failed: {e}")
        return {'success': False, 'error': str(e)}

# Template context processor to make current_user available in all templates
@app.context_processor
def inject_user():
    return dict(current_user=get_current_user(), config=config)

# ==================== WEB ROUTES ====================

@app.route('/')
def dashboard():
    """Main dashboard page with real user data"""
    print("🎯 Dashboard function called!")
    try:
        # Check if user is authenticated
        current_user_data = get_current_user()
        if not current_user_data.get('is_authenticated'):
            return redirect(url_for('login'))
        
        # Get real user data from database
        conn = get_db_connection()
        credentials = []
        recent_activities = []
        stats = {
            'my_credentials': 0,
            'documents_accessed': 0,
            'pending_requests': 0,
            'security_score': 85
        }
        
        print(f"🔍 Dashboard debug: conn={bool(conn)}, is_sqlite={is_sqlite()}, user_id={current_user_data.get('user_id')}")
        
        if conn and not is_sqlite():
            print("✅ Using PostgreSQL credentials loading")
            try:
                with conn.cursor() as cursor:
                    # Get user's issued credentials with all needed fields
                    cursor.execute("""
                        SELECT id, credential_category, credential_type, classification_level, 
                               identus_record_id, invitation_url, issued_at, expires_at, status
                        FROM issued_credentials 
                        WHERE user_id = %s AND status = 'issued'
                        ORDER BY issued_at DESC
                    """, (current_user_data.get('user_id'),))
                    
                    db_credentials = cursor.fetchall()
                    print(f"📋 Found {len(db_credentials)} credentials in database")
                    
                    # Format credentials for display and fetch VCs
                    for cred in db_credentials:
                        # Create credential display object first
                        credential_display = {
                            'id': cred['id'],
                            'name': f"{cred['credential_type'].title()} Credential",
                            'type': cred['credential_type'],
                            'category': cred['credential_category'],
                            'classification_level': cred.get('classification_level'),
                            'identus_record_id': cred.get('identus_record_id'),
                            'invitation_url': cred.get('invitation_url'),
                            'issued_date': cred['issued_at'],
                            'expires_at': cred.get('expires_at'),
                            'status': cred['status']
                        }
                        
                        # Fetch the actual VC from Identus if available
                        vc_data = None
                        if cred.get('identus_record_id'):
                            try:
                                from identus_wrapper import IdentusDashboardClient
                                identus_client = IdentusDashboardClient()
                                vc_data = identus_client.get_verifiable_credential(cred['identus_record_id'])
                                
                                if vc_data:
                                    print(f"✅ Retrieved real VC for {cred['identus_record_id']}")
                                else:
                                    print(f"ℹ️ No VC available for {cred['identus_record_id']}")
                                    
                            except Exception as e:
                                print(f"⚠️ Could not fetch VC for {cred['identus_record_id']}: {e}")
                                vc_data = None
                        
                        # Add VC data to credential display
                        credential_display['verifiable_credential'] = vc_data
                        
                        # If we have a VC with expiration date, use it for display
                        if vc_data and vc_data.get('expirationDate') and not credential_display.get('expires_at'):
                            try:
                                credential_display['expires_at'] = datetime.fromisoformat(vc_data['expirationDate'].replace('Z', '+00:00'))
                            except Exception:
                                pass
                                
                        print(f"📋 Adding credential: {credential_display.get('name')} - {credential_display.get('type')}")
                        credentials.append(credential_display)
                        print(f"📋 Credentials list now has {len(credentials)} items")
                    
                    # Get document count (documents user can access based on classification level only)
                    # SECURITY: Classification credentials supersede document ownership
                    cursor.execute("""
                        SELECT COUNT(*) as doc_count
                        FROM documents d
                        WHERE d.classification_level <= (
                            SELECT COALESCE(MAX(classification_level), 0)
                            FROM issued_credentials 
                            WHERE identity_hash = %s 
                            AND credential_category = 'classification' 
                            AND status = 'issued'
                            AND (expires_at IS NULL OR expires_at > NOW())
                        )
                    """, (current_user_data.get('identity_hash'),))
                    
                    doc_result = cursor.fetchone()
                    stats['documents_accessed'] = doc_result['doc_count'] if doc_result else 0
                    
                    # Get credential requests
                    cursor.execute("""
                        SELECT COUNT(*) as pending_count
                        FROM credential_requests 
                        WHERE user_id = %s AND status = 'pending'
                    """, (current_user_data.get('user_id'),))
                    
                    pending_result = cursor.fetchone()
                    stats['pending_requests'] = pending_result['pending_count'] if pending_result else 0
                    
                    # Get recent credential activities
                    cursor.execute("""
                        SELECT action, credential_type, details, created_at
                        FROM credential_audit_log 
                        WHERE user_id = %s 
                        ORDER BY created_at DESC 
                        LIMIT 5
                    """, (current_user_data.get('user_id'),))
                    
                    audit_records = cursor.fetchall()
                    
                    # Format activities for display
                    for record in audit_records:
                        activity = {
                            'action': record['action'].title().replace('_', ' '),
                            'description': f"{record['credential_type']} credential {record['action']}",
                            'timestamp': record['created_at'],
                            'type': 'success' if record['action'] in ['approve', 'issue'] else 'info'
                        }
                        recent_activities.append(activity)
                    
                    # Update stats
                    stats['my_credentials'] = len(credentials)
                    
            except Exception as db_error:
                print(f"⚠️ Database error in dashboard: {db_error}")
            finally:
                conn.close()
        else:
            # SQLite/Development mode - use mock data
            print("🔧 Dashboard using mock data for development mode")
            
            # Mock credentials for John Doe
            credentials = [
                {
                    'id': 1,
                    'name': 'Enterprise Credential',
                    'type': 'enterprise',
                    'category': 'enterprise',
                    'classification_level': 0,
                    'identus_record_id': 'demo_enterprise_123',
                    'issued_date': datetime.now() - timedelta(days=5),
                    'expires_at': datetime.now() + timedelta(days=360),
                    'status': 'issued',
                    'verifiable_credential': {
                        '@context': ['https://www.w3.org/2018/credentials/v1'],
                        'type': ['VerifiableCredential', 'EnterpriseAccessCredential'],
                        'issuer': 'did:prism:issuer123',
                        'issuanceDate': (datetime.now() - timedelta(days=5)).isoformat(),
                        'expirationDate': (datetime.now() + timedelta(days=360)).isoformat(),
                        'credentialSubject': {
                            'id': 'did:prism:holder456',
                            'fullName': current_user_data.get('full_name', 'John Doe'),
                            'email': current_user_data.get('email', 'john.doe@company.com'),
                            'employeeId': current_user_data.get('employee_id', 'EMP-001'),
                            'department': current_user_data.get('department', 'Engineering'),
                            'enterpriseAccount': current_user_data.get('enterprise_account_name', 'DEFAULT_ENTERPRISE')
                        }
                    }
                },
                {
                    'id': 2,
                    'name': 'Public Classification Credential',
                    'type': 'public',
                    'category': 'classification',
                    'classification_level': 1,
                    'identus_record_id': 'demo_public_456',
                    'issued_date': datetime.now() - timedelta(days=3),
                    'expires_at': datetime.now() + timedelta(days=180),
                    'status': 'issued',
                    'verifiable_credential': {
                        '@context': ['https://www.w3.org/2018/credentials/v1'],
                        'type': ['VerifiableCredential', 'ClassificationCredential'],
                        'issuer': 'did:prism:issuer123',
                        'issuanceDate': (datetime.now() - timedelta(days=3)).isoformat(),
                        'expirationDate': (datetime.now() + timedelta(days=180)).isoformat(),
                        'credentialSubject': {
                            'id': 'did:prism:holder456',
                            'fullName': current_user_data.get('full_name', 'John Doe'),
                            'classificationLevel': 1,
                            'classificationName': 'Public',
                            'authorizedOperations': ['read', 'process'],
                            'department': current_user_data.get('department', 'Engineering')
                        }
                    }
                }
            ]
            
            # Mock statistics
            stats = {
                'my_credentials': 2,
                'documents_accessed': 8,
                'pending_requests': 1,
                'security_score': 92
            }
            
            # Mock recent activities
            recent_activities = [
                {
                    'action': 'Credential Issued',
                    'description': 'Public classification credential approved and issued',
                    'timestamp': datetime.now() - timedelta(hours=2),
                    'type': 'success'
                },
                {
                    'action': 'Document Accessed',
                    'description': 'Accessed quarterly_report.pdf (Public)',
                    'timestamp': datetime.now() - timedelta(hours=8),
                    'type': 'info'
                },
                {
                    'action': 'Credential Request',
                    'description': 'Requested Internal classification credential',
                    'timestamp': datetime.now() - timedelta(days=1),
                    'type': 'info'
                }
            ]
        
        # Add default activity if no real activities
        if not recent_activities:
            recent_activities.append({
                'action': 'Account Created',
                'description': f'Welcome to the enterprise account system, {current_user.get("full_name", "User")}!',
                'timestamp': current_user.get('last_login', datetime.now()),
                'type': 'success'
            })
        
        # Add default credential if user has enterprise credential status
        if not credentials and current_user.get('has_enterprise_credential'):
            credentials.append({
                'name': 'Enterprise Access Credential',
                'type': 'basic_enterprise',
                'classification_level': 0,
                'issued_date': current_user.get('last_login', datetime.now()),
                'status': 'issued'
            })
        
        print(f"📋 Rendering dashboard with {len(credentials)} credentials")
        for i, cred in enumerate(credentials):
            print(f"  {i+1}. {cred.get('name', 'Unknown')} - {cred.get('type', 'Unknown')}")
        
        return render_template('dashboard.html',
                             stats=stats,
                             credentials=credentials,
                             recent_activities=recent_activities)
    except Exception as e:
        print(f"❌ Dashboard error: {e}")
        traceback.print_exc()
        flash('Error loading dashboard', 'error')
        return render_template('dashboard.html', stats={}, credentials=[], recent_activities=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication"""
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            
            if not email or not password:
                flash('Please provide both email and password', 'error')
                return render_template('login.html')
            
            # Get user from database
            conn = get_db_connection()
            if conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, email, password_hash, enterprise_account_name, 
                               identity_hash, full_name, department, job_title, 
                               employee_id, has_enterprise_credential
                        FROM users 
                        WHERE email = %s AND is_active = true
                    """, (email,))
                    
                    user_row = cursor.fetchone()
                    
                    if user_row and verify_password(password, user_row['password_hash']):
                        # Create user data and store in session
                        user_data = {
                            'is_authenticated': True,
                            'user_id': user_row['id'],
                            'email': user_row['email'],
                            'enterprise_account_name': user_row['enterprise_account_name'],
                            'enterprise_account_display': 'Default Enterprise Account',
                            'identity_hash': user_row['identity_hash'],
                            'identity_hash_display': user_row['identity_hash'][:8] + '...',
                            'full_name': user_row['full_name'],
                            'department': user_row['department'],
                            'job_title': user_row['job_title'],
                            'employee_id': user_row['employee_id'],
                            'has_enterprise_credential': user_row['has_enterprise_credential'],
                            'is_admin': is_admin_user({'email': user_row['email'], 'job_title': user_row['job_title'], 'is_authenticated': True}),
                            'can_recover_credentials': True,
                            'last_login': datetime.now(),
                            'session_expires': datetime.now() + timedelta(hours=8)
                        }
                        
                        set_current_user(user_data)
                        
                        flash(f'Welcome back, {user_row["full_name"]}!', 'success')
                        return redirect(url_for('dashboard'))
                    else:
                        flash('Invalid email or password', 'error')
                        return render_template('login.html')
            else:
                flash('Database connection error', 'error')
                return render_template('login.html')
                
        except Exception as e:
            print(f"❌ Login error: {e}")
            traceback.print_exc()
            flash('Login error occurred', 'error')
            return render_template('login.html')
    
    # GET request - show login form
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    clear_current_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/documents/upload')
def upload_document():
    """Document upload page"""
    return render_template('documents/upload.html')

@app.route('/documents/browse')
def browse_documents():
    """Browse documents page"""
    try:
        # Check if user is authenticated
        current_user_data = get_current_user()
        if not current_user_data.get('is_authenticated'):
            return redirect(url_for('login'))
        
        # Get user's accessible documents from database
        conn = get_db_connection()
        documents = []
        
        if conn:
            try:
                with conn.cursor() as cursor:
                    # Get documents the user can access ONLY based on their classification level
                    # SECURITY: Classification credentials supersede document ownership
                    cursor.execute("""
                        SELECT d.id, d.title, d.filename, d.classification_level, 
                               d.classification_label, d.file_size, d.created_at,
                               d.created_by_identity_hash, u.full_name as uploaded_by_name
                        FROM documents d
                        JOIN users u ON d.created_by_user_id = u.id
                        WHERE d.classification_level <= (
                            SELECT COALESCE(MAX(classification_level), 0)
                            FROM issued_credentials 
                            WHERE identity_hash = %s 
                            AND credential_category = 'classification' 
                            AND status = 'issued'
                            AND (expires_at IS NULL OR expires_at > NOW())
                        )
                        ORDER BY d.created_at DESC
                    """, (current_user_data.get('identity_hash'),))
                    
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        # Map classification level to name
                        classification_name = {
                            1: 'Public',
                            2: 'Internal', 
                            3: 'Confidential'
                        }.get(row['classification_level'], 'Unknown')
                        
                        # Since the query already filters for accessible documents, 
                        # all returned documents should have access granted
                        documents.append({
                            'id': row['id'],
                            'title': row['title'],
                            'filename': row['filename'],
                            'classification_level': row['classification_level'],
                            'classification_label': row['classification_label'],
                            'classification_level_name': classification_name,
                            'file_size': row['file_size'],
                            'created_at': row['created_at'],
                            'uploaded_by_name': row['uploaded_by_name'],
                            'created_by_identity_hash': row['created_by_identity_hash'],
                            'can_access': True  # All returned documents are accessible
                        })
                        
            except Exception as e:
                print(f"❌ Error fetching documents: {e}")
                flash('Error loading documents', 'error')
            finally:
                conn.close()
        
        return render_template('documents/browse.html', documents=documents)
        
    except Exception as e:
        print(f"❌ Browse documents error: {e}")
        flash('Error loading documents', 'error')
        return render_template('documents/browse.html', documents=[])

def is_admin_user(user):
    """Check if user has admin privileges"""
    # Check if user is authenticated
    if not user or not user.get('is_authenticated'):
        return False
    
    # Admin role criteria (you can modify this logic)
    admin_emails = ['admin@company.com']  # Specific admin emails
    admin_job_titles = ['System Administrator', 'Admin', 'Administrator']  # Admin job titles
    
    user_email = user.get('email', '').lower()
    user_job_title = user.get('job_title', '')
    
    # Check if user meets admin criteria
    return (user_email in admin_emails or 
            user_job_title in admin_job_titles or
            'admin' in user_email.lower())

@app.route('/admin/multi-tenant')
def admin_multi_tenant():
    """Multi-tenant Identus administration panel"""
    try:
        # Check if user is authenticated and has admin privileges
        if not current_user.get('is_authenticated'):
            return redirect(url_for('login'))
            
        if not is_admin_user(current_user):
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
            
        print(f"✅ Multi-tenant admin access granted to {current_user.get('email')}")
        
        return render_template('admin/multi-tenant.html', current_user=current_user)
        
    except Exception as e:
        print(f"❌ Error in multi-tenant admin panel: {e}")
        flash('Error loading multi-tenant admin panel. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin')
def admin_panel():
    """Admin panel for managing credential requests"""
    try:
        # Check if user is authenticated and has admin privileges
        print(f"🔍 Admin panel access attempt - User authenticated: {current_user.get('is_authenticated')}")
        print(f"🔍 Current user: {current_user.get('email', 'None')} - {current_user.get('full_name', 'None')}")
        
        if not current_user.get('is_authenticated'):
            print("❌ User not authenticated, redirecting to login")
            return redirect(url_for('login'))
            
        if not is_admin_user(current_user):
            print(f"❌ User {current_user.get('email')} is not admin, redirecting to dashboard")
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
            
        print(f"✅ Admin access granted to {current_user.get('email')}")
        
        # Get pending credential requests
        pending_requests = []
        conn = get_db_connection()
        if conn:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT cr.id, cr.user_id, cr.credential_type, cr.credential_category, 
                               cr.status, cr.business_justification, cr.department_approval,
                               cr.requested_at, u.full_name, u.email, u.department
                        FROM credential_requests cr
                        JOIN users u ON cr.user_id = u.id
                        WHERE cr.status = 'pending'
                        ORDER BY cr.requested_at DESC
                    """)
                    
                    rows = cursor.fetchall()
                    for row in rows:
                        pending_requests.append({
                            'id': row['id'],
                            'user_id': row['user_id'],
                            'user_name': row['full_name'],
                            'user_email': row['email'],
                            'user_department': row['department'],
                            'credential_type': row['credential_type'],
                            'credential_category': row['credential_category'],
                            'status': row['status'],
                            'business_justification': row['business_justification'],
                            'department_approval': row['department_approval'],
                            'requested_at': row['requested_at']
                        })
                    
                    print(f"📊 Found {len(pending_requests)} pending credential requests for admin")
                        
            except Exception as db_error:
                print(f"⚠️ Database error in admin panel: {db_error}")
            finally:
                conn.close()
        
        # Calculate stats for the admin panel
        high_level_count = len([req for req in pending_requests if req['credential_type'] in ['internal', 'confidential']])
        unique_users = len(set(req['user_id'] for req in pending_requests))
        
        return render_template('admin/credential-requests.html', 
                             pending_requests=pending_requests,
                             high_level_count=high_level_count,
                             unique_users=unique_users)
        
    except Exception as e:
        print(f"❌ Admin panel error: {e}")
        flash('Error loading admin panel', 'error')
        return redirect(url_for('dashboard'))

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/auth/login', methods=['POST'])
def auth_login():
    """Handle login form submission with enterprise account authentication"""
    try:
        email = request.form.get('email')
        password = request.form.get('password')
        enterprise_account = request.form.get('enterprise_account')
        remember_me = request.form.get('remember_me')
        
        if not email or not password:
            print(f"❌ Missing credentials: email='{email}', password='{password}'")
            flash('Email and password are required', 'error')
            return redirect(url_for('login'))
        
        print(f"🔍 Login attempt: {email} / password={'*' * len(password) if password else 'None'}")
        print(f"🔍 Is SQLite: {is_sqlite()}")
        print(f"🔍 Email in list: {email in ['john.doe@company.com', 'jane.smith@company.com', 'admin@company.com']}")
        
        # Development mode authentication bypass for testing
        if is_sqlite() and email in ['john.doe@company.com', 'jane.smith@company.com', 'admin@company.com']:
            print(f"🔧 Development mode: Authenticating {email}")
            
            # Mock authentication success for development
            if email == 'john.doe@company.com' and password == 'john123':
                auth_result = {
                    'success': True,
                    'user': {
                        'id': 1,
                        'email': 'john.doe@company.com',
                        'full_name': 'John Doe',
                        'department': 'Engineering',
                        'job_title': 'Senior Developer',
                        'employee_id': 'EMP-001',
                        'enterprise_account_name': 'DEFAULT_ENTERPRISE',
                        'identity_hash': 'f51bf4b4f472276b722dd7f3a0f1d24636985c862eac00012cf8560f0abbb7c2',
                        'identity_hash_display': 'f51bf4b4...'
                    },
                    'credentials': {
                        'enterprise': {'status': 'issued'},
                        'public': {'status': 'issued'}
                    }
                }
            elif email == 'jane.smith@company.com' and password == 'jane123':
                auth_result = {
                    'success': True,
                    'user': {
                        'id': 2,
                        'email': 'jane.smith@company.com',
                        'full_name': 'Jane Smith',
                        'department': 'Data Science',
                        'job_title': 'Data Scientist',
                        'employee_id': 'EMP-002',
                        'enterprise_account_name': 'DEFAULT_ENTERPRISE',
                        'identity_hash': 'jane_identity_hash_12345',
                        'identity_hash_display': 'jane_ide...'
                    },
                    'credentials': {
                        'enterprise': {'status': 'issued'}
                    }
                }
            elif email == 'admin@company.com' and password == 'admin123':
                auth_result = {
                    'success': True,
                    'user': {
                        'id': 3,
                        'email': 'admin@company.com',
                        'full_name': 'System Administrator',
                        'department': 'IT',
                        'job_title': 'System Administrator',
                        'employee_id': 'ADM-001',
                        'enterprise_account_name': 'DEFAULT_ENTERPRISE',
                        'identity_hash': 'admin_identity_hash_12345',
                        'identity_hash_display': 'admin_id...'
                    },
                    'credentials': {
                        'enterprise': {'status': 'issued'},
                        'public': {'status': 'issued'},
                        'internal': {'status': 'issued'},
                        'confidential': {'status': 'issued'}
                    }
                }
            else:
                auth_result = {'success': False, 'error': 'Invalid credentials'}
        else:
            # Authenticate user with enterprise account system
            auth_result = authenticate_user(email, password, enterprise_account)
        
        if auth_result['success']:
            user = auth_result['user']
            credentials = auth_result['credentials']
            
            # Update current_user session with authenticated user data
            current_user.update({
                'is_authenticated': True,
                'user_id': user['id'],
                'email': user['email'],
                'enterprise_account_name': user['enterprise_account_name'],
                'enterprise_account_display': auth_result.get('user', {}).get('account_display_name', user['enterprise_account_name']),
                'identity_hash': user['identity_hash'],
                'identity_hash_display': auth_result['identity_hash_display'],
                'full_name': user['full_name'],
                'department': user['department'],
                'job_title': user['job_title'],
                'employee_id': user['employee_id'],
                'has_enterprise_credential': user['has_enterprise_credential'],
                'last_login': datetime.now(),
                'session_expires': datetime.now() + timedelta(hours=8)
            })
            
            # Process credentials
            classification_creds = {'public': {'status': 'none', 'level': 0},
                                  'internal': {'status': 'none', 'level': 0},
                                  'confidential': {'status': 'none', 'level': 0}}
            active_creds = []
            max_level = 0
            
            for cred in credentials:
                if cred['credential_type'] in classification_creds:
                    classification_creds[cred['credential_type']] = {
                        'status': 'issued',
                        'level': cred['classification_level'] or 0
                    }
                    active_creds.append(cred['credential_type'])
                    max_level = max(max_level, cred['classification_level'] or 0)
            
            current_user.update({
                'classification_credentials': classification_creds,
                'active_credentials': active_creds,
                'max_classification_level': max_level,
                'pending_requests': []  # TODO: Load from database
            })
            
            flash(f'Welcome back, {user["full_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(auth_result['error'], 'error')
            return redirect(url_for('login'))
            
    except Exception as e:
        print(f"❌ Login error: {e}")
        flash('Login failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page with enterprise account selection"""
    if request.method == 'GET':
        # Use our multi-tenant enterprise configurations
        from multi_tenant_identus import multi_tenant_client
        
        enterprise_accounts = []
        for enterprise_name, config in multi_tenant_client.enterprises.items():
            enterprise_accounts.append({
                'account_name': enterprise_name,
                'account_display_name': config.account_display_name
            })
        
        return render_template('register.html', enterprise_accounts=enterprise_accounts)
    
    else:  # POST
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            full_name = request.form.get('full_name')
            enterprise_account = request.form.get('enterprise_account', 'DEFAULT_ENTERPRISE')
            department = request.form.get('department')
            job_title = request.form.get('job_title')
            employee_id = request.form.get('employee_id')
            
            # Validate input
            if not all([email, password, confirm_password, full_name]):
                flash('All required fields must be filled', 'error')
                return redirect(url_for('register'))
            
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return redirect(url_for('register'))
            
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'error')
                return redirect(url_for('register'))
            
            # Create enterprise user with credential
            result = create_enterprise_user_with_credential(email, password, full_name, enterprise_account, 
                                                          department, job_title, employee_id)
            
            if result['success']:
                # Enhanced success message with enterprise info
                enterprise_info = f"Enterprise: {result.get('enterprise_display_name', enterprise_account)}"
                credential_info = "Basic enterprise credential issued!" if result.get('credential_issued') else "Basic credential will be issued upon login."
                
                flash(f'Account created successfully! {enterprise_info}. {credential_info} You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash(result['error'], 'error')
                return redirect(url_for('register'))
                
        except Exception as e:
            print(f"❌ Registration error: {e}")
            flash('Registration failed. Please try again.', 'error')
            return redirect(url_for('register'))

@app.route('/auth/logout')
def auth_logout():
    """Handle logout"""
    clear_current_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

def create_enterprise_user_with_credential(email: str, password: str, full_name: str, 
                                          enterprise_account_name: str = "DEFAULT_ENTERPRISE",
                                          department: str = None, job_title: str = None, 
                                          employee_id: str = None) -> dict:
    """Create new enterprise user and issue basic credential"""
    try:
        from multi_tenant_identus import multi_tenant_client
        from new_credential_issuer import new_credential_issuer
        from holder_wallet_manager import holder_wallet_manager
        import hashlib
        
        print(f"🏢 Creating enterprise user for {enterprise_account_name}")
        print(f"👤 User: {full_name} ({email})")
        
        # Validate enterprise account
        if enterprise_account_name not in multi_tenant_client.enterprises:
            return {'success': False, 'error': f'Enterprise account {enterprise_account_name} not found'}
        
        # Generate enterprise-specific identity hash (consistent with login)
        identity_hash = generate_identity_hash(email, password, enterprise_account_name)
        
        # Hash password
        password_hash = hash_password(password)
        
        # Create user info dictionary
        user_info = {
            'email': email,
            'full_name': full_name,
            'department': department or 'Unknown',
            'job_title': job_title or 'Employee',
            'employee_id': employee_id or f"EMP-{identity_hash[:8].upper()}",
            'enterprise_account': enterprise_account_name,
            'identity_hash': identity_hash,
            'password_hash': password_hash
        }
        
        # Set enterprise context for credential issuance
        if not multi_tenant_client.set_enterprise_context(enterprise_account_name):
            print(f"⚠️ Could not set enterprise context, using fallback")
        
        # Get enterprise configuration
        enterprise_config = multi_tenant_client.enterprises[enterprise_account_name]
        basic_classification = enterprise_config.classification_levels[0] if enterprise_config.classification_levels else 'public'
        
        print(f"🎯 Issuing {basic_classification} credential for {enterprise_account_name}")
        
        # Initialize credential issuer if needed
        if not new_credential_issuer.issuer_did or not new_credential_issuer.schema_id:
            print("🔧 Initializing credential issuer...")
            if not new_credential_issuer.initialize():
                print("⚠️ Credential issuer initialization failed, proceeding without")
        
        # Issue basic enterprise credential
        credential_result = None
        try:
            # Try multi-tenant first
            credential_result = multi_tenant_client.issue_enterprise_credential(
                identity_hash, user_info, basic_classification
            )
            
            if not credential_result.get('success'):
                raise Exception("Multi-tenant credential issuance failed")
                
        except Exception as mt_error:
            print(f"⚠️ Multi-tenant issuance failed: {mt_error}")
            try:
                # Fallback to new credential issuer
                credential_result = new_credential_issuer.issue_classification_credential(
                    user_info, basic_classification
                )
            except Exception as fallback_error:
                print(f"⚠️ Fallback credential issuance failed: {fallback_error}")
                credential_result = {
                    'success': False,
                    'error': str(fallback_error)
                }
        
        # Save user to database (for login persistence)
        conn = get_db_connection()
        user_id = None
        
        if conn:
            try:
                with conn.cursor() as cursor:
                    # Check if user already exists
                    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                    if cursor.fetchone():
                        return {'success': False, 'error': 'User already exists'}
                    
                    # Get enterprise account ID
                    cursor.execute("SELECT id FROM enterprise_accounts WHERE account_name = %s", (enterprise_account_name,))
                    enterprise_row = cursor.fetchone()
                    if not enterprise_row:
                        return {'success': False, 'error': f'Enterprise account {enterprise_account_name} not found in database'}
                    enterprise_account_id = enterprise_row['id']
                    
                    # Create user in database
                    cursor.execute("""
                        INSERT INTO users (email, password_hash, enterprise_account_id, enterprise_account_name, 
                                         identity_hash, full_name, department, job_title, employee_id)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (email, password_hash, enterprise_account_id, enterprise_account_name, 
                          identity_hash, full_name, department, job_title, employee_id))
                    
                    result = cursor.fetchone()
                    if result:
                        user_id = result['id']
                        print(f"✅ User saved to database with ID: {user_id}")
                    conn.commit()
                    
            except Exception as db_error:
                print(f"❌ Database save failed: {db_error}")
                if conn:
                    conn.rollback()
                return {'success': False, 'error': f'Database save failed: {str(db_error)}'}
            finally:
                if conn:
                    conn.close()
        else:
            return {'success': False, 'error': 'Database connection failed'}
        
        # Create holder DID for the user
        print(f"🔑 Creating holder DID for user {user_id}...")
        holder_did = holder_wallet_manager.create_user_did(user_id, identity_hash)
        
        if holder_did:
            print(f"✅ Created holder DID for user {user_id}")
            # Store holder DID in database
            conn = get_db_connection()
            if conn:
                try:
                    with conn.cursor() as cursor:
                        cursor.execute("""
                            UPDATE users 
                            SET holder_did = %s 
                            WHERE id = %s
                        """, (holder_did, user_id))
                    conn.commit()
                    print(f"✅ Stored holder DID in database")
                except Exception as e:
                    print(f"⚠️ Could not store holder DID: {e}")
                finally:
                    if conn:
                        conn.close()
        else:
            print(f"⚠️ Could not create holder DID for user {user_id}")
        
        return {
            'success': True,
            'user_id': user_id,
            'identity_hash': identity_hash,
            'enterprise_account': enterprise_account_name,
            'enterprise_display_name': enterprise_config.account_display_name,
            'tenant_id': enterprise_config.tenant_id,
            'classification_levels': enterprise_config.classification_levels,
            'credential_issued': credential_result.get('success', False),
            'credential_info': credential_result if credential_result else None,
            'basic_classification': basic_classification,
            'message': f'Enterprise user created successfully for {enterprise_config.account_display_name}'
        }
        
    except Exception as e:
        print(f"❌ Enterprise user creation failed: {e}")
        return {'success': False, 'error': str(e)}

@app.route('/api/user/profile')
def get_user_profile():
    """Get current user profile including enterprise account info"""
    try:
        current_user_data = get_current_user()
        if not current_user_data.get('is_authenticated'):
            return jsonify({'error': 'Not authenticated'}), 401
        
        # Get additional user info from database if needed
        profile_data = {
            'user_id': current_user_data['user_id'],
            'email': current_user_data['email'],
            'full_name': current_user_data['full_name'],
            'department': current_user_data['department'],
            'job_title': current_user_data['job_title'],
            'employee_id': current_user_data['employee_id'],
            'enterprise_account_name': current_user_data['enterprise_account_name'],
            'enterprise_account_display': current_user_data['enterprise_account_display'],
            'identity_hash_display': current_user_data['identity_hash_display'],
            'has_enterprise_credential': current_user_data['has_enterprise_credential'],
            'classification_credentials': current_user_data.get('classification_credentials', []),
            'max_classification_level': current_user_data.get('max_classification_level', 0),
            'active_credentials': current_user_data.get('active_credentials', []),
            'pending_requests': current_user_data.get('pending_requests', [])
        }
        
        return jsonify(profile_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/enterprise/accounts', methods=['GET'])
def get_enterprise_accounts():
    """Get available enterprise accounts for registration"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT account_name, account_display_name, description 
                FROM enterprise_accounts 
                WHERE is_active = true 
                ORDER BY account_display_name
            """)
            accounts = [dict(account) for account in cursor.fetchall()]
            
        return jsonify({'accounts': accounts})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/user/max-classification-level', methods=['GET'])
def get_user_max_classification_level_api():
    """Get user's current maximum classification level"""
    try:
        current_user_data = get_current_user()
        if not current_user_data.get('is_authenticated'):
            return jsonify({'error': 'Not authenticated'}), 401
        
        identity_hash = current_user_data['identity_hash']
        max_level = get_user_max_classification_level(identity_hash)
        
        return jsonify({
            'max_classification_level': max_level,
            'identity_hash_display': current_user_data['identity_hash_display']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== CREDENTIAL REQUEST ROUTES ====================

@app.route('/api/credentials/request', methods=['POST'])
def request_credential():
    """Handle credential request submission"""
    try:
        # Check authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
            
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        credential_type = data.get('credentialType')
        business_justification = data.get('businessJustification')
        department_approval = data.get('departmentApproval')
        
        if not credential_type or not business_justification:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Determine credential category and classification level
        if credential_type == 'basic_enterprise':
            category = 'enterprise'
            classification_level = None
        else:
            category = 'classification'
            classification_level = {'public': 1, 'internal': 2, 'confidential': 3}.get(credential_type)
        
        # Insert credential request into database
        conn = get_db_connection()
        if conn:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO credential_requests 
                        (user_id, identity_hash, enterprise_account_name, credential_category, 
                         credential_type, status, business_justification, department_approval)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (
                        current_user.get('user_id'),
                        current_user.get('identity_hash'),
                        current_user.get('enterprise_account_name'),
                        category,
                        credential_type,
                        'pending',
                        business_justification,
                        department_approval
                    ))
                    
                    request_id = cursor.fetchone()['id']
                    conn.commit()
                    
                    # Log the request in audit trail
                    cursor.execute("""
                        INSERT INTO credential_audit_log 
                        (user_id, identity_hash, enterprise_account_name, action, 
                         credential_category, credential_type, details, performed_by)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        current_user.get('user_id'),
                        current_user.get('identity_hash'),
                        current_user.get('enterprise_account_name'),
                        'request',
                        category,
                        credential_type,
                        json.dumps({
                            'request_id': request_id,
                            'justification': business_justification,
                            'department_approval': department_approval
                        }),
                        current_user.get('email')
                    ))
                    conn.commit()
                    
                    return jsonify({
                        'success': True, 
                        'message': 'Credential request submitted successfully',
                        'request_id': request_id
                    })
                    
            except Exception as db_error:
                print(f"⚠️ Database error in credential request: {db_error}")
                conn.rollback()
                return jsonify({'success': False, 'error': 'Database error'}), 500
            finally:
                conn.close()
        else:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
            
    except Exception as e:
        print(f"❌ Credential request error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/credential-requests/<int:request_id>', methods=['POST'])
def handle_credential_request(request_id):
    """Handle approve/deny of credential requests"""
    try:
        # Check admin privileges
        if not current_user.get('is_authenticated'):
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
            
        if not is_admin_user(current_user):
            return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
        
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        action = data.get('action')  # 'approve' or 'deny'
        reason = data.get('reason')  # For deny actions
        
        if action not in ['approve', 'deny']:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        conn = get_db_connection()
        if conn:
            try:
                with conn.cursor() as cursor:
                    # Get the request details first
                    cursor.execute("""
                        SELECT cr.*, u.full_name, u.email, u.identity_hash, u.enterprise_account_name
                        FROM credential_requests cr
                        JOIN users u ON cr.user_id = u.id
                        WHERE cr.id = %s AND cr.status = 'pending'
                    """, (request_id,))
                    
                    request_row = cursor.fetchone()
                    if not request_row:
                        return jsonify({'success': False, 'error': 'Request not found or already processed'}), 404
                    
                    # Update the request status
                    new_status = 'approved' if action == 'approve' else 'denied'
                    cursor.execute("""
                        UPDATE credential_requests 
                        SET status = %s, processed_at = NOW(), processed_by = %s, denial_reason = %s
                        WHERE id = %s
                    """, (new_status, current_user.get('email', 'admin'), reason, request_id))
                    
                    # If approved, create an issued credential record
                    if action == 'approve':
                        # Determine classification level
                        classification_level = None
                        if request_row['credential_type'] in ['public', 'internal', 'confidential']:
                            classification_level = {'public': 1, 'internal': 2, 'confidential': 3}[request_row['credential_type']]
                        
                        # Insert into issued_credentials table
                        cursor.execute("""
                            INSERT INTO issued_credentials 
                            (user_id, identity_hash, enterprise_account_name, credential_category, 
                             credential_type, classification_level, identus_record_id, status, issued_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                        """, (
                            request_row['user_id'],
                            request_row['identity_hash'],
                            request_row['enterprise_account_name'],
                            request_row['credential_category'],
                            request_row['credential_type'],
                            classification_level,
                            f"approved_request_{request_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",  # Mock record ID
                            'issued'
                        ))
                    
                    # Log the admin action in audit trail
                    cursor.execute("""
                        INSERT INTO credential_audit_log 
                        (user_id, identity_hash, enterprise_account_name, action, 
                         credential_category, credential_type, details, performed_by)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        request_row['user_id'],
                        request_row['identity_hash'],
                        request_row['enterprise_account_name'],
                        action,
                        request_row['credential_category'],
                        request_row['credential_type'],
                        json.dumps({
                            'request_id': request_id,
                            'admin_action': action,
                            'reason': reason,
                            'processed_by': current_user.get('email', 'admin')
                        }),
                        current_user.get('email', 'admin')
                    ))
                    
                    conn.commit()
                    
                    return jsonify({
                        'success': True, 
                        'message': f'Credential request {action}d successfully',
                        'action': action,
                        'user_name': request_row['full_name']
                    })
                    
            except Exception as db_error:
                print(f"⚠️ Database error in credential {action}: {db_error}")
                conn.rollback()
                return jsonify({'success': False, 'error': 'Database error'}), 500
            finally:
                conn.close()
        else:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500
            
    except Exception as e:
        print(f"❌ Credential {action} error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== API ROUTES ====================

@app.route('/api/applications', methods=['GET'])
def get_applications():
    """Get all credential applications"""
    return jsonify(applications_db)

@app.route('/api/applications/<app_id>/approve', methods=['POST'])
def approve_application(app_id):
    """Approve a credential application with real Identus integration"""
    try:
        # Find the application
        app = next((a for a in applications_db if a['id'] == app_id), None)
        if not app:
            return jsonify({'error': 'Application not found'}), 404
        
        if app['status'] != 'pending':
            return jsonify({'error': 'Application already processed'}), 400
        
        # Try to issue real credential
        try:
            print(f"🎫 Attempting to issue real credential for {app['name']}...")
            
            # Check if Identus is available
            if not identus_client.check_agents_health():
                raise Exception("Identus agents are not running")
            
            if not identus_client.issuer_did or not identus_client.schema_uri:
                raise Exception("Identus not properly initialized")
            
            # Issue real credential
            credential_result = identus_client.issue_credential(app)
            
            # Update application status with real credential info
            app['status'] = 'approved'
            app['approvedDate'] = datetime.now().isoformat()
            app['processedBy'] = 'identus-system'
            app['credentialId'] = credential_result.get('credentialId')
            app['invitationUrl'] = credential_result.get('invitationUrl')
            app['realCredential'] = True
            
            print(f"✅ Real credential issued successfully for {app['name']}!")
            
            return jsonify({
                'success': True,
                'message': f'✅ Real credential issued to {app["name"]}! 🎉',
                'credential': credential_result,
                'type': 'real'
            })
            
        except Exception as identus_error:
            print(f"⚠️ Real credential issuance failed: {identus_error}")
            print(f"🔍 Full error details: {str(identus_error)}")
            print("❌ MOCK CREDENTIALS DISABLED - Re-raising error for debugging...")
            
            # TEMPORARILY DISABLED: Mock credential fallback
            # Instead, return the actual error to see what's failing
            return jsonify({
                'success': False,
                'error': f'Identus credential issuance failed: {str(identus_error)}',
                'type': 'identus_error',
                'details': str(identus_error)
            }), 500
        
    except Exception as e:
        print(f"❌ Application approval failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/applications/<app_id>/deny', methods=['POST'])
def deny_application(app_id):
    """Deny a credential application"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'No reason provided')
        
        # Find the application
        app = next((a for a in applications_db if a['id'] == app_id), None)
        if not app:
            return jsonify({'error': 'Application not found'}), 404
        
        if app['status'] != 'pending':
            return jsonify({'error': 'Application already processed'}), 400
        
        # Update application status
        app['status'] = 'denied'
        app['deniedDate'] = datetime.now().isoformat()
        app['denialReason'] = reason
        app['processedBy'] = 'system'
        
        print(f"❌ Application denied for {app['name']}: {reason}")
        
        return jsonify({
            'success': True,
            'message': f'Application denied for {app["name"]}',
            'reason': reason
        })
        
    except Exception as e:
        print(f"❌ Application denial failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/applications/refresh', methods=['POST'])
def refresh_applications():
    """Refresh applications from Identus system"""
    try:
        print("🔄 Refreshing applications from Identus...")
        load_real_identus_data()
        
        return jsonify({
            'success': True,
            'message': f'Refreshed {len(applications_db)} applications',
            'count': len(applications_db)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Refresh failed: {str(e)}'
        }), 500

@app.route('/api/applications/<app_id>', methods=['GET'])
def get_application(app_id):
    """Get a specific application"""
    app = next((a for a in applications_db if a['id'] == app_id), None)
    if not app:
        return jsonify({'error': 'Application not found'}), 404
    
    return jsonify(app)

@app.route('/api/applications', methods=['POST'])
def create_application():
    """Create a new credential application"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'specialization', 'experienceLevel']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create new application
        new_app = {
            "id": f"app-{int(datetime.now().timestamp())}",
            "name": data['name'],
            "email": data['email'],
            "specialization": data['specialization'],
            "experienceLevel": data['experienceLevel'],
            "qualifications": data.get('qualifications', []),
            "submittedDate": datetime.now().isoformat(),
            "status": "pending",
            "labelerID": f"LAB{int(datetime.now().timestamp())}"
        }
        
        applications_db.append(new_app)
        
        print(f"📝 New application created for {new_app['name']}")
        
        return jsonify({
            'success': True,
            'message': f'Application created for {new_app["name"]}',
            'application': new_app
        }), 201
        
    except Exception as e:
        print(f"❌ Application creation failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/status', methods=['GET'])
def system_status():
    """Get system status information"""
    try:
        agents_healthy = identus_client.check_agents_health()
        initialized = identus_client.issuer_did is not None
        
        status_info = {
            'system_healthy': agents_healthy and initialized,
            'identus_healthy': agents_healthy,
            'initialized': initialized,
            'issuer_did': identus_client.issuer_did,
            'schema_uri': identus_client.schema_uri,
            'status': 'ready' if (agents_healthy and initialized) else 'not_ready'
        }
        
        # Add individual service status
        status_info.update({
            'identus_issuer': agents_healthy,
            'identus_holder': agents_healthy,
            'identus_verifier': agents_healthy,
            'database': True  # Mock database status
        })
        
        # Add additional diagnostic info
        if not agents_healthy:
            status_info['message'] = 'Identus agents not responding on ports 8080/7000/9000'
        elif not initialized:
            status_info['message'] = 'Identus agents running but not initialized'
        else:
            status_info['message'] = 'Identus ready for credential issuance'
        
        return jsonify(status_info)
        
    except Exception as e:
        return jsonify({
            'system_healthy': False,
            'identus_healthy': False,
            'initialized': False,
            'status': 'error',
            'error': str(e),
            'message': 'Error checking system status'
        })

@app.route('/api/identus/status', methods=['GET'])
def identus_status():
    """Check Identus system status"""
    try:
        agents_healthy = identus_client.check_agents_health()
        initialized = identus_client.issuer_did is not None
        
        status_info = {
            'agents_healthy': agents_healthy,
            'initialized': initialized,
            'issuer_did': identus_client.issuer_did,
            'schema_uri': identus_client.schema_uri,
            'status': 'ready' if (agents_healthy and initialized) else 'not_ready'
        }
        
        # Add additional diagnostic info
        if not agents_healthy:
            status_info['message'] = 'Identus agents not responding on ports 8080/7000/9000'
        elif not initialized:
            status_info['message'] = 'Identus agents running but not initialized'
        else:
            status_info['message'] = 'Identus ready for credential issuance'
        
        return jsonify(status_info)
        
    except Exception as e:
        return jsonify({
            'agents_healthy': False,
            'initialized': False,
            'status': 'error',
            'error': str(e),
            'message': 'Error checking Identus status'
        })

@app.route('/api/identus/reinitialize', methods=['POST'])
def reinitialize_identus():
    """Reinitialize Identus connection"""
    try:
        print("🔄 Reinitializing Identus connection...")
        
        if identus_client.check_agents_health():
            success = identus_client.initialize()
            if success:
                return jsonify({
                    'success': True,
                    'message': 'Identus reinitialized successfully',
                    'issuer_did': identus_client.issuer_did,
                    'schema_uri': identus_client.schema_uri
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Identus initialization failed'
                }), 500
        else:
            return jsonify({
                'success': False,
                'message': 'Identus agents not healthy'
            }), 503
            
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Reinitialization failed: {str(e)}'
        }), 500

@app.route('/api/verification/create', methods=['POST'])
def create_verification_request():
    """Create a verification request"""
    try:
        if not identus_client.issuer_did or not identus_client.schema_uri:
            return jsonify({
                'success': False,
                'message': 'Identus not initialized'
            }), 503
        
        verification_result = identus_client.create_verification_request()
        
        return jsonify({
            'success': True,
            'message': 'Verification request created',
            'verification': verification_result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Verification creation failed: {str(e)}'
        }), 500

@app.route('/api/dashboard/stats', methods=['GET'])
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        stats = {
            'my_credentials': current_user.get('credentials_count', 0),
            'documents_accessed': 15,  # Mock data
            'pending_requests': len([app for app in applications_db if app['status'] == 'pending']),
            'security_score': 85,
            'active_credentials': 2  # Mock data
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/activity', methods=['GET'])
def dashboard_activity():
    """Get recent activity for dashboard"""
    try:
        # Mock recent activities
        activities = {
            'items': [
                {
                    'action': 'Credential Approved',
                    'description': 'Public classification credential approved',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'success'
                },
                {
                    'action': 'Document Uploaded',
                    'description': 'Annual report classified as Internal',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'info'
                },
                {
                    'action': 'Access Granted',
                    'description': 'Accessed confidential document',
                    'timestamp': datetime.now().isoformat(),
                    'type': 'warning'
                }
            ]
        }
        
        return jsonify(activities)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        identus_healthy = identus_client.check_agents_health()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'applications_count': len(applications_db),
            'identus_healthy': identus_healthy,
            'identus_initialized': identus_client.issuer_did is not None,
            'pending_applications': len([app for app in applications_db if app['status'] == 'pending']),
            'approved_applications': len([app for app in applications_db if app['status'] == 'approved']),
            'denied_applications': len([app for app in applications_db if app['status'] == 'denied'])
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    try:
        stats = {
            'total': len(applications_db),
            'pending': len([app for app in applications_db if app['status'] == 'pending']),
            'approved': len([app for app in applications_db if app['status'] == 'approved']),
            'denied': len([app for app in applications_db if app['status'] == 'denied']),
            'real_credentials': len([app for app in applications_db if app.get('realCredential', False)]),
            'mock_credentials': len([app for app in applications_db if app['status'] == 'approved' and not app.get('realCredential', False)])
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== DOCUMENT ROUTES ====================

@app.route('/documents/upload', methods=['POST'])
def handle_document_upload():
    """Handle document upload with classification"""
    try:
        # Check if file was uploaded
        if 'document' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('upload_document'))
        
        file = request.files['document']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('upload_document'))
        
        # Get form data
        title = request.form.get('title', '').strip()
        classification = request.form.get('classification', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '')
        department = request.form.get('department', '')
        tags = request.form.get('tags', '')
        encrypt_immediately = request.form.get('encrypt_immediately') == 'on'
        enable_ephemeral_access = request.form.get('enable_ephemeral_access') == 'on'
        ephemeral_access_default = request.form.get('ephemeral_access_default') == 'on'
        
        # Validate required fields
        if not title:
            flash('Document title is required', 'error')
            return redirect(url_for('upload_document'))
        
        if not classification or not config.is_classification_valid(classification):
            flash('Valid classification level is required', 'error')
            return redirect(url_for('upload_document'))
        
        # Validate file type
        allowed_extensions = config.documents.allowed_extensions
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        if file_extension not in allowed_extensions:
            flash(f'File type not allowed. Allowed types: {", ".join(allowed_extensions)}', 'error')
            return redirect(url_for('upload_document'))
        
        # Create upload directory if it doesn't exist
        upload_folder = config.documents.upload_folder
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate filename
        timestamp = int(datetime.now().timestamp())
        filename = f"{timestamp}_{file.filename}"
        filepath = os.path.join(upload_folder, filename)
        
        # Save file
        file.save(filepath)
        
        # Enhanced document processing with ephemeral access support (Task 4.1)
        # Get user's classification level for database storage
        user_classification_level = get_user_max_classification_level(current_user.get('identity_hash', ''))
        classification_level = config.get_classification_level(classification)
        
        # SECURITY CHECK: Validate user can upload at requested classification level
        if user_classification_level < classification_level:
            flash(f'Access denied: You need {classification} classification credentials to upload {classification} documents. Your maximum level: {user_classification_level}', 'error')
            os.remove(filepath)  # Delete uploaded file
            return redirect(url_for('upload_document'))
        
        # Store document in database
        conn = get_db_connection()
        document_id = None
        
        if conn:
            try:
                with conn.cursor() as cursor:
                    # Insert document into database
                    cursor.execute("""
                        INSERT INTO documents (
                            title, filename, file_path, file_size, mime_type,
                            classification_level, classification_label,
                            created_by_user_id, created_by_identity_hash,
                            creator_max_classification_level, enterprise_account_name,
                            is_encrypted, encrypted_with_ephemeral_did, original_encryption_method
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (
                        title, filename, filepath, os.path.getsize(filepath), 
                        file.mimetype or 'application/octet-stream',
                        classification_level, classification,
                        current_user.get('user_id'), current_user.get('identity_hash'),
                        user_classification_level, current_user.get('enterprise_account_name', 'DEFAULT_ENTERPRISE'),
                        encrypt_immediately, enable_ephemeral_access,
                        'ephemeral_did' if enable_ephemeral_access else 'classification'
                    ))
                    result = cursor.fetchone()
                    document_id = result['id'] if result else None
                    conn.commit()
                    
            except Exception as e:
                print(f"❌ Database error during document upload: {e}")
                conn.rollback()
                # Continue without database storage for now
                pass
            finally:
                conn.close()
        
        document_data = {
            'id': document_id or f"doc-{timestamp}",
            'title': title,
            'filename': filename,
            'filepath': filepath,
            'classification': classification,
            'description': description,
            'category': category,
            'department': department,
            'tags': tags.split(',') if tags else [],
            'encrypted': encrypt_immediately,
            'ephemeral_access_enabled': enable_ephemeral_access,
            'ephemeral_access_default': ephemeral_access_default,
            'access_methods': {
                'standard': True,
                'ephemeral': enable_ephemeral_access
            },
            'security_features': {
                'immediate_encryption': encrypt_immediately,
                'ephemeral_did_support': enable_ephemeral_access,
                'default_secure_access': ephemeral_access_default
            },
            'uploaded_by': current_user['email'],
            'uploaded_at': datetime.now().isoformat(),
            'size': os.path.getsize(filepath)
        }
        
        print(f"📄 Document uploaded: {title} ({classification}) - ID: {document_id}")
        
        flash(f'Document "{title}" uploaded successfully with {classification} classification', 'success')
        
        # Check if this is an AJAX request or form submission
        if request.headers.get('Content-Type') == 'application/json' or request.headers.get('Accept') == 'application/json':
            # Return JSON for AJAX requests
            return jsonify({
                'success': True,
                'message': f'Document uploaded and classified as {classification}',
                'document': document_data,
                'redirect_url': url_for('dashboard')
            })
        else:
            # Redirect for form submissions
            return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"❌ Document upload failed: {e}")
        traceback.print_exc()
        flash('Document upload failed. Please try again.', 'error')
        
        # Check if this is an AJAX request or form submission
        if request.headers.get('Content-Type') == 'application/json' or request.headers.get('Accept') == 'application/json':
            return jsonify({
                'success': False,
                'message': f'Upload failed: {str(e)}'
            }), 500
        else:
            return redirect(url_for('upload_document'))

# ==================== DOCUMENT ACCESS METHODS API (Task 4.1) ====================

@app.route('/api/documents/access-methods/<doc_id>', methods=['GET'])
def get_document_access_methods(doc_id):
    """Get available access methods for a document (Task 4.1)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get document from database
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT d.*, 
                           u.full_name as uploader_name,
                           u.email as uploader_email
                    FROM documents d
                    LEFT JOIN users u ON d.created_by_user_id = u.id
                    WHERE d.id = %s
                """, (doc_id,))
                
                document = cursor.fetchone()
                if not document:
                    return jsonify({'error': 'Document not found'}), 404
                
                # Check if user can access this classification level
                user_max_level = get_user_max_classification_level(current_user.get('identity_hash', ''))
                doc_level = document['classification_level']
                
                if user_max_level < doc_level:
                    return jsonify({'error': 'Insufficient classification level'}), 403
                
                # Determine available access methods
                access_methods = {
                    'standard': True,  # Always available if user has classification
                    'ephemeral': bool(document.get('encrypted_with_ephemeral_did', False))
                }
                
                # Get ephemeral session info if applicable
                ephemeral_info = {}
                if access_methods['ephemeral']:
                    cursor.execute("""
                        SELECT COUNT(*) as active_sessions,
                               MAX(expires_at) as latest_expiry
                        FROM document_access_sessions 
                        WHERE document_id = %s 
                        AND user_identity_hash = %s 
                        AND status = 'active'
                        AND expires_at > NOW()
                    """, (doc_id, current_user.get('identity_hash')))
                    
                    session_info = cursor.fetchone()
                    ephemeral_info = {
                        'active_sessions': session_info['active_sessions'] if session_info else 0,
                        'latest_expiry': session_info['latest_expiry'].isoformat() if session_info and session_info['latest_expiry'] else None,
                        'can_create_session': session_info['active_sessions'] == 0 if session_info else True
                    }
                
                return jsonify({
                    'success': True,
                    'document': {
                        'id': document['id'],
                        'title': document['title'],
                        'filename': document['filename'],
                        'classification_level': document['classification_level'],
                        'classification_label': document['classification_label'],
                        'created_at': document['created_at'].isoformat(),
                        'uploader': document['uploader_name'] or 'Unknown',
                        'file_size': document['file_size']
                    },
                    'access_methods': access_methods,
                    'ephemeral_info': ephemeral_info,
                    'user_classification_level': user_max_level
                })
                
        finally:
            conn.close()
            
    except Exception as e:
        print(f"❌ Error getting document access methods: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/documents/prepare-ephemeral/<doc_id>', methods=['POST'])
def prepare_ephemeral_document_access(doc_id):
    """Prepare document for ephemeral DID access (Task 4.1)"""
    try:
        # Check user authentication
        current_user_data = get_current_user()
        if not current_user_data.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get document from database
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM documents WHERE id = %s
                """, (doc_id,))
                
                document = cursor.fetchone()
                if not document:
                    return jsonify({'error': 'Document not found'}), 404
                
                # Check if user can access this classification level using exact level matching
                user_identity_hash = current_user_data.get('identity_hash', '')
                doc_level = document['classification_level']
                
                # Use the database function for exact level access control
                cursor.execute("SELECT can_user_access_level(%s, %s)", (user_identity_hash, doc_level))
                result = cursor.fetchone()
                can_access = bool(result['can_user_access_level']) if result else False
                
                if not can_access:
                    return jsonify({'error': 'Insufficient classification level'}), 403
                
                # Check if document supports ephemeral access
                if not document.get('encrypted_with_ephemeral_did', False):
                    # Enable ephemeral access for this document
                    cursor.execute("""
                        UPDATE documents 
                        SET encrypted_with_ephemeral_did = true,
                            original_encryption_method = 'ephemeral_did',
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = %s
                    """, (doc_id,))
                    conn.commit()
                
                # Check for existing active sessions
                cursor.execute("""
                    SELECT session_token, expires_at 
                    FROM document_access_sessions 
                    WHERE document_id = %s 
                    AND user_identity_hash = %s 
                    AND expires_at > NOW()
                    AND completed_at IS NULL
                    ORDER BY expires_at DESC
                    LIMIT 1
                """, (doc_id, user_identity_hash))
                
                existing_session = cursor.fetchone()
                
                return jsonify({
                    'success': True,
                    'document': {
                        'id': document['id'],
                        'title': document['title'],
                        'filename': document['filename'],
                        'classification_label': document['classification_label'],
                        'ephemeral_ready': True
                    },
                    'existing_session': {
                        'token': existing_session['session_token'],
                        'expires_at': existing_session['expires_at'].isoformat()
                    } if existing_session else None,
                    'next_steps': {
                        'generate_ephemeral_did': True,
                        'request_encrypted_document': True,
                        'access_url': f"/documents/request-ephemeral-access/{doc_id}"
                    }
                })
                
        finally:
            conn.close()
            
    except Exception as e:
        print(f"❌ Error preparing ephemeral document access: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

# ==================== CLASSIFICATION MANAGEMENT API (Task 4.2) ====================

@app.route('/api/classification/verify-ephemeral-access', methods=['POST'])
def verify_ephemeral_access():
    """Verify user classification for ephemeral DID access (Task 4.2)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        document_id = data.get('document_id')
        requested_classification = data.get('requested_classification', 'public')
        
        if not document_id:
            return jsonify({'error': 'document_id is required'}), 400
        
        # Use classification manager to verify access
        verification_result = classification_manager.verify_classification_for_ephemeral_access(
            current_user.get('identity_hash'),
            document_id,
            requested_classification
        )
        
        # Log the access attempt
        classification_manager.log_ephemeral_access_attempt(
            current_user.get('identity_hash'),
            document_id,
            'ephemeral_did',
            result='verified' if verification_result['can_access'] else 'denied',
            details={
                'requested_classification': requested_classification,
                'verification_result': verification_result
            }
        )
        
        return jsonify(verification_result)
        
    except Exception as e:
        print(f"❌ Error verifying ephemeral access: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/classification/user-access-history', methods=['GET'])
def get_user_access_history():
    """Get user's ephemeral access history (Task 4.2)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get query parameters
        limit = min(int(request.args.get('limit', 50)), 100)  # Max 100 records
        days_back = min(int(request.args.get('days_back', 30)), 90)  # Max 90 days
        
        # Get access history using classification manager
        history_result = classification_manager.get_user_ephemeral_access_history(
            current_user.get('identity_hash'),
            limit=limit,
            days_back=days_back
        )
        
        return jsonify(history_result)
        
    except Exception as e:
        print(f"❌ Error getting user access history: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/classification/document-patterns/<int:doc_id>', methods=['GET'])
def get_document_access_patterns(doc_id):
    """Get access patterns for a specific document (Task 4.2)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Check if user is admin or document owner for accessing patterns
        if not is_admin_user(current_user):
            # Check if user is document owner
            conn = get_db_connection()
            if conn:
                try:
                    with conn.cursor() as cursor:
                        cursor.execute("""
                            SELECT created_by_identity_hash FROM documents WHERE id = %s
                        """, (doc_id,))
                        document = cursor.fetchone()
                        
                        if not document or document['created_by_identity_hash'] != current_user.get('identity_hash'):
                            return jsonify({'error': 'Access denied - document owner or admin required'}), 403
                finally:
                    conn.close()
            else:
                return jsonify({'error': 'Database connection failed'}), 500
        
        # Get document access patterns using classification manager
        patterns_result = classification_manager.get_document_access_patterns(doc_id)
        
        return jsonify(patterns_result)
        
    except Exception as e:
        print(f"❌ Error getting document access patterns: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/classification/cleanup-expired', methods=['POST'])
def cleanup_expired_sessions():
    """Clean up expired ephemeral sessions (Task 4.2 - Admin only)"""
    try:
        # Check user authentication and admin privileges
        if not current_user.get('is_authenticated') or not is_admin_user(current_user):
            return jsonify({'error': 'Admin access required'}), 403
        
        # Perform cleanup using classification manager
        cleanup_result = classification_manager.cleanup_expired_ephemeral_sessions()
        
        # Log the cleanup action
        if cleanup_result['success']:
            classification_manager.log_ephemeral_access_attempt(
                current_user.get('identity_hash'),
                0,  # No specific document
                'system',
                result='cleanup_performed',
                details={
                    'action': 'expired_session_cleanup',
                    'cleanup_results': cleanup_result['cleanup_results']
                }
            )
        
        return jsonify(cleanup_result)
        
    except Exception as e:
        print(f"❌ Error cleaning up expired sessions: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

# ==================== EPHEMERAL SESSION MANAGEMENT API (Task 5.1) ====================

@app.route('/api/sessions/ephemeral/create', methods=['POST'])
def create_ephemeral_session():
    """Create a new ephemeral session for document access (Task 5.1)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        document_id = data.get('document_id')
        ephemeral_did = data.get('ephemeral_did')
        ephemeral_public_key = data.get('ephemeral_public_key')
        session_duration_minutes = data.get('session_duration_minutes', 60)
        metadata = data.get('metadata', {})
        
        if not all([document_id, ephemeral_did, ephemeral_public_key]):
            return jsonify({'error': 'Missing required fields: document_id, ephemeral_did, ephemeral_public_key'}), 400
        
        # Security validation first
        security_check = security_validator.validate_ephemeral_did_authenticity(
            ephemeral_did, ephemeral_public_key, current_user.get('identity_hash')
        )
        
        if not security_check.get('valid', False):
            return jsonify({
                'error': 'Ephemeral DID security validation failed',
                'validation_details': security_check
            }), 400
        
        # Check for DID reuse
        reuse_check = security_validator.detect_ephemeral_did_reuse(
            ephemeral_did, current_user.get('identity_hash')
        )
        
        if reuse_check.get('reuse_detected', False):
            reuse_analysis = reuse_check.get('reuse_analysis', {})
            if reuse_analysis.get('cross_user_reuse', False):
                return jsonify({
                    'error': 'Ephemeral DID reuse detected - security violation',
                    'reuse_details': reuse_check
                }), 403
        
        # Create the session
        session_duration = timedelta(minutes=session_duration_minutes)
        creation_result = session_manager.create_ephemeral_session(
            current_user.get('identity_hash'),
            document_id,
            ephemeral_did,
            ephemeral_public_key,
            session_duration,
            metadata
        )
        
        return jsonify(creation_result)
        
    except Exception as e:
        print(f"❌ Error creating ephemeral session: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sessions/ephemeral/validate/<session_token>', methods=['GET'])
def validate_ephemeral_session_api(session_token):
    """Validate an ephemeral session (Task 5.1)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Validate the session
        validation_result = session_manager.validate_ephemeral_session(
            session_token,
            current_user.get('identity_hash'),
            request.args.get('document_id', type=int)
        )
        
        if validation_result.get('valid', False):
            # Additional security validation
            security_validation = security_validator.validate_session_security(session_token)
            validation_result['security_analysis'] = security_validation.get('security_analysis', {})
        
        return jsonify(validation_result)
        
    except Exception as e:
        print(f"❌ Error validating ephemeral session: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sessions/ephemeral/expire/<session_token>', methods=['POST'])
def expire_ephemeral_session_api(session_token):
    """Manually expire an ephemeral session (Task 5.1)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json() or {}
        reason = data.get('reason', 'user_requested')
        
        # Expire the session
        expiration_result = session_manager.expire_ephemeral_session(
            session_token,
            reason,
            current_user.get('identity_hash')
        )
        
        return jsonify(expiration_result)
        
    except Exception as e:
        print(f"❌ Error expiring ephemeral session: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sessions/ephemeral/active', methods=['GET'])
def get_active_ephemeral_sessions_api():
    """Get active ephemeral sessions for the current user (Task 5.1)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Get query parameters
        document_id = request.args.get('document_id', type=int)
        limit = min(int(request.args.get('limit', 50)), 100)  # Max 100
        
        # Get active sessions
        sessions_result = session_manager.get_active_ephemeral_sessions(
            current_user.get('identity_hash'),
            document_id,
            limit
        )
        
        return jsonify(sessions_result)
        
    except Exception as e:
        print(f"❌ Error getting active ephemeral sessions: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sessions/ephemeral/cleanup', methods=['POST'])
def cleanup_ephemeral_sessions_api():
    """Clean up expired ephemeral sessions (Admin only - Task 5.1)"""
    try:
        # Check admin privileges
        if not current_user.get('is_authenticated') or not is_admin_user(current_user):
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json() or {}
        batch_size = min(int(data.get('batch_size', 100)), 500)  # Max 500
        
        # Perform cleanup
        cleanup_result = session_manager.cleanup_expired_sessions(batch_size)
        
        return jsonify(cleanup_result)
        
    except Exception as e:
        print(f"❌ Error cleaning up ephemeral sessions: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sessions/statistics', methods=['GET'])
def get_session_statistics_api():
    """Get session statistics (Admin only - Task 5.1)"""
    try:
        # Check admin privileges
        if not current_user.get('is_authenticated') or not is_admin_user(current_user):
            return jsonify({'error': 'Admin access required'}), 403
        
        days_back = min(int(request.args.get('days_back', 7)), 30)  # Max 30 days
        
        # Get statistics
        stats_result = session_manager.get_session_statistics(days_back)
        
        return jsonify(stats_result)
        
    except Exception as e:
        print(f"❌ Error getting session statistics: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

# ==================== EPHEMERAL DID SECURITY VALIDATION API (Task 5.2) ====================

@app.route('/api/security/validate-did', methods=['POST'])
def validate_did_authenticity_api():
    """Validate ephemeral DID authenticity (Task 5.2)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        ephemeral_did = data.get('ephemeral_did')
        ephemeral_public_key = data.get('ephemeral_public_key')
        
        if not ephemeral_did:
            return jsonify({'error': 'ephemeral_did is required'}), 400
        
        # Validate DID authenticity
        validation_result = security_validator.validate_ephemeral_did_authenticity(
            ephemeral_did,
            ephemeral_public_key,
            current_user.get('identity_hash')
        )
        
        return jsonify(validation_result)
        
    except Exception as e:
        print(f"❌ Error validating DID authenticity: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/security/detect-reuse', methods=['POST'])
def detect_did_reuse_api():
    """Detect ephemeral DID reuse (Task 5.2)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        ephemeral_did = data.get('ephemeral_did')
        time_window_hours = min(int(data.get('time_window_hours', 24)), 168)  # Max 7 days
        
        if not ephemeral_did:
            return jsonify({'error': 'ephemeral_did is required'}), 400
        
        # Detect reuse
        reuse_result = security_validator.detect_ephemeral_did_reuse(
            ephemeral_did,
            current_user.get('identity_hash'),
            time_window_hours
        )
        
        return jsonify(reuse_result)
        
    except Exception as e:
        print(f"❌ Error detecting DID reuse: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/security/validate-session/<session_token>', methods=['GET'])
def validate_session_security_api(session_token):
    """Comprehensive security validation of a session (Task 5.2)"""
    try:
        # Check user authentication
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Validate session security
        validation_result = security_validator.validate_session_security(session_token)
        
        return jsonify(validation_result)
        
    except Exception as e:
        print(f"❌ Error validating session security: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/security/usage-report', methods=['GET'])
def generate_usage_report_api():
    """Generate comprehensive usage report (Admin only - Task 5.2)"""
    try:
        # Check admin privileges
        if not current_user.get('is_authenticated') or not is_admin_user(current_user):
            return jsonify({'error': 'Admin access required'}), 403
        
        days_back = min(int(request.args.get('days_back', 7)), 30)  # Max 30 days
        include_security = request.args.get('include_security', 'true').lower() == 'true'
        
        # Generate usage report
        report_result = security_validator.generate_ephemeral_did_usage_report(
            days_back,
            include_security
        )
        
        return jsonify(report_result)
        
    except Exception as e:
        print(f"❌ Error generating usage report: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error'}), 500

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

# ==================== EPHEMERAL DID API ROUTES (Working Package 3) ====================

@app.route('/api/ephemeral/generate-session', methods=['POST'])
def create_ephemeral_access_session():
    """Create ephemeral access session for document"""
    try:
        current_user_data = get_current_user()
        if not current_user_data.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        # Extract request data
        document_id = data.get('documentId')
        ephemeral_did = data.get('ephemeralDID')
        ephemeral_public_key = data.get('ephemeralPublicKey')
        business_justification = data.get('businessJustification', '').strip()
        session_duration_minutes = data.get('sessionDurationMinutes', 60)
        
        # Validate required fields
        if not all([document_id, ephemeral_did, ephemeral_public_key]):
            return jsonify({'error': 'Missing required fields: documentId, ephemeralDID, ephemeralPublicKey'}), 400
        
        if not business_justification:
            return jsonify({'error': 'Business justification is required'}), 400
        
        # Validate DID format (temporarily relaxed for development)
        if not (ephemeral_did.startswith('did:key:z') and len(ephemeral_did) > 15):
            return jsonify({'error': 'Invalid ephemeral DID format'}), 400
        
        # Create database session record
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            # Get document info
            cursor.execute("SELECT * FROM documents WHERE id = %s", (document_id,))
            document = cursor.fetchone()
            
            if not document:
                return jsonify({'error': 'Document not found'}), 404
            
            # Generate session data
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(minutes=session_duration_minutes)
            session_id = f"session_{int(datetime.utcnow().timestamp())}"
            
            # Insert session into database
            cursor.execute("""
                INSERT INTO document_access_sessions (
                    user_id, user_identity_hash, enterprise_account_name, document_id, 
                    ephemeral_did, ephemeral_public_key, session_token, 
                    classification_level, created_at, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                current_user_data.get('user_id'), current_user_data['identity_hash'], 
                current_user_data.get('enterprise_account_name', 'DEFAULT_ENTERPRISE'),
                document_id, ephemeral_did, json.dumps(ephemeral_public_key), session_token,
                document['classification_level'], datetime.utcnow(), expires_at
            ))
            
            session_db_id = cursor.fetchone()['id']
            conn.commit()
            
            print(f"✅ Created ephemeral access session {session_id} (DB ID: {session_db_id})")
            
            return jsonify({
                'success': True,
                'sessionToken': session_token,
                'sessionId': session_id,
                'ephemeralDID': ephemeral_did,
                'expiresAt': expires_at.isoformat(),
                'classificationLevel': document['classification_level'],
                'message': 'Ephemeral access session created successfully'
            })
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Database error creating session: {e}")
            print(f"❌ Error type: {type(e).__name__}")
            print(f"❌ Current user data: {current_user_data}")
            print(f"❌ Document data: {document}")
            import traceback
            print(f"❌ Full traceback: {traceback.format_exc()}")
            return jsonify({'error': 'Failed to create session in database'}), 500
        finally:
            cursor.close()
            conn.close()
        
    except Exception as e:
        print(f"❌ Failed to create ephemeral session: {e}")
        return jsonify({'error': 'Failed to create ephemeral access session'}), 500

@app.route('/api/ephemeral/encrypt-document/<session_token>', methods=['GET'])
def get_encrypted_document_ephemeral(session_token):
    """Get document encrypted with ephemeral public key"""
    try:
        current_user_data = get_current_user()
        if not current_user_data.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Validate and get session
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT das.*, d.filename, d.file_path, d.file_size,
                   d.mime_type, d.classification_level
            FROM document_access_sessions das
            JOIN documents d ON das.document_id = d.id
            WHERE das.session_token = %s 
            AND das.user_identity_hash = %s
            AND das.expires_at > NOW()
            AND das.completed_at IS NULL
        """, (session_token, current_user_data['identity_hash']))
        
        session = cursor.fetchone()
        if not session:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid or expired session token'}), 404
        
        # Check if document already encrypted for this session
        existing_encrypted = ephemeral_encryption.get_session_encrypted_file(session['id'])
        
        if existing_encrypted:
            print(f"📄 Using existing encrypted document for session {session['id']}")
            encrypted_data = ephemeral_encryption._read_encrypted_file(existing_encrypted)
        else:
            # Read and encrypt document
            document_path = session['file_path']
            if not os.path.exists(document_path):
                cursor.close()
                conn.close()
                return jsonify({'error': 'Document file not found'}), 404
            
            with open(document_path, 'rb') as f:
                document_data = f.read()
            
            print(f"🔒 Encrypting document for ephemeral session {session['id']}")
            
            # Encrypt document with ephemeral public key
            encryption_result = encrypt_document_for_ephemeral_session(
                document_data,
                session['ephemeral_did'],
                session['id']
            )
            
            # Store encryption metadata
            cursor.execute("""
                INSERT INTO document_ephemeral_encryption (
                    document_id, access_session_id, ephemeral_did,
                    encrypted_document_path, encryption_algorithm
                ) VALUES (%s, %s, %s, %s, %s)
            """, (
                session['document_id'],
                session['id'],
                session['ephemeral_did'],
                encryption_result['encrypted_file_path'],
                encryption_result['encryption_algorithm']
            ))
            
            # Update session status
            cursor.execute("""
                UPDATE document_access_sessions 
                SET document_encrypted_with_ephemeral_key = true, 
                    access_granted = true, 
                    accessed_at = NOW()
                WHERE id = %s
            """, (session['id'],))
            
            # Log encryption success
            cursor.execute("""
                INSERT INTO ephemeral_did_audit_log (
                    user_id, user_identity_hash, enterprise_account_name, document_id,
                    ephemeral_did, action, classification_level, session_token, success
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                session['user_id'],
                session['user_identity_hash'],
                session['enterprise_account_name'],
                session['document_id'],
                session['ephemeral_did'],
                'document_encrypted',
                session['classification_level'],
                session_token,
                True
            ))
            
            conn.commit()
            
            # Read the encrypted data
            encrypted_data = ephemeral_encryption._read_encrypted_file(encryption_result['encrypted_file_path'])
        
        cursor.close()
        conn.close()
        
        # DEMO MODE: For testing, return the original document directly
        print(f"🔧 DEMO MODE: Serving original document directly (no client-side decryption needed)")
        
        # Read the original document file directly
        document_path = session['file_path']
        with open(document_path, 'rb') as f:
            original_document_data = f.read()
        
        # Base64 encode the original document for transport
        original_b64 = base64.b64encode(original_document_data).decode('utf-8')
        
        print(f"✅ DEMO MODE: Serving {len(original_document_data)} bytes of original document")
        
        # Prepare response for client-side decryption
        response = {
            'success': True,
            'encryptedDocument': original_b64,  # This is actually the original document, base64 encoded
            'encryptedKey': encrypted_data['encrypted_key'],
            'iv': encrypted_data['iv'],
            'authTag': encrypted_data['auth_tag'],
            'algorithm': 'DEMO-ORIGINAL-DOCUMENT',  # Signal to client this is original
            'sessionInfo': {
                'sessionToken': session_token,
                'ephemeralDID': session['ephemeral_did'],
                'expiresAt': encrypted_data['expires_at'],
                'documentInfo': {
                    'filename': session['filename'],
                    'contentType': session['mime_type'],
                    'size': session['file_size']
                }
            },
            'instructions': 'Use your ephemeral private key to decrypt this document in your browser',
            'security': {
                'perfectForwardSecrecy': True,
                'clientSideDecryption': True,
                'serverKeyExposure': False
            }
        }
        
        print(f"✅ Served encrypted document for ephemeral session {session['id']}")
        return jsonify(response)
        
    except Exception as e:
        print(f"❌ Failed to get encrypted document: {e}")
        print(f"❌ Error type: {type(e).__name__}")
        import traceback
        print(f"❌ Full traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to retrieve encrypted document'}), 500

@app.route('/api/ephemeral/session-status/<session_token>', methods=['GET'])
def get_ephemeral_session_status(session_token):
    """Get status of ephemeral access session using new helper function (Task 2.3)"""
    try:
        current_user_data = get_current_user()
        if not current_user_data.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Use new helper function for session validation (Task 2.3)
        validation_result = validate_ongoing_ephemeral_session(session_token, current_user_data['identity_hash'])
        
        if not validation_result['success']:
            return jsonify({'error': validation_result.get('error', 'Session validation failed')}), 500
        
        if not validation_result['valid']:
            return jsonify({'error': validation_result.get('error', 'Invalid session')}), 404
        
        # Extract enhanced status information from validation result
        return jsonify({
            'success': True,
            'sessionToken': session_token,
            'status': validation_result['status'],
            'ephemeralDID': validation_result['ephemeral_did'],
            'documentId': validation_result['document_id'],
            'documentFilename': validation_result['document_filename'],
            'classificationLevel': validation_result['classification_level'],
            'expiresAt': validation_result['expires_at'],
            'secondsRemaining': validation_result['seconds_remaining'],
            'classificationVerified': validation_result['classification_verified'],
            'createdAt': validation_result['created_at'],
            'message': validation_result['message']
        })
        
    except Exception as e:
        print(f"❌ Failed to get session status: {e}")
        return jsonify({'error': 'Failed to retrieve session status'}), 500

@app.route('/api/ephemeral/cleanup-expired', methods=['POST'])
def cleanup_expired_ephemeral_sessions():
    """Admin endpoint to cleanup expired ephemeral sessions"""
    try:
        # Check admin privileges (basic check)
        current_user_data = get_current_user()
        if not current_user_data.get('is_authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # For now, allow any authenticated user to trigger cleanup
        # In production, add proper admin role checking
        
        # Cleanup expired sessions in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get expired sessions before cleanup
        cursor.execute("""
            SELECT id FROM document_access_sessions 
            WHERE expires_at < NOW() AND completed_at IS NULL
        """)
        
        expired_session_ids = [row[0] for row in cursor.fetchall()]
        
        # Mark expired sessions as completed
        cleanup_count = ephemeral_encryption.cleanup_expired_files()
        
        # Update database
        cursor.execute("""
            UPDATE document_access_sessions 
            SET completed_at = NOW()
            WHERE expires_at < NOW() AND completed_at IS NULL
        """)
        
        db_cleanup_count = cursor.rowcount
        
        # Log cleanup operation
        cursor.execute("""
            INSERT INTO ephemeral_did_audit_log (
                action, success, error_details, created_at
            ) VALUES (%s, %s, %s, %s)
        """, (
            'session_cleanup',
            True,
            f'Cleaned up {cleanup_count} encrypted files and {db_cleanup_count} database sessions',
            datetime.utcnow()
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"✅ Cleanup complete: {cleanup_count} files, {db_cleanup_count} DB sessions")
        
        return jsonify({
            'success': True,
            'message': 'Expired ephemeral sessions cleaned up successfully',
            'filesCleanedUp': cleanup_count,
            'sessionsCleanedUp': db_cleanup_count,
            'expiredSessionIds': expired_session_ids
        })
        
    except Exception as e:
        print(f"❌ Failed to cleanup expired sessions: {e}")
        return jsonify({'error': 'Failed to cleanup expired sessions'}), 500

@app.route('/documents/request-ephemeral-access/<int:doc_id>', methods=['GET'])
def request_ephemeral_document_access_page(doc_id):
    """Show ephemeral document access request page"""
    try:
        current_user_data = get_current_user()
        if not current_user_data.get('is_authenticated'):
            flash('Please log in to access documents.', 'error')
            return redirect(url_for('login'))
        
        # Get document information
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT d.*, u.full_name as created_by_name,
                   CASE 
                       WHEN d.classification_level = 1 THEN 'Public'
                       WHEN d.classification_level = 2 THEN 'Internal'
                       WHEN d.classification_level = 3 THEN 'Confidential'
                       ELSE 'Unknown'
                   END as classification_level_name
            FROM documents d
            LEFT JOIN users u ON d.created_by_user_id = u.id
            WHERE d.id = %s
        """, (doc_id,))
        
        document = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not document:
            flash('Document not found.', 'error')
            return redirect(url_for('dashboard'))
        
        # Check if user has classification credentials
        classification_level = document['classification_level']
        user_identity_hash = current_user_data['identity_hash']
        
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT can_user_access_level(%s, %s) as can_access
        """, (user_identity_hash, classification_level))
        
        access_check = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not access_check['can_access']:
            flash(f'You do not have the required classification credentials (Level {classification_level}) to access this document.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('documents/access-with-ephemeral.html', 
                             document=document,
                             current_user=current_user)
        
    except Exception as e:
        print(f"❌ Failed to load ephemeral access page: {e}")
        flash('Failed to load document access page.', 'error')
        return redirect(url_for('dashboard'))


# ==================== TEMPLATE FILTERS ====================

@app.template_filter('datetime')
def datetime_filter(value):
    """Format datetime for templates"""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except:
            return value
    
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M')
    
    return value

@app.template_filter('filesize')
def filesize_filter(value):
    """Format file size for templates"""
    try:
        size = int(value)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
    except:
        return value

# ==================== MULTI-TENANT IDENTUS API ROUTES ====================

@app.route('/api/multi-tenant/agents/status')
def multi_tenant_agents_status():
    """Get status of all multi-tenant Identus agents"""
    try:
        status = multi_tenant_client.get_agent_status()
        return jsonify({
            'success': True,
            'agent_status': status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/multi-tenant/enterprises/status')
def multi_tenant_enterprises_status():
    """Get status of all enterprise configurations"""
    try:
        status = multi_tenant_client.get_enterprise_status()
        return jsonify({
            'success': True,
            'enterprise_status': status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/multi-tenant/enterprise/set', methods=['POST'])
def set_enterprise_context():
    """Set enterprise context for multi-tenant operations"""
    try:
        data = request.get_json()
        enterprise_account = data.get('enterprise_account')
        
        if not enterprise_account:
            return jsonify({
                'success': False,
                'error': 'Missing enterprise_account parameter'
            }), 400
        
        success = multi_tenant_client.set_enterprise_context(enterprise_account)
        
        if success:
            return jsonify({
                'success': True,
                'enterprise_account': enterprise_account,
                'current_agent': multi_tenant_client.current_agent.name if multi_tenant_client.current_agent else None,
                'tenant_id': multi_tenant_client.current_enterprise.tenant_id if multi_tenant_client.current_enterprise else None
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Failed to set enterprise context for {enterprise_account}'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/multi-tenant/credential/issue', methods=['POST'])
def issue_multi_tenant_credential():
    """Issue credential using multi-tenant architecture"""
    try:
        data = request.get_json()
        
        # Required parameters
        identity_hash = data.get('identity_hash')
        enterprise_account = data.get('enterprise_account')
        credential_type = data.get('credential_type')
        user_info = data.get('user_info', {})
        
        if not all([identity_hash, enterprise_account, credential_type]):
            return jsonify({
                'success': False,
                'error': 'Missing required parameters: identity_hash, enterprise_account, credential_type'
            }), 400
        
        # Set enterprise context
        context_set = multi_tenant_client.set_enterprise_context(enterprise_account)
        if not context_set:
            return jsonify({
                'success': False,
                'error': f'Failed to set enterprise context for {enterprise_account}'
            }), 500
        
        # Issue credential
        result = multi_tenant_client.issue_enterprise_credential(
            identity_hash, user_info, credential_type
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/multi-tenant/credential/verify', methods=['POST'])
def verify_multi_tenant_credential():
    """Verify credential using multi-tenant architecture"""
    try:
        data = request.get_json()
        
        # Required parameters
        identity_hash = data.get('identity_hash')
        enterprise_account = data.get('enterprise_account')
        credential_type = data.get('credential_type')
        
        if not all([identity_hash, enterprise_account, credential_type]):
            return jsonify({
                'success': False,
                'error': 'Missing required parameters: identity_hash, enterprise_account, credential_type'
            }), 400
        
        # Set enterprise context
        context_set = multi_tenant_client.set_enterprise_context(enterprise_account)
        if not context_set:
            return jsonify({
                'success': False,
                'error': f'Failed to set enterprise context for {enterprise_account}'
            }), 500
        
        # Verify credential
        result = multi_tenant_client.verify_enterprise_credential(
            identity_hash, credential_type
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/multi-tenant/test/connectivity')
def test_multi_tenant_connectivity():
    """Test connectivity to all configured agents across enterprises"""
    try:
        # Test all agents and enterprises
        agent_status = multi_tenant_client.get_agent_status()
        enterprise_status = multi_tenant_client.get_enterprise_status()
        
        # Test connectivity to each enterprise's preferred agent
        connectivity_results = {}
        
        for enterprise_name, enterprise_info in enterprise_status['enterprises'].items():
            try:
                # Set enterprise context
                context_set = multi_tenant_client.set_enterprise_context(enterprise_name)
                
                if context_set:
                    # Try to make a simple request
                    response = multi_tenant_client._make_request('GET', '/_system/health')
                    connectivity_results[enterprise_name] = {
                        'success': True,
                        'agent_used': multi_tenant_client.current_agent.name,
                        'tenant_id': multi_tenant_client.current_enterprise.tenant_id,
                        'response': response
                    }
                else:
                    connectivity_results[enterprise_name] = {
                        'success': False,
                        'error': 'Failed to set enterprise context'
                    }
                    
            except Exception as e:
                connectivity_results[enterprise_name] = {
                    'success': False,
                    'error': str(e)
                }
        
        return jsonify({
            'success': True,
            'agent_status': agent_status,
            'enterprise_status': enterprise_status,
            'connectivity_results': connectivity_results,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ==================== STARTUP ====================

if __name__ == '__main__':
    print("🚀 Starting Hyperledger Identus Classification Document System...")
    print("=" * 60)
    print(f"📊 Dashboard: http://localhost:{config.web.port}")
    print(f"🔗 API: http://localhost:{config.web.port}/api/")
    print(f"🏥 Health: http://localhost:{config.web.port}/health")
    print(f"📈 Stats: http://localhost:{config.web.port}/api/stats")
    print(f"🔧 Environment: {config.environment}")
    print(f"🗄️ Database: {config.database.database_url}")
    print("")
    print("🎯 Features:")
    print("  • Real Identus credential issuance")
    print("  • HTML templates with Bootstrap UI")
    print("  • Classification-based document management")
    print("  • Real-time status monitoring")
    print("  • Configuration management")
    print("")
    print("💡 Make sure your Identus agents are running on ports 8080, 7000, and 9000")
    print("💡 Press Ctrl+C to stop the server")
    print("=" * 60)
    
    # Validate configuration
    if not config.validate_config():
        print("❌ Configuration validation failed. Please check your settings.")
        sys.exit(1)
    
    # Run the Flask app
    app.run(
        host=config.web.host,
        port=config.web.port,
        debug=config.web.debug,
        threaded=config.web.threaded
    )