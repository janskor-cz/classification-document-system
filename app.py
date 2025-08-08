#!/usr/bin/env python3
"""
Updated Flask server for Hyperledger Identus Classification Document System
Now with proper templates, config management, and enhanced functionality
"""

from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, send_from_directory
from flask_cors import CORS
import os
import json
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
from document_encryption import ephemeral_encryption, encrypt_document_for_ephemeral_session

# Initialize Flask app
app = Flask(__name__, 
           template_folder='frontend/templates',
           static_folder='frontend/static')

# Configure Flask with our config system
config = get_config()
app.config.update(get_flask_config())

# Enable CORS
CORS(app)

# Configure Flask app
app.config['SECRET_KEY'] = config.security.secret_key

# Database connection helper
def get_db_connection():
    """Get database connection using connection string from config"""
    try:
        # For development, connect to identus-postgres container
        conn = psycopg2.connect(
            host='localhost',
            port=5432,
            database='identus_db',
            user='postgres',
            password='postgres',
            cursor_factory=RealDictCursor
        )
        return conn
    except Exception as e:
        print(f"❌ Database connection error: {e}")
        return None

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
    'identity_hash': 'sample_identity_hash_john_doe_12345678',  # Generated with enterprise account as salt
    'identity_hash_display': 'sample_i...',  # First 8 chars for display
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
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check if user has exact matching classification level
        cursor.execute("""
            SELECT can_user_access_level(%s, %s) as can_access
        """, (user_identity_hash, classification_level))
        
        access_check = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if access_check and access_check['can_access']:
            return {
                'success': True,
                'can_access': True,
                'classification_level': classification_level,
                'message': f'User has valid classification credentials for level {classification_level}'
            }
        else:
            return {
                'success': True,
                'can_access': False,
                'classification_level': classification_level,
                'message': f'User lacks classification credentials for level {classification_level}'
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
            SELECT das.*, d.filename, d.classification_level, d.content_type,
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
    return dict(current_user=current_user, config=config)

# ==================== WEB ROUTES ====================

@app.route('/')
def dashboard():
    """Main dashboard page with real user data"""
    try:
        # Check if user is authenticated
        if not current_user.get('is_authenticated'):
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
        
        if conn:
            try:
                with conn.cursor() as cursor:
                    # Get user's issued credentials with all needed fields
                    cursor.execute("""
                        SELECT id, credential_category, credential_type, classification_level, 
                               identus_record_id, invitation_url, issued_at, expires_at, status
                        FROM issued_credentials 
                        WHERE user_id = %s AND status = 'issued'
                        ORDER BY issued_at DESC
                    """, (current_user.get('user_id'),))
                    
                    db_credentials = cursor.fetchall()
                    
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
                        
                        # Fetch the actual VC from Identus if available, otherwise create mock
                        vc_data = None
                        if cred.get('identus_record_id'):
                            try:
                                from identus_wrapper import IdentusDashboardClient
                                identus_client = IdentusDashboardClient()
                                vc_data = identus_client.get_verifiable_credential(cred['identus_record_id'])
                                
                                # If no real VC found, create a mock from database data
                                if vc_data is None:
                                    vc_data = identus_client.create_mock_vc_from_database(credential_display)
                                    print(f"📋 Created mock VC for {cred['identus_record_id']}")
                                else:
                                    print(f"✅ Retrieved real VC for {cred['identus_record_id']}")
                                    
                            except Exception as e:
                                print(f"⚠️ Could not fetch VC for {cred['identus_record_id']}: {e}")
                                # Fallback to creating mock VC from database data
                                try:
                                    from identus_wrapper import IdentusDashboardClient
                                    identus_client = IdentusDashboardClient()
                                    vc_data = identus_client.create_mock_vc_from_database(credential_display)
                                    print(f"📋 Created fallback mock VC due to error")
                                except Exception as mock_error:
                                    print(f"❌ Could not create mock VC: {mock_error}")
                                    vc_data = {"error": f"Could not fetch or create VC: {str(e)}"}
                        
                        # Add VC data to credential display
                        credential_display['verifiable_credential'] = vc_data
                        
                        # If we have a mock VC with expiration date, use it for display
                        if vc_data and vc_data.get('expirationDate') and not credential_display.get('expires_at'):
                            try:
                                credential_display['expires_at'] = datetime.fromisoformat(vc_data['expirationDate'].replace('Z', '+00:00'))
                            except Exception:
                                pass
                                
                        credentials.append(credential_display)
                    
                    # Get credential requests
                    cursor.execute("""
                        SELECT COUNT(*) as pending_count
                        FROM credential_requests 
                        WHERE user_id = %s AND status = 'pending'
                    """, (current_user.get('user_id'),))
                    
                    pending_result = cursor.fetchone()
                    stats['pending_requests'] = pending_result['pending_count'] if pending_result else 0
                    
                    # Get recent credential activities
                    cursor.execute("""
                        SELECT action, credential_type, details, created_at
                        FROM credential_audit_log 
                        WHERE user_id = %s 
                        ORDER BY created_at DESC 
                        LIMIT 5
                    """, (current_user.get('user_id'),))
                    
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
        
        return render_template('dashboard.html',
                             stats=stats,
                             credentials=credentials,
                             recent_activities=recent_activities)
    except Exception as e:
        print(f"❌ Dashboard error: {e}")
        traceback.print_exc()
        flash('Error loading dashboard', 'error')
        return render_template('dashboard.html', stats={}, credentials=[], recent_activities=[])

@app.route('/login')
def login():
    """Login page"""
    return render_template('login.html')

@app.route('/documents/upload')
def upload_document():
    """Document upload page"""
    return render_template('documents/upload.html')

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
            flash('Email and password are required', 'error')
            return redirect(url_for('login'))
        
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
        # Get available enterprise accounts
        conn = get_db_connection()
        enterprise_accounts = []
        if conn:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT account_name, account_display_name FROM enterprise_accounts WHERE is_active = true ORDER BY account_display_name")
                    enterprise_accounts = [dict(account) for account in cursor.fetchall()]
            except Exception as e:
                print(f"❌ Error loading enterprise accounts: {e}")
            finally:
                conn.close()
        
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
            
            # Create user account
            result = create_user_account(email, password, full_name, enterprise_account, 
                                       department, job_title, employee_id)
            
            if result['success']:
                flash(f'Account created successfully! You can now log in.', 'success')
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
    current_user['is_authenticated'] = False
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/api/user/profile')
def get_user_profile():
    """Get current user profile including enterprise account info"""
    try:
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Not authenticated'}), 401
        
        # Get additional user info from database if needed
        profile_data = {
            'user_id': current_user['user_id'],
            'email': current_user['email'],
            'full_name': current_user['full_name'],
            'department': current_user['department'],
            'job_title': current_user['job_title'],
            'employee_id': current_user['employee_id'],
            'enterprise_account_name': current_user['enterprise_account_name'],
            'enterprise_account_display': current_user['enterprise_account_display'],
            'identity_hash_display': current_user['identity_hash_display'],
            'has_enterprise_credential': current_user['has_enterprise_credential'],
            'classification_credentials': current_user['classification_credentials'],
            'max_classification_level': current_user['max_classification_level'],
            'active_credentials': current_user['active_credentials'],
            'pending_requests': current_user['pending_requests']
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
def get_user_max_classification_level():
    """Get user's current maximum classification level"""
    try:
        if not current_user.get('is_authenticated'):
            return jsonify({'error': 'Not authenticated'}), 401
        
        identity_hash = current_user['identity_hash']
        max_level = get_user_max_classification_level(identity_hash)
        
        return jsonify({
            'max_classification_level': max_level,
            'identity_hash_display': current_user['identity_hash_display']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== CREDENTIAL REQUEST ROUTES ====================

@app.route('/api/credentials/request', methods=['POST'])
def request_credential():
    """Handle credential request submission"""
    try:
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
            print("📋 Falling back to mock credential...")
            
            # Fall back to mock credential
            app['status'] = 'approved'
            app['approvedDate'] = datetime.now().isoformat()
            app['processedBy'] = 'mock-system'
            app['realCredential'] = False
            
            return jsonify({
                'success': True,
                'message': f'Mock credential issued to {app["name"]} (Identus unavailable)',
                'credential': {
                    'credentialId': f'mock-cred-{int(datetime.now().timestamp())}',
                    'invitationUrl': f'mock://credential/{app_id}',
                    'recordId': f'mock-rec-{int(datetime.now().timestamp())}'
                },
                'type': 'mock',
                'warning': 'Real Identus system unavailable - using mock credential'
            })
        
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
        
        # Mock document processing (in real implementation, this would encrypt the file)
        document_data = {
            'id': f"doc-{timestamp}",
            'title': title,
            'filename': filename,
            'filepath': filepath,
            'classification': classification,
            'description': description,
            'category': category,
            'department': department,
            'tags': tags.split(',') if tags else [],
            'encrypted': encrypt_immediately,
            'uploaded_by': current_user['email'],
            'uploaded_at': datetime.now().isoformat(),
            'size': os.path.getsize(filepath)
        }
        
        print(f"📄 Document uploaded: {title} ({classification})")
        
        flash(f'Document "{title}" uploaded successfully with {classification} classification', 'success')
        return jsonify({
            'success': True,
            'message': f'Document uploaded and classified as {classification}',
            'document': document_data,
            'redirect_url': url_for('dashboard')
        })
        
    except Exception as e:
        print(f"❌ Document upload failed: {e}")
        traceback.print_exc()
        flash('Document upload failed. Please try again.', 'error')
        return jsonify({
            'success': False,
            'message': f'Upload failed: {str(e)}'
        }), 500

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
        if not current_user.get('authenticated'):
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
        
        # Validate DID format
        if not ephemeral_encryption.validate_ephemeral_did_format(ephemeral_did):
            return jsonify({'error': 'Invalid ephemeral DID format'}), 400
        
        # Get document and verify user can access it
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT d.*, u.full_name as created_by_name
            FROM documents d
            LEFT JOIN users u ON d.created_by_user_id = u.id
            WHERE d.id = %s
        """, (document_id,))
        
        document = cursor.fetchone()
        if not document:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Document not found'}), 404
        
        # Verify user has classification credentials for this document
        classification_level = document['classification_level']
        user_identity_hash = current_user['identity_hash']
        
        # Use new helper function for classification verification (Task 2.3)
        cursor.close()
        conn.close()
        
        classification_result = verify_classification_for_ephemeral_access(user_identity_hash, classification_level)
        if not classification_result['success']:
            return jsonify({'error': classification_result.get('error', 'Classification verification failed')}), 500
        
        if not classification_result['can_access']:
            return jsonify({'error': f'Insufficient classification credentials for level {classification_level}'}), 403
        
        # Reconnect for remaining operations
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check for DID reuse
        cursor.execute("""
            SELECT check_ephemeral_did_reuse(%s, 24) as is_reused
        """, (ephemeral_did,))
        
        reuse_check = cursor.fetchone()
        if reuse_check['is_reused']:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Ephemeral DID has been used recently. Please generate a new one.'}), 400
        
        # Generate session token
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=session_duration_minutes)
        
        # Create access session
        cursor.execute("""
            INSERT INTO document_access_sessions (
                user_id, user_identity_hash, enterprise_account_name, document_id,
                ephemeral_did, ephemeral_public_key, session_token, classification_level,
                classification_verified, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            current_user['user_id'],
            user_identity_hash,
            current_user['enterprise_account_name'],
            document_id,
            ephemeral_did,
            json.dumps(ephemeral_public_key),
            session_token,
            classification_level,
            True,
            expires_at
        ))
        
        session_id = cursor.fetchone()['id']
        
        # Log session creation
        cursor.execute("""
            INSERT INTO ephemeral_did_audit_log (
                user_id, user_identity_hash, enterprise_account_name, document_id,
                ephemeral_did, action, classification_level, session_token, success
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            current_user['user_id'],
            user_identity_hash,
            current_user['enterprise_account_name'],
            document_id,
            ephemeral_did,
            'access_requested',
            classification_level,
            session_token,
            True
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"✅ Created ephemeral access session {session_id} for user {current_user['full_name']}")
        
        return jsonify({
            'success': True,
            'sessionToken': session_token,
            'sessionId': session_id,
            'ephemeralDID': ephemeral_did,
            'expiresAt': expires_at.isoformat(),
            'classificationLevel': classification_level,
            'message': 'Ephemeral access session created successfully'
        })
        
    except Exception as e:
        print(f"❌ Failed to create ephemeral session: {e}")
        return jsonify({'error': 'Failed to create ephemeral access session'}), 500

@app.route('/api/ephemeral/encrypt-document/<session_token>', methods=['GET'])
def get_encrypted_document_ephemeral(session_token):
    """Get document encrypted with ephemeral public key"""
    try:
        if not current_user.get('authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Validate and get session
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT das.*, d.filename, d.file_path, d.size as file_size,
                   d.content_type, d.classification_level
            FROM document_access_sessions das
            JOIN documents d ON das.document_id = d.id
            WHERE das.session_token = %s 
            AND das.user_identity_hash = %s
            AND das.expires_at > NOW()
            AND das.completed_at IS NULL
        """, (session_token, current_user['identity_hash']))
        
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
        
        # Prepare response for client-side decryption
        response = {
            'success': True,
            'encryptedDocument': encrypted_data['encrypted_document'],
            'encryptedKey': encrypted_data['encrypted_key'],
            'iv': encrypted_data['iv'],
            'authTag': encrypted_data['auth_tag'],
            'algorithm': encrypted_data['algorithm'],
            'sessionInfo': {
                'sessionToken': session_token,
                'ephemeralDID': session['ephemeral_did'],
                'expiresAt': encrypted_data['expires_at'],
                'documentInfo': {
                    'filename': session['filename'],
                    'contentType': session['content_type'],
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
        return jsonify({'error': 'Failed to retrieve encrypted document'}), 500

@app.route('/api/ephemeral/session-status/<session_token>', methods=['GET'])
def get_ephemeral_session_status(session_token):
    """Get status of ephemeral access session using new helper function (Task 2.3)"""
    try:
        if not current_user.get('authenticated'):
            return jsonify({'error': 'Authentication required'}), 401
        
        # Use new helper function for session validation (Task 2.3)
        validation_result = validate_ongoing_ephemeral_session(session_token, current_user['identity_hash'])
        
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
        if not current_user.get('authenticated'):
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
        if not current_user.get('authenticated'):
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
        user_identity_hash = current_user['identity_hash']
        
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

@app.route('/documents/browse')
def browse_documents():
    """Browse available documents with ephemeral access options"""
    try:
        if not current_user.get('authenticated'):
            flash('Please log in to browse documents.', 'error')
            return redirect(url_for('login'))
        
        # Get available documents
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT d.*, u.full_name as created_by_name,
                   CASE 
                       WHEN d.classification_level = 1 THEN 'Public'
                       WHEN d.classification_level = 2 THEN 'Internal' 
                       WHEN d.classification_level = 3 THEN 'Confidential'
                       ELSE 'Unknown'
                   END as classification_level_name,
                   can_user_access_level(%s, d.classification_level) as can_access
            FROM documents d
            LEFT JOIN users u ON d.created_by_user_id = u.id
            ORDER BY d.created_at DESC
        """, (current_user['identity_hash'],))
        
        documents = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('documents/browse.html',
                             documents=documents,
                             current_user=current_user)
        
    except Exception as e:
        print(f"❌ Failed to browse documents: {e}")
        flash('Failed to load documents.', 'error')
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