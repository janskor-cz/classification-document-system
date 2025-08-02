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
from datetime import datetime
import sys
import traceback
from functools import wraps

# Import our configuration and Identus integration
from config import get_config, get_flask_config
from identus_wrapper import identus_client

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

# Real applications storage - loads from Identus system
applications_db = []

# Simple user session simulation (replace with proper auth in production)
current_user = {
    'is_authenticated': True,
    'name': 'Demo User',
    'email': 'demo@example.com',
    'credentials_count': 0,
    'is_admin': True
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
            print("💡 Start your Identus agents on ports 8000 and 9000 for real credential issuance.")
            load_real_identus_data()  # Will use demo data
    except Exception as e:
        print(f"⚠️ Identus initialization error: {e}")
        load_real_identus_data()  # Will use demo data

# Start Identus initialization in background
threading.Thread(target=initialize_identus, daemon=True).start()

# Template context processor to make current_user available in all templates
@app.context_processor
def inject_user():
    return dict(current_user=current_user, config=config)

# ==================== WEB ROUTES ====================

@app.route('/')
def dashboard():
    """Main dashboard page"""
    try:
        # Calculate statistics
        stats = {
            'my_credentials': current_user.get('credentials_count', 0),
            'documents_accessed': 15,  # Mock data
            'pending_requests': len([app for app in applications_db if app['status'] == 'pending']),
            'security_score': 85
        }
        
        # Get user's credentials (mock data)
        credentials = [
            {
                'name': 'Enterprise Credential',
                'type': 'enterprise',
                'issued_date': datetime.now()
            },
            {
                'name': 'Public Classification',
                'type': 'public',
                'issued_date': datetime.now()
            }
        ]
        
        # Get recent activities (mock data)
        recent_activities = [
            {
                'action': 'Credential Approved',
                'description': 'Public classification credential approved',
                'timestamp': datetime.now(),
                'type': 'success'
            },
            {
                'action': 'Document Uploaded',
                'description': 'Annual report classified as Internal',
                'timestamp': datetime.now(),
                'type': 'info'
            }
        ]
        
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

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/auth/login', methods=['POST'])
def auth_login():
    """Handle login form submission"""
    try:
        email = request.form.get('email')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me')
        
        # Mock authentication (replace with real auth in production)
        if email and password:
            # Simulate successful login
            current_user['is_authenticated'] = True
            current_user['email'] = email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
            
    except Exception as e:
        print(f"❌ Login error: {e}")
        flash('Login failed. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/auth/logout')
def auth_logout():
    """Handle logout"""
    current_user['is_authenticated'] = False
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

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
            status_info['message'] = 'Identus agents not responding on ports 8000/9000'
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
            status_info['message'] = 'Identus agents not responding on ports 8000/9000'
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
        
    } catch (error) {
        return jsonify({'error': str(error)}), 500

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
    print("💡 Make sure your Identus agents are running on ports 7000, 8000, and 9000")
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