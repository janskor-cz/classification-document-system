#!/usr/bin/env python3
"""
Enhanced Flask server for GitHub Codespaces
Integrates real Identus credential issuance with web dashboard
"""

from flask import Flask, render_template, send_from_directory, jsonify, request
from flask_cors import CORS
import os
import json
import threading
from datetime import datetime
import sys

# Import Identus integration
from identus_wrapper import identus_client

app = Flask(__name__)
CORS(app)

# Auto-configure for environment
if os.getenv('CODESPACES'):
    print("🌐 Configuring Flask for GitHub Codespaces...")
    app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY', 'codespaces-dev-secret-key'),
        DEBUG=True,
        HOST='0.0.0.0',  # Important for Codespaces port forwarding
        PORT=5000,
        # Codespaces provides HTTPS automatically
        PREFERRED_URL_SCHEME='https'
    )
else:
    print("🏠 Configuring Flask for local development...")
    app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY', 'local-dev-secret-key'),
        DEBUG=True,
        HOST='localhost',
        PORT=5000
    )

# Real applications storage - loads from Identus system
applications_db = []

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
        
        # Add demo applications if needed
        if len(applications_db) < 3:
            demo_apps = [
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
            load_real_identus_data()  # Will use demo data
    except Exception as e:
        print(f"⚠️ Identus initialization error: {e}")
        load_real_identus_data()  # Will use demo data

# Start Identus initialization in background
threading.Thread(target=initialize_identus, daemon=True).start()

# ==================== ROUTES ====================

@app.route('/')
def dashboard():
    """Serve the main dashboard"""
    try:
        return send_from_directory('static', 'issuer_dashboard.html')
    except Exception as e:
        print(f"❌ Error serving dashboard: {e}")
        return f"<h1>Dashboard Error</h1><p>Could not load dashboard: {e}</p>", 500

@app.route('/real-dashboard')
def real_dashboard():
    """Serve the enhanced dashboard"""
    try:
        return send_from_directory('templates', 'dashboard.html')
    except Exception as e:
        print(f"❌ Error serving real dashboard: {e}")
        return f"<h1>Dashboard Error</h1><p>Could not load enhanced dashboard: {e}</p>", 500

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

@app.route('/health')
def health_check():
    """Enhanced health check endpoint for Codespaces"""
    try:
        identus_healthy = identus_client.check_agents_health()
        
        health_info = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'environment': 'codespaces' if os.getenv('CODESPACES') else 'local',
            'applications_count': len(applications_db),
            'identus_healthy': identus_healthy,
            'identus_initialized': identus_client.issuer_did is not None,
            'pending_applications': len([app for app in applications_db if app['status'] == 'pending']),
            'approved_applications': len([app for app in applications_db if app['status'] == 'approved']),
            'denied_applications': len([app for app in applications_db if app['status'] == 'denied'])
        }
        
        if os.getenv('CODESPACES'):
            health_info['codespace_name'] = os.getenv('CODESPACE_NAME')
            health_info['port_forwarding_domain'] = os.getenv('GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN')
        
        return jsonify(health_info)
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

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
            'status': 'ready' if (agents_healthy and initialized) else 'not_ready',
            'environment': 'codespaces' if os.getenv('CODESPACES') else 'local'
        }
        
        # Add additional diagnostic info
        if not agents_healthy:
            status_info['message'] = 'Identus agents not responding'
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

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ==================== STARTUP ====================

if __name__ == '__main__':
    print("🚀 Starting Classification Document System Flask Server...")
    print("=" * 60)
    
    if os.getenv('CODESPACES'):
        print("🌐 Running in GitHub Codespaces")
        print(f"📊 Dashboard: Check Ports tab for forwarded URL")
        print(f"🆔 Identus Agents: Ports 8000, 7000, 9000 (auto-forwarded)")
    else:
        print("🏠 Running in local development mode")
        print(f"📊 Dashboard: http://localhost:5000")
        print(f"🆔 Identus Agents: 8000, 7000, 9000")
    
    print("")
    print("🎯 Features:")
    print("  • Real Identus credential issuance")
    print("  • Mock fallback when Identus unavailable")
    print("  • Application management")
    print("  • Real-time status monitoring")
    print("")
    print("💡 Use './dev-commands.sh status' to check all services")
    print("💡 Press Ctrl+C to stop the server")
    print("=" * 60)
    
    # Run the Flask app
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=app.config['DEBUG']
    )