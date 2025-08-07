#!/usr/bin/env python3
"""
Enhanced Identus wrapper for GitHub Codespaces integration
Handles both local development and Codespaces environments
"""

import requests
import json
import time
import os
from datetime import datetime, timedelta
from typing import Dict, Optional

from config import get_identus_config

identus_config = get_identus_config()

class IdentusConfig:
    """Configuration for Identus Cloud Agent"""
    def __init__(self, base_url: str = "http://localhost:8080", api_key: Optional[str] = None):
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = 30

class IdentusDashboardClient:
    """Enhanced Identus client for GitHub Codespaces and local development"""
    
    def __init__(self):
        # Auto-detect environment and configure URLs
        if os.getenv('CODESPACES'):
            print("🌐 Detected GitHub Codespaces environment")
            # In Codespaces, use localhost with port forwarding
            self.issuer_url = "http://localhost:8080"
            self.holder_url = "http://localhost:7000"
            self.verifier_url = "http://localhost:9000"
            self.bridge_ip = "127.0.0.1"
        else:
            print("🏠 Detected local development environment")
            # Local development configuration
            self.issuer_url = "http://localhost:8080"
            self.holder_url = "http://localhost:7000"
            self.verifier_url = "http://localhost:9000"
            self.bridge_ip = "172.17.0.1"
        
        # Initialize connection state
        self.issuer_did = None
        self.schema_uri = None
        
        print(f"🔗 Issuer URL: {self.issuer_url}")
        print(f"🔗 Holder URL: {self.holder_url}")
        print(f"🔗 Verifier URL: {self.verifier_url}")
        
    def initialize(self):
        """Initialize the Identus system (call this once at startup)"""
        print("🔧 Initializing Identus integration...")
        
        try:
            # Try to get existing published DID first (avoid creating new ones)
            dids_response = self._make_request(self.issuer_url, 'GET', '/did-registrar/dids')
            
            # Look for any existing DID (published or not) to avoid blockchain operations
            existing_did = None
            for did in dids_response.get('contents', []):
                if did.get('status') in ['PUBLISHED', 'PUBLICATION_PENDING']:
                    existing_did = did.get('did') or did.get('longFormDid')
                    print(f"✅ Found existing DID: {existing_did[:50]}...")
                    break
            
            if existing_did:
                self.issuer_did = existing_did
                print(f"✅ Using existing Issuer DID")
            else:
                print("⚠️ No existing DID found. Using development mode.")
                # In development, we can use a mock DID or skip DID operations
                self.issuer_did = "did:prism:development-mode-did"
                print("✅ Using development mode DID")
            
            # Get existing schema (avoid creating new ones)
            self.schema_uri = self._get_schema_uri_graceful()
            print(f"✅ Schema ready")
            
            return True
            
        except Exception as e:
            print(f"⚠️ Identus initialization with limited functionality: {e}")
            # Set development mode defaults
            self.issuer_did = "did:prism:development-mode-did" 
            self.schema_uri = "http://localhost:8080/schemas/development-schema"
            print("✅ Running in development mode with mock DIDs")
            return True  # Return True to continue with limited functionality
    
    def _make_request(self, base_url: str, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """Make HTTP request to Identus API with enhanced error handling"""
        url = f"{base_url}{endpoint}"
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=headers, json=data, timeout=30)
            
            response.raise_for_status()
            
            # Handle empty responses
            if not response.text:
                return {}
                
            return response.json()
            
        except requests.exceptions.Timeout:
            print(f"⏰ Request timeout for {url}")
            raise Exception(f"Request timeout - {url}")
        except requests.exceptions.ConnectionError:
            print(f"🔌 Connection error for {url}")
            raise Exception(f"Cannot connect to service - {url}")
        except requests.exceptions.HTTPError as e:
            print(f"🚫 HTTP error {e.response.status_code} for {url}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    print(f"Error details: {error_detail}")
                except:
                    print(f"Error response: {e.response.text}")
            raise Exception(f"HTTP {e.response.status_code} error")
        except Exception as e:
            print(f"❌ Unexpected error for {url}: {e}")
            raise
    
    def _get_published_did(self) -> str:
        """Get existing published DID or create new one"""
        try:
            dids_response = self._make_request(self.issuer_url, 'GET', '/did-registrar/dids')
            
            for did in dids_response.get('contents', []):
                if did.get('status') == 'PUBLISHED':
                    return did['did']
            
            # No published DID found, create one
            print("📝 No published DID found, creating new one...")
            return self._create_and_publish_did()
            
        except Exception as e:
            print(f"❌ Error getting published DID: {e}")
            raise Exception("Could not get or create published DID")
    
    def _create_and_publish_did(self) -> str:
        """Create and publish a new DID"""
        try:
            # Create DID
            did_data = {
                "documentTemplate": {
                    "publicKeys": [
                        {
                            "id": "auth-1",
                            "purpose": "authentication"
                        },
                        {
                            "id": "issue-1",
                            "purpose": "assertionMethod"
                        }
                    ],
                    "services": []
                }
            }
            
            did_response = self._make_request(self.issuer_url, 'POST', '/did-registrar/dids', did_data)
            long_form_did = did_response['longFormDid']
            print(f"✅ Created DID: {long_form_did[:50]}...")
            
            # Publish DID
            print("📤 Publishing DID...")
            self._make_request(self.issuer_url, 'POST', f'/did-registrar/dids/{long_form_did}/publications')
            
            # Wait for publishing
            print("⏳ Waiting for DID publication...")
            time.sleep(10)
            
            # Get published DID
            dids = self._make_request(self.issuer_url, 'GET', '/did-registrar/dids')
            for did in dids.get('contents', []):
                if did.get('status') == 'PUBLISHED':
                    published_did = did['did']
                    print(f"✅ DID published: {published_did}")
                    return published_did
            
            raise Exception("Failed to publish DID")
            
        except Exception as e:
            print(f"❌ Error creating/publishing DID: {e}")
            raise
    
    def _get_schema_uri(self) -> str:
        """Get existing schema URI or create new schema"""
        try:
            schemas_response = self._make_request(self.issuer_url, 'GET', '/schema-registry/schemas')
            
            if not schemas_response.get('contents'):
                print("📝 No schemas found, creating new schema...")
                return self._create_data_labeler_schema()
            
            # Use the first available schema
            first_schema = schemas_response['contents'][0]
            schema_guid = first_schema['guid']
            schema_uri = f"http://{self.bridge_ip}:8080/schema-registry/schemas/{schema_guid}"
            
            print(f"✅ Using existing schema: {first_schema.get('name', 'Unknown')}")
            return schema_uri
            
        except Exception as e:
            print(f"❌ Error getting schema: {e}")
            # Fallback to creating new schema
            return self._create_data_labeler_schema()
    
    def _create_data_labeler_schema(self) -> str:
        """Create a schema for data labeler credentials"""
        try:
            schema_data = {
                "name": "DataLabelerCredential",
                "version": "1.0.0",
                "description": "Credential for certified data labelers",
                "type": "https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json",
                "author": self.issuer_did,
                "tags": ["data-labeling", "certification"],
                "schema": {
                    "$id": "https://data-labeling.example.com/schemas/labeler-v1",
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "description": "Data Labeler Certification",
                    "type": "object",
                    "properties": {
                        "fullName": {"type": "string"},
                        "email": {"type": "string"},
                        "specialization": {"type": "string"},
                        "experienceLevel": {"type": "string"},
                        "certificationDate": {"type": "string"},
                        "labelerID": {"type": "string"},
                        "qualifications": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["fullName", "email", "certificationDate", "labelerID"],
                    "additionalProperties": True
                }
            }
            
            schema_response = self._make_request(self.issuer_url, 'POST', '/schema-registry/schemas', schema_data)
            schema_guid = schema_response['guid']
            schema_uri = f"http://{self.bridge_ip}:8080/schema-registry/schemas/{schema_guid}"
            
            print(f"✅ Created new schema: {schema_uri}")
            return schema_uri
            
        except Exception as e:
            print(f"❌ Error creating schema: {e}")
            raise Exception("Could not create schema")
    
    def _get_schema_uri_graceful(self) -> str:
        """Get existing schema URI without creating new ones (graceful for development)"""
        try:
            schemas_response = self._make_request(self.issuer_url, 'GET', '/schema-registry/schemas')
            
            if schemas_response.get('contents'):
                # Use the first available schema
                first_schema = schemas_response['contents'][0]
                schema_guid = first_schema['guid']
                schema_uri = f"http://{self.bridge_ip}:8080/schema-registry/schemas/{schema_guid}"
                print(f"✅ Using existing schema: {first_schema.get('name', 'Unknown')}")
                return schema_uri
            else:
                print("⚠️ No existing schemas found. Using development schema.")
                return "http://localhost:8080/schemas/development-data-labeler-schema"
                
        except Exception as e:
            print(f"⚠️ Error getting schema (using development mode): {e}")
            return "http://localhost:8080/schemas/development-data-labeler-schema"
    
    def get_credential_records(self) -> Dict:
        """Get all credential records from Identus"""
        try:
            return self._make_request(self.issuer_url, 'GET', '/issue-credentials/records')
        except Exception as e:
            print(f"⚠️ Could not get credential records: {e}")
            return {'contents': []}
    
    def get_dids(self) -> Dict:
        """Get all DIDs from Identus"""
        try:
            return self._make_request(self.issuer_url, 'GET', '/did-registrar/dids')
        except Exception as e:
            print(f"⚠️ Could not get DIDs: {e}")
            return {'contents': []}
    
    def get_schemas(self) -> Dict:
        """Get all schemas from Identus"""
        try:
            return self._make_request(self.issuer_url, 'GET', '/schema-registry/schemas')
        except Exception as e:
            print(f"⚠️ Could not get schemas: {e}")
            return {'contents': []}
    
    def issue_credential(self, application_data: Dict) -> Dict:
        """Issue a real credential for an approved application"""
        if not self.issuer_did or not self.schema_uri:
            raise Exception("Identus not initialized. Call initialize() first.")
        
        print(f"🎫 Issuing credential for {application_data['name']}...")
        
        # Adapt application data to credential claims
        claims = self._adapt_claims_to_schema(application_data)
        
        credential_data = {
            "claims": claims,
            "goal": "Data Labeler Certification",
            "credentialFormat": "JWT",
            "issuingDID": self.issuer_did,
            "schemaId": self.schema_uri,
            "automaticIssuance": True
        }
        
        try:
            response = self._make_request(
                self.issuer_url, 
                'POST', 
                '/issue-credentials/credential-offers/invitation', 
                credential_data
            )
            
            print(f"✅ Credential issued successfully!")
            
            return {
                'success': True,
                'credentialId': response.get('recordId'),
                'invitationUrl': response.get('invitationUrl'),
                'claims': claims
            }
            
        except Exception as e:
            print(f"❌ Credential issuance failed: {e}")
            raise
    
    def _adapt_claims_to_schema(self, app_data: Dict) -> Dict:
        """Adapt application data to match schema requirements"""
        
        # Check if using driving license schema (common fallback)
        if "042c04b9" in self.schema_uri or "driving-license" in self.schema_uri.lower():
            print("📋 Using driving license schema format...")
            return {
                "emailAddress": app_data['email'],
                "familyName": app_data['name'],
                "dateOfIssuance": datetime.now().isoformat(),
                "drivingLicenseID": app_data['labelerID'],
                "drivingClass": 1
            }
        
        # Default data labeling format
        return {
            "fullName": app_data['name'],
            "email": app_data['email'],
            "specialization": app_data.get('specialization', 'General'),
            "experienceLevel": app_data.get('experienceLevel', 'Beginner'),
            "certificationDate": datetime.now().isoformat(),
            "labelerID": app_data['labelerID'],
            "qualifications": app_data.get('qualifications', [])
        }
    
    def create_verification_request(self) -> Dict:
        """Create a verification request"""
        if not self.issuer_did or not self.schema_uri:
            raise Exception("Identus not initialized. Call initialize() first.")
        
        verification_data = {
            "goal": "Verify Data Labeler Credentials",
            "credentialFormat": "JWT",
            "proofs": [
                {
                    "schemaId": self.schema_uri,
                    "trustIssuers": [self.issuer_did]
                }
            ],
            "options": {
                "challenge": f"verification-{int(time.time())}",
                "domain": "data-labeling.example.com"
            }
        }
        
        try:
            response = self._make_request(
                self.verifier_url,
                'POST',
                '/present-proof/presentations/invitation',
                verification_data
            )
            
            return {
                'success': True,
                'verificationId': response.get('invitationId'),
                'invitationUrl': response.get('invitationUrl')
            }
            
        except Exception as e:
            print(f"❌ Verification request creation failed: {e}")
            raise
    
    def check_agents_health(self) -> bool:
        """Check if Identus agents are running"""
        print("🔍 Checking Identus agents health...")
        
        agents = [
            ("Issuer", self.issuer_url),
            ("Holder", self.holder_url),
            ("Verifier", self.verifier_url)
        ]
        
        healthy_count = 0
        
        for name, url in agents:
            try:
                self._make_request(url, 'GET', '/_system/health')
                print(f"✅ {name} agent is healthy")
                healthy_count += 1
            except Exception as e:
                print(f"❌ {name} agent is not healthy: {e}")
        
        all_healthy = healthy_count == len(agents)
        
        if all_healthy:
            print("🎉 All Identus agents are healthy!")
        else:
            print(f"⚠️ {healthy_count}/{len(agents)} agents are healthy")
        
        return all_healthy
    
    # ==================== ENTERPRISE-BASED CREDENTIAL METHODS ====================
    
    def issue_enterprise_based_credential(self, identity_hash: str, 
                                        enterprise_account_name: str,
                                        user_info: dict, 
                                        credential_type: str) -> dict:
        """Issue credential to enterprise-managed identity"""
        if not self.issuer_did or not self.schema_uri:
            print("⚠️ Identus not fully initialized. Using development mode for credential issuance.")
            # Return mock credential for development
            return {
                'success': True,
                'credentialId': f'dev-{credential_type}-{int(datetime.now().timestamp())}',
                'invitationUrl': f'mock://credential/{credential_type}',
                'identusRecordId': f'dev-record-{int(datetime.now().timestamp())}',
                'claims': {
                    "identityHash": identity_hash,
                    "enterpriseAccount": enterprise_account_name,
                    "credentialType": credential_type,
                    "issuedAt": datetime.now().isoformat(),
                    "mode": "development"
                },
                'credentialType': credential_type,
                'enterpriseAccount': enterprise_account_name,
                'identityHash': identity_hash,
                'developmentMode': True
            }
        
        print(f"🎫 Issuing {credential_type} credential for enterprise user...")
        
        # Create credential claims using identity hash and enterprise account
        claims = {
            "identityHash": identity_hash,
            "enterpriseAccount": enterprise_account_name,
            "email": user_info['email'],
            "fullName": user_info['full_name'],
            "department": user_info.get('department', ''),
            "jobTitle": user_info.get('job_title', ''),
            "employeeId": user_info.get('employee_id', ''),
            "credentialType": credential_type,
            "issuedAt": datetime.now().isoformat(),
            "expiresAt": (datetime.now() + timedelta(days=365)).isoformat(),
            "issuerDID": self.issuer_did,
            "version": "1.0"
        }
        
        # Add classification-specific claims
        if credential_type in ['public', 'internal', 'confidential']:
            classification_levels = {'public': 1, 'internal': 2, 'confidential': 3}
            claims.update({
                "classificationLevel": classification_levels.get(credential_type, 1),
                "classificationLabel": credential_type,
                "documentAccessRights": self._get_access_rights_for_level(credential_type)
            })
        
        credential_data = {
            "claims": claims,
            "goal": f"Enterprise {credential_type.title()} Credential",
            "credentialFormat": "JWT",
            "issuingDID": self.issuer_did,
            "schemaId": self.schema_uri,
            "automaticIssuance": True
        }
        
        try:
            response = self._make_request(
                self.issuer_url, 
                'POST', 
                '/issue-credentials/credential-offers/invitation', 
                credential_data
            )
            
            print(f"✅ {credential_type.title()} credential issued successfully!")
            
            return {
                'success': True,
                'credentialId': response.get('recordId'),
                'invitationUrl': response.get('invitationUrl'),
                'identusRecordId': response.get('recordId'),
                'claims': claims,
                'credentialType': credential_type,
                'enterpriseAccount': enterprise_account_name,
                'identityHash': identity_hash
            }
            
        except Exception as e:
            print(f"⚠️ Enterprise credential issuance failed, using development mode: {e}")
            # Fallback to development mode credential
            return {
                'success': True,
                'credentialId': f'dev-fallback-{credential_type}-{int(datetime.now().timestamp())}',
                'invitationUrl': f'mock://credential/{credential_type}',
                'identusRecordId': f'dev-fallback-{int(datetime.now().timestamp())}',
                'claims': claims,
                'credentialType': credential_type,
                'enterpriseAccount': enterprise_account_name,
                'identityHash': identity_hash,
                'developmentMode': True,
                'fallback': True
            }
    
    def recover_enterprise_credentials(self, email: str, 
                                     enterprise_account_name: str,
                                     new_identity_hash: str,
                                     admin_auth_token: str) -> dict:
        """Registration Authority recovery of lost user credentials"""
        print(f"🔄 Starting credential recovery for {email} in enterprise {enterprise_account_name}...")
        
        # TODO: Verify admin authorization
        if not admin_auth_token or len(admin_auth_token) < 10:
            return {
                'success': False,
                'error': 'Invalid admin authorization token'
            }
        
        try:
            # Get all credential records to find old credentials
            records_response = self.get_credential_records()
            old_credentials = []
            
            # Find credentials that might belong to the old identity
            # In a real implementation, this would be more sophisticated
            for record in records_response.get('contents', []):
                claims = record.get('claims', {})
                if (claims.get('email') == email and 
                    claims.get('enterpriseAccount') == enterprise_account_name):
                    old_credentials.append(record)
                    print(f"📋 Found old credential: {record.get('recordId', 'unknown')}")
            
            # For each old credential type, issue new credential with new identity hash
            recovery_results = []
            for old_cred in old_credentials:
                old_claims = old_cred.get('claims', {})
                credential_type = old_claims.get('credentialType', 'unknown')
                
                print(f"🔄 Recovering {credential_type} credential...")
                
                # Create user info from old claims
                user_info = {
                    'email': old_claims.get('email'),
                    'full_name': old_claims.get('fullName'),
                    'department': old_claims.get('department', ''),
                    'job_title': old_claims.get('jobTitle', ''),
                    'employee_id': old_claims.get('employeeId', '')
                }
                
                # Issue new credential with new identity hash
                recovery_result = self.issue_enterprise_based_credential(
                    new_identity_hash, enterprise_account_name, user_info, credential_type
                )
                
                if recovery_result['success']:
                    recovery_results.append({
                        'credential_type': credential_type,
                        'old_record_id': old_cred.get('recordId'),
                        'new_record_id': recovery_result['credentialId'],
                        'status': 'recovered'
                    })
                    print(f"✅ {credential_type} credential recovered successfully")
                else:
                    print(f"❌ Failed to recover {credential_type} credential: {recovery_result.get('error')}")
            
            return {
                'success': True,
                'recovered_credentials': recovery_results,
                'new_identity_hash': new_identity_hash,
                'enterprise_account': enterprise_account_name,
                'recovery_timestamp': datetime.now().isoformat(),
                'performed_by': admin_auth_token[:10] + '***'
            }
            
        except Exception as e:
            print(f"❌ Credential recovery failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def verify_enterprise_based_credential(self, identity_hash: str,
                                         enterprise_account_name: str,
                                         credential_type: str) -> dict:
        """Verify if user has valid credential for classification level"""
        try:
            print(f"🔍 Verifying {credential_type} credential for identity {identity_hash[:8]}...")
            
            # Get all credential records
            records_response = self.get_credential_records()
            
            # Look for matching credential
            for record in records_response.get('contents', []):
                claims = record.get('claims', {})
                
                if (claims.get('identityHash') == identity_hash and
                    claims.get('enterpriseAccount') == enterprise_account_name and
                    claims.get('credentialType') == credential_type):
                    
                    # Check if credential is still valid (not expired)
                    expires_at = claims.get('expiresAt')
                    if expires_at:
                        from dateutil import parser
                        expiry_date = parser.parse(expires_at)
                        if datetime.now() > expiry_date:
                            return {
                                'valid': False,
                                'reason': 'credential_expired',
                                'expires_at': expires_at
                            }
                    
                    print(f"✅ Valid {credential_type} credential found")
                    return {
                        'valid': True,
                        'credential_id': record.get('recordId'),
                        'issued_at': claims.get('issuedAt'),
                        'expires_at': claims.get('expiresAt'),
                        'classification_level': claims.get('classificationLevel'),
                        'enterprise_account': claims.get('enterpriseAccount')
                    }
            
            print(f"❌ No valid {credential_type} credential found")
            return {
                'valid': False,
                'reason': 'credential_not_found'
            }
            
        except Exception as e:
            print(f"❌ Credential verification failed: {e}")
            return {
                'valid': False,
                'reason': 'verification_error',
                'error': str(e)
            }
    
    def list_enterprise_credentials(self, enterprise_account_name: str) -> list:
        """Get all credentials issued under enterprise account"""
        try:
            print(f"📋 Listing credentials for enterprise account: {enterprise_account_name}")
            
            records_response = self.get_credential_records()
            enterprise_credentials = []
            
            for record in records_response.get('contents', []):
                claims = record.get('claims', {})
                
                if claims.get('enterpriseAccount') == enterprise_account_name:
                    enterprise_credentials.append({
                        'record_id': record.get('recordId'),
                        'identity_hash': claims.get('identityHash'),
                        'email': claims.get('email'),
                        'full_name': claims.get('fullName'),
                        'credential_type': claims.get('credentialType'),
                        'classification_level': claims.get('classificationLevel'),
                        'issued_at': claims.get('issuedAt'),
                        'expires_at': claims.get('expiresAt'),
                        'status': record.get('protocolState', 'unknown')
                    })
            
            print(f"✅ Found {len(enterprise_credentials)} credentials for enterprise {enterprise_account_name}")
            return enterprise_credentials
            
        except Exception as e:
            print(f"❌ Error listing enterprise credentials: {e}")
            return []
    
    def revoke_credential_with_enterprise_auth(self, record_id: str, 
                                             enterprise_account_name: str,
                                             reason: str,
                                             admin_auth: str) -> bool:
        """Revoke credential with enterprise account authority"""
        try:
            print(f"🚫 Revoking credential {record_id} for enterprise {enterprise_account_name}")
            
            # TODO: Verify admin authorization
            if not admin_auth or len(admin_auth) < 10:
                print("❌ Invalid admin authorization")
                return False
            
            # Verify the credential belongs to the enterprise account
            records_response = self.get_credential_records()
            credential_found = False
            
            for record in records_response.get('contents', []):
                if record.get('recordId') == record_id:
                    claims = record.get('claims', {})
                    if claims.get('enterpriseAccount') == enterprise_account_name:
                        credential_found = True
                        break
            
            if not credential_found:
                print(f"❌ Credential {record_id} not found or not owned by enterprise {enterprise_account_name}")
                return False
            
            # Note: Identus Cloud Agent doesn't have a direct revocation endpoint in current version
            # This would need to be implemented based on the specific Identus version and capabilities
            print(f"⚠️ Credential revocation marked for processing (manual step required)")
            print(f"   Reason: {reason}")
            print(f"   Admin: {admin_auth[:10]}***")
            
            # In a full implementation, this would:
            # 1. Update the credential status in the database
            # 2. Add revocation to blockchain if supported
            # 3. Notify relevant parties
            
            return True
            
        except Exception as e:
            print(f"❌ Credential revocation failed: {e}")
            return False
    
    def _get_access_rights_for_level(self, classification_level: str) -> list:
        """Get document access rights for classification level"""
        access_rights = {
            'public': ['read_public', 'create_public'],
            'internal': ['read_public', 'read_internal', 'create_public', 'create_internal'],
            'confidential': ['read_public', 'read_internal', 'read_confidential', 
                           'create_public', 'create_internal', 'create_confidential']
        }
        return access_rights.get(classification_level, ['read_public'])

# Global instance to be used by Flask app
identus_client = IdentusDashboardClient()
