#!/usr/bin/env python3
"""
Enhanced Identus wrapper for GitHub Codespaces integration
Handles both local development and Codespaces environments
"""

import requests
import json
import time
import os
from datetime import datetime
from typing import Dict, Optional

class IdentusConfig:
    """Configuration for Identus Cloud Agent"""
    def __init__(self, base_url: str = "http://localhost:8000", api_key: Optional[str] = None):
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
            self.issuer_url = "http://localhost:8000/cloud-agent"
            self.holder_url = "http://localhost:7000/cloud-agent"
            self.verifier_url = "http://localhost:9000/cloud-agent"
            self.bridge_ip = "127.0.0.1"
        else:
            print("🏠 Detected local development environment")
            # Local development configuration
            self.issuer_url = "http://localhost:8000/cloud-agent"
            self.holder_url = "http://localhost:7000/cloud-agent"
            self.verifier_url = "http://localhost:9000/cloud-agent"
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
            # Get existing published DID
            self.issuer_did = self._get_published_did()
            print(f"✅ Using Issuer DID: {self.issuer_did}")
            
            # Get existing schema
            self.schema_uri = self._get_schema_uri()
            print(f"✅ Using Schema: {self.schema_uri}")
            
            return True
            
        except Exception as e:
            print(f"❌ Identus initialization failed: {e}")
            return False
    
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
            schema_uri = f"http://{self.bridge_ip}:8000/cloud-agent/schema-registry/schemas/{schema_guid}"
            
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
            schema_uri = f"http://{self.bridge_ip}:8000/cloud-agent/schema-registry/schemas/{schema_guid}"
            
            print(f"✅ Created new schema: {schema_uri}")
            return schema_uri
            
        except Exception as e:
            print(f"❌ Error creating schema: {e}")
            raise Exception("Could not create schema")
    
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

# Global instance to be used by Flask app
identus_client = IdentusDashboardClient()