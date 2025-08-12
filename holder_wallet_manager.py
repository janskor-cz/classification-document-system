"""
Holder Wallet Manager for User DID and Credential Management
Manages user DIDs and handles credential acceptance in the holder agent
"""

import json
import requests
import hashlib
import base64
from typing import Dict, Optional, List
from datetime import datetime
import urllib.parse


class HolderWalletManager:
    """Manages holder wallet operations for users"""
    
    def __init__(self, holder_url: str = "http://localhost:7000/cloud-agent"):
        self.holder_url = holder_url
        self.user_dids = {}  # Cache of user DIDs
        self.user_connections = {}  # Cache of user connections
        
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """Make HTTP request to holder agent"""
        url = f"{self.holder_url}{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                response = requests.post(url, headers=headers, json=data)
            elif method == 'PUT':
                response = requests.put(url, headers=headers, json=data)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            if response.status_code in [200, 201]:
                return response.json()
            else:
                print(f"❌ HTTP {response.status_code}: {response.text}")
                return {}
                
        except Exception as e:
            print(f"❌ Request failed: {e}")
            return {}
    
    def create_user_did(self, user_id: int, identity_hash: str) -> Optional[str]:
        """Create a DID for a user in the holder agent"""
        try:
            print(f"🔑 Creating DID for user {user_id}...")
            
            # Check if user already has a DID
            existing_did = self.get_user_did(user_id)
            if existing_did:
                print(f"✅ User already has DID: {existing_did}")
                return existing_did
            
            # Create new DID
            did_data = {
                "documentTemplate": {
                    "publicKeys": [{
                        "id": f"user-{user_id}-key",
                        "purpose": ["authentication", "assertionMethod", "keyAgreement", "capabilityDelegation"]
                    }],
                    "services": [{
                        "id": f"user-{user_id}-service",
                        "type": ["LinkedDomains"],
                        "serviceEndpoints": [f"https://enterprise.com/user/{user_id}"]
                    }]
                }
            }
            
            response = self._make_request('POST', '/did-registrar/dids', did_data)
            
            if response.get('longFormDid'):
                did = response['longFormDid']
                print(f"✅ Created DID for user {user_id}: {did[:50]}...")
                
                # Store in cache
                self.user_dids[user_id] = {
                    'did': did,
                    'identity_hash': identity_hash,
                    'created_at': datetime.now().isoformat()
                }
                
                return did
            else:
                print(f"⚠️ No DID returned for user {user_id}")
                return None
                
        except Exception as e:
            print(f"❌ Failed to create DID for user {user_id}: {e}")
            return None
    
    def get_user_did(self, user_id: int) -> Optional[str]:
        """Get existing DID for a user"""
        # Check cache first
        if user_id in self.user_dids:
            return self.user_dids[user_id]['did']
        
        # Could check holder agent for existing DIDs here
        # For now, return None if not in cache
        return None
    
    def accept_credential_invitation(self, user_id: int, invitation_url: str) -> Optional[str]:
        """Accept a credential invitation on behalf of a user"""
        try:
            print(f"📱 User {user_id} accepting credential invitation...")
            
            # Parse the invitation URL
            if '?_oob=' in invitation_url or '?oob=' in invitation_url:
                # Extract and decode the invitation
                parsed_url = urllib.parse.urlparse(invitation_url)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                
                invitation_param = query_params.get('_oob', [''])[0] or query_params.get('oob', [''])[0]
                
                if invitation_param:
                    # Decode base64 invitation
                    # Add padding if needed
                    padding = 4 - len(invitation_param) % 4
                    if padding != 4:
                        invitation_param += '=' * padding
                    
                    invitation_json = base64.urlsafe_b64decode(invitation_param).decode('utf-8')
                    invitation_data = json.loads(invitation_json)
                    
                    print(f"📨 Decoded invitation from: {invitation_data.get('label', 'Unknown')}")
                    
                    # Accept the invitation
                    response = self._make_request('POST', '/connection-invitations', invitation_data)
                    
                    connection_id = response.get('connectionId')
                    if connection_id:
                        print(f"✅ User {user_id} accepted invitation: {connection_id}")
                        
                        # Store connection for user
                        if user_id not in self.user_connections:
                            self.user_connections[user_id] = []
                        
                        self.user_connections[user_id].append({
                            'connection_id': connection_id,
                            'invitation_url': invitation_url,
                            'accepted_at': datetime.now().isoformat(),
                            'state': 'accepted'
                        })
                        
                        return connection_id
            
            print(f"⚠️ Could not parse invitation URL")
            return None
            
        except Exception as e:
            print(f"❌ Failed to accept invitation for user {user_id}: {e}")
            return None
    
    def get_user_connections(self, user_id: int) -> List[Dict]:
        """Get all connections for a user"""
        return self.user_connections.get(user_id, [])
    
    def get_user_credentials(self, user_id: int) -> List[Dict]:
        """Get all credentials for a user from holder wallet"""
        try:
            # Get all credentials from holder agent
            response = self._make_request('GET', '/credentials')
            
            user_credentials = []
            for cred in response.get('contents', []):
                # Filter by user ID or connection (would need proper mapping)
                # For now, return all credentials
                user_credentials.append(cred)
            
            return user_credentials
            
        except Exception as e:
            print(f"❌ Failed to get credentials for user {user_id}: {e}")
            return []
    
    def accept_credential_offer(self, user_id: int, credential_record_id: str) -> bool:
        """Accept a credential offer for a user"""
        try:
            print(f"🎫 User {user_id} accepting credential offer {credential_record_id}...")
            
            # Accept the credential offer
            response = self._make_request('POST', f'/credentials/{credential_record_id}/accept')
            
            if response.get('recordId'):
                print(f"✅ User {user_id} accepted credential: {response.get('recordId')}")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Failed to accept credential for user {user_id}: {e}")
            return False


# Global instance
holder_wallet_manager = HolderWalletManager()