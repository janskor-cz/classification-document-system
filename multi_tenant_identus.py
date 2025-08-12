#!/usr/bin/env python3
"""
Multi-Tenant Hyperledger Identus Integration
Implements enterprise-based agent routing and multi-tenancy architecture
"""

import requests
import json
import time
import os
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass

@dataclass
class IdentusAgent:
    """Configuration for a single Identus agent instance"""
    name: str
    url: str
    api_key: Optional[str] = None
    tenant_id: Optional[str] = None
    enterprise_accounts: List[str] = None  # Which enterprises use this agent
    max_connections: int = 100
    health_status: str = "unknown"
    
    def __post_init__(self):
        if self.enterprise_accounts is None:
            self.enterprise_accounts = []

@dataclass
class EnterpriseConfig:
    """Configuration for enterprise account"""
    account_name: str
    account_display_name: str
    agent_preference: str  # Primary agent to use
    fallback_agents: List[str]  # Fallback agents if primary is down
    tenant_id: str  # Tenant ID for this enterprise
    api_key: str  # API key for this enterprise
    classification_levels: List[str]  # Allowed classification levels
    wallet_id: Optional[str] = None
    
class MultiTenantIdentusClient:
    """Multi-tenant Identus client supporting multiple cloud agents"""
    
    def __init__(self):
        self.agents = {}
        self.enterprises = {}
        self.current_enterprise = None
        self.current_agent = None
        self._initialize_agents()
        self._initialize_enterprises()
        
    def _initialize_agents(self):
        """Initialize multiple Identus agent configurations"""
        
        # Primary Agent Cluster (Production)
        self.agents['primary-issuer'] = IdentusAgent(
            name="Primary Issuer",
            url=os.getenv('IDENTUS_PRIMARY_ISSUER_URL', 'http://localhost:8080'),
            api_key=os.getenv('IDENTUS_PRIMARY_API_KEY'),
            enterprise_accounts=['ENTERPRISE_A', 'ENTERPRISE_B'],
            max_connections=200
        )
        
        self.agents['primary-holder'] = IdentusAgent(
            name="Primary Holder", 
            url=os.getenv('IDENTUS_PRIMARY_HOLDER_URL', 'http://localhost:7000'),
            api_key=os.getenv('IDENTUS_PRIMARY_HOLDER_API_KEY'),
            enterprise_accounts=['ENTERPRISE_A', 'ENTERPRISE_B'],
            max_connections=150
        )
        
        self.agents['primary-verifier'] = IdentusAgent(
            name="Primary Verifier",
            url=os.getenv('IDENTUS_PRIMARY_VERIFIER_URL', 'http://localhost:9000'),
            api_key=os.getenv('IDENTUS_PRIMARY_VERIFIER_API_KEY'),
            enterprise_accounts=['ENTERPRISE_A', 'ENTERPRISE_B'],
            max_connections=150
        )
        
        # Secondary Agent Cluster (Backup/DR)
        self.agents['secondary-issuer'] = IdentusAgent(
            name="Secondary Issuer",
            url=os.getenv('IDENTUS_SECONDARY_ISSUER_URL', 'http://localhost:8081'),
            api_key=os.getenv('IDENTUS_SECONDARY_API_KEY'),
            enterprise_accounts=['ENTERPRISE_C', 'ENTERPRISE_D'],
            max_connections=100
        )
        
        # Enterprise-Specific Agents
        self.agents['gov-issuer'] = IdentusAgent(
            name="Government Issuer",
            url=os.getenv('IDENTUS_GOV_ISSUER_URL', 'http://localhost:8082'),
            api_key=os.getenv('IDENTUS_GOV_API_KEY'),
            enterprise_accounts=['GOVERNMENT_AGENCY'],
            max_connections=50
        )
        
        print(f"🔧 Initialized {len(self.agents)} Identus agents")
        
    def _initialize_enterprises(self):
        """Initialize enterprise configurations with agent assignments"""
        
        self.enterprises['DEFAULT_ENTERPRISE'] = EnterpriseConfig(
            account_name="DEFAULT_ENTERPRISE",
            account_display_name="Default Enterprise Account",
            agent_preference="primary-issuer",
            fallback_agents=[],  # No fallback - only use running agents
            tenant_id="tenant-default",
            api_key=os.getenv('DEFAULT_ENTERPRISE_API_KEY', 'default-key-123'),
            classification_levels=['public', 'internal']
        )
        
        self.enterprises['ENTERPRISE_A'] = EnterpriseConfig(
            account_name="ENTERPRISE_A",
            account_display_name="Enterprise Alpha Corp",
            agent_preference="primary-issuer", 
            fallback_agents=[],  # No fallback - only use running agents
            tenant_id="tenant-alpha",
            api_key=os.getenv('ENTERPRISE_A_API_KEY', 'alpha-key-456'),
            classification_levels=['public', 'internal', 'confidential']
        )
        
        self.enterprises['ENTERPRISE_B'] = EnterpriseConfig(
            account_name="ENTERPRISE_B",
            account_display_name="Enterprise Beta Solutions",
            agent_preference="primary-issuer",
            fallback_agents=[],  # No fallback - only use running agents
            tenant_id="tenant-beta", 
            api_key=os.getenv('ENTERPRISE_B_API_KEY', 'beta-key-789'),
            classification_levels=['public', 'internal']
        )
        
        self.enterprises['GOVERNMENT_AGENCY'] = EnterpriseConfig(
            account_name="GOVERNMENT_AGENCY",
            account_display_name="Government Classification Agency",
            agent_preference="primary-issuer",  # Use primary since gov agent not running
            fallback_agents=[],  # No fallback - only use running agents
            tenant_id="tenant-government",
            api_key=os.getenv('GOV_AGENCY_API_KEY', 'gov-key-secure'),
            classification_levels=['public', 'internal', 'confidential', 'restricted']
        )
        
        print(f"🏢 Initialized {len(self.enterprises)} enterprise configurations")
    
    def set_enterprise_context(self, enterprise_account_name: str) -> bool:
        """Set the current enterprise context for operations"""
        
        if enterprise_account_name not in self.enterprises:
            print(f"❌ Unknown enterprise account: {enterprise_account_name}")
            return False
            
        self.current_enterprise = self.enterprises[enterprise_account_name]
        
        # Select appropriate agent based on enterprise preference
        agent_selected = self._select_agent_for_enterprise(enterprise_account_name)
        
        if agent_selected:
            print(f"✅ Enterprise context set: {enterprise_account_name}")
            print(f"🎯 Using agent: {self.current_agent.name}")
            print(f"🏢 Tenant ID: {self.current_enterprise.tenant_id}")
            return True
        else:
            print(f"❌ No available agents for enterprise: {enterprise_account_name}")
            return False
    
    def _select_agent_for_enterprise(self, enterprise_account_name: str) -> bool:
        """Select best available agent for enterprise account"""
        
        enterprise = self.enterprises[enterprise_account_name]
        
        # Try primary agent first
        primary_agent_name = enterprise.agent_preference
        if primary_agent_name in self.agents:
            primary_agent = self.agents[primary_agent_name]
            if self._check_agent_health(primary_agent):
                self.current_agent = primary_agent
                return True
            else:
                print(f"⚠️ Primary agent {primary_agent_name} is unhealthy")
        
        # Try fallback agents
        for fallback_name in enterprise.fallback_agents:
            if fallback_name in self.agents:
                fallback_agent = self.agents[fallback_name]
                if self._check_agent_health(fallback_agent):
                    print(f"🔄 Using fallback agent: {fallback_name}")
                    self.current_agent = fallback_agent
                    return True
                else:
                    print(f"⚠️ Fallback agent {fallback_name} is unhealthy")
        
        # No healthy agents found
        print(f"❌ No healthy agents available for enterprise {enterprise_account_name}")
        return False
    
    def _check_agent_health(self, agent: IdentusAgent) -> bool:
        """Check if an agent is healthy and responsive"""
        try:
            response = requests.get(
                f"{agent.url}/_system/health",
                timeout=5,
                headers=self._get_headers_for_agent(agent)
            )
            
            if response.status_code == 200:
                agent.health_status = "healthy"
                return True
            else:
                agent.health_status = f"unhealthy-{response.status_code}"
                return False
                
        except Exception as e:
            agent.health_status = f"error-{str(e)[:20]}"
            return False
    
    def _get_headers_for_agent(self, agent: IdentusAgent) -> Dict[str, str]:
        """Get HTTP headers for agent requests including authentication"""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Add API key authentication if available
        if agent.api_key:
            headers['X-API-Key'] = agent.api_key
            
        # Add tenant-specific headers if in enterprise context
        if self.current_enterprise:
            headers['X-Tenant-ID'] = self.current_enterprise.tenant_id
            headers['X-Enterprise-Account'] = self.current_enterprise.account_name
            
        return headers
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """Make HTTP request to current agent with multi-tenant authentication"""
        
        if not self.current_agent:
            raise Exception("No agent selected. Call set_enterprise_context() first.")
            
        if not self.current_enterprise:
            raise Exception("No enterprise context set. Call set_enterprise_context() first.")
        
        url = f"{self.current_agent.url}{endpoint}"
        headers = self._get_headers_for_agent(self.current_agent)
        
        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=headers, json=data, timeout=30)
            elif method.upper() == 'PUT':
                response = requests.put(url, headers=headers, json=data, timeout=30)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=30)
            
            response.raise_for_status()
            
            # Handle empty responses
            if not response.text:
                return {}
                
            return response.json()
            
        except requests.exceptions.Timeout:
            print(f"⏰ Request timeout for {url}")
            # Try fallback agent if available
            return self._try_fallback_request(method, endpoint, data)
        except requests.exceptions.ConnectionError:
            print(f"🔌 Connection error for {url}")
            return self._try_fallback_request(method, endpoint, data)
        except requests.exceptions.HTTPError as e:
            print(f"🚫 HTTP error {e.response.status_code} for {url}")
            
            # Get detailed error information
            error_detail = {}
            try:
                error_detail = e.response.json()
                print(f"Error details: {error_detail}")
            except:
                error_detail = {'error': e.response.text}
            
            # For multi-tenant system, don't use fallback for HTTP 500 errors 
            # since we only have primary agents running
            if e.response.status_code >= 500 and len(self.current_enterprise.fallback_agents) > 0:
                # Only try fallback if we have configured fallback agents
                return self._try_fallback_request(method, endpoint, data)
            else:
                # Return clear error message
                raise Exception(f"HTTP {e.response.status_code}: {error_detail}")
        except Exception as e:
            print(f"❌ Unexpected error for {url}: {e}")
            raise
    
    def _try_fallback_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """Try the same request with a fallback agent"""
        
        if not self.current_enterprise:
            raise Exception("No enterprise context for fallback")
            
        original_agent = self.current_agent
        
        # Try each fallback agent
        for fallback_name in self.current_enterprise.fallback_agents:
            if fallback_name in self.agents and fallback_name != original_agent.name:
                fallback_agent = self.agents[fallback_name]
                
                if self._check_agent_health(fallback_agent):
                    print(f"🔄 Retrying with fallback agent: {fallback_name}")
                    self.current_agent = fallback_agent
                    
                    try:
                        url = f"{fallback_agent.url}{endpoint}"
                        headers = self._get_headers_for_agent(fallback_agent)
                        
                        if method.upper() == 'GET':
                            response = requests.get(url, headers=headers, timeout=30)
                        elif method.upper() == 'POST':
                            response = requests.post(url, headers=headers, json=data, timeout=30)
                        
                        response.raise_for_status()
                        
                        if not response.text:
                            return {}
                            
                        print(f"✅ Fallback request successful with {fallback_name}")
                        return response.json()
                        
                    except Exception as e:
                        print(f"❌ Fallback agent {fallback_name} also failed: {e}")
                        continue
        
        # Restore original agent and raise error
        self.current_agent = original_agent
        raise Exception("All agents failed - no fallback available")
    
    def issue_enterprise_credential(self, identity_hash: str, user_info: Dict, 
                                  credential_type: str) -> Dict:
        """Issue credential using multi-tenant architecture"""
        
        if not self.current_enterprise:
            raise Exception("Enterprise context not set")
            
        # Verify enterprise can issue this credential type
        if credential_type not in self.current_enterprise.classification_levels:
            raise Exception(f"Enterprise {self.current_enterprise.account_name} cannot issue {credential_type} credentials")
            
        print(f"🎫 Issuing {credential_type} credential for enterprise {self.current_enterprise.account_name}")
        print(f"🏢 Using tenant: {self.current_enterprise.tenant_id}")
        print(f"🎯 Using agent: {self.current_agent.name}")
        
        # Create credential claims with enterprise and tenant context
        claims = {
            "identityHash": identity_hash,
            "enterpriseAccount": self.current_enterprise.account_name,
            "tenantId": self.current_enterprise.tenant_id,
            "agentUsed": self.current_agent.name,
            "email": user_info['email'],
            "fullName": user_info['full_name'],
            "department": user_info.get('department', ''),
            "jobTitle": user_info.get('job_title', ''),
            "employeeId": user_info.get('employee_id', ''),
            "credentialType": credential_type,
            "issuedAt": datetime.now().isoformat(),
            "expiresAt": (datetime.now() + timedelta(days=365)).isoformat(),
            "version": "2.0-multi-tenant"
        }
        
        # Add classification-specific claims
        if credential_type in ['public', 'internal', 'confidential', 'restricted']:
            classification_levels = {'public': 1, 'internal': 2, 'confidential': 3, 'restricted': 4}
            claims.update({
                "classificationLevel": classification_levels.get(credential_type, 1),
                "classificationLabel": credential_type,
                "documentAccessRights": self._get_access_rights_for_level(credential_type)
            })
        
        # Step 1: Establish connection for credential issuance
        connection_id = self._establish_connection()
        
        credential_data = {
            "connectionId": connection_id,
            "claims": claims,
            "goal": f"Enterprise {credential_type.title()} Credential",
            "credentialFormat": "JWT",
            "automaticIssuance": True
        }
        
        try:
            response = self._make_request('POST', '/issue-credentials/credential-offers', credential_data)
            
            print(f"✅ Multi-tenant credential issued successfully!")
            
            return {
                'success': True,
                'credentialId': response.get('recordId'),
                'invitationUrl': response.get('invitationUrl'),
                'identusRecordId': response.get('recordId'),
                'claims': claims,
                'credentialType': credential_type,
                'enterpriseAccount': self.current_enterprise.account_name,
                'tenantId': self.current_enterprise.tenant_id,
                'agentUsed': self.current_agent.name,
                'identityHash': identity_hash,
                'multiTenant': True
            }
            
        except Exception as e:
            print(f"❌ Multi-tenant credential issuance failed: {e}")
            raise
    
    def _establish_connection(self) -> str:
        """Establish connection between agents for credential issuance - Multi-tenant version"""
        print("🔗 Creating multi-tenant connection for credential issuance...")
        
        try:
            # Step 1: Check for existing active connections first
            connections = self._make_request('GET', '/connections')
            if connections.get('contents'):
                for conn in connections['contents']:
                    if conn.get('state') in ['ConnectionResponseSent', 'ConnectionResponseReceived', 'InvitationGenerated']:
                        print(f"✅ Using existing connection: {conn['connectionId']} (state: {conn.get('state')})")
                        return conn['connectionId']
            
            # Step 2: Create new connection invitation with tenant context
            invitation_data = {
                "label": f"Multi-Tenant Credential Issuance - {self.current_enterprise.tenant_id}"
            }
            
            invitation_response = self._make_request('POST', '/connections', invitation_data)
            
            connection_id = invitation_response['connectionId']
            print(f"🔗 Created multi-tenant connection: {connection_id}")
            print(f"🏢 Enterprise: {self.current_enterprise.account_name}")
            print(f"🎯 Agent: {self.current_agent.name}")
            
            # Return the connection ID immediately - don't wait for acceptance
            return connection_id
            
        except Exception as e:
            print(f"❌ Failed to establish multi-tenant connection: {e}")
            raise Exception(f"Could not establish connection: {e}")
    
    def verify_enterprise_credential(self, identity_hash: str, credential_type: str) -> Dict:
        """Verify credential with enterprise context"""
        
        if not self.current_enterprise:
            raise Exception("Enterprise context not set")
            
        print(f"🔍 Verifying {credential_type} credential for enterprise {self.current_enterprise.account_name}")
        
        try:
            records_response = self._make_request('GET', '/issue-credentials/records')
            
            # Look for matching credential in current tenant context
            for record in records_response.get('contents', []):
                claims = record.get('claims', {})
                
                if (claims.get('identityHash') == identity_hash and
                    claims.get('enterpriseAccount') == self.current_enterprise.account_name and
                    claims.get('tenantId') == self.current_enterprise.tenant_id and
                    claims.get('credentialType') == credential_type):
                    
                    # Check expiration
                    expires_at = claims.get('expiresAt')
                    if expires_at:
                        from dateutil import parser
                        expiry_date = parser.parse(expires_at)
                        if datetime.now() > expiry_date:
                            return {
                                'valid': False,
                                'reason': 'credential_expired',
                                'expires_at': expires_at,
                                'enterprise': self.current_enterprise.account_name,
                                'tenant': self.current_enterprise.tenant_id
                            }
                    
                    print(f"✅ Valid multi-tenant {credential_type} credential found")
                    return {
                        'valid': True,
                        'credential_id': record.get('recordId'),
                        'issued_at': claims.get('issuedAt'),
                        'expires_at': claims.get('expiresAt'),
                        'classification_level': claims.get('classificationLevel'),
                        'enterprise_account': claims.get('enterpriseAccount'),
                        'tenant_id': claims.get('tenantId'),
                        'agent_used': claims.get('agentUsed'),
                        'multi_tenant': True
                    }
            
            print(f"❌ No valid {credential_type} credential found in tenant {self.current_enterprise.tenant_id}")
            return {
                'valid': False,
                'reason': 'credential_not_found',
                'enterprise': self.current_enterprise.account_name,
                'tenant': self.current_enterprise.tenant_id
            }
            
        except Exception as e:
            print(f"❌ Multi-tenant credential verification failed: {e}")
            return {
                'valid': False,
                'reason': 'verification_error',
                'error': str(e),
                'enterprise': self.current_enterprise.account_name if self.current_enterprise else 'unknown'
            }
    
    def get_agent_status(self) -> Dict:
        """Get status of all configured agents"""
        
        status = {
            'total_agents': len(self.agents),
            'healthy_agents': 0,
            'unhealthy_agents': 0,
            'agents': {}
        }
        
        for agent_name, agent in self.agents.items():
            is_healthy = self._check_agent_health(agent)
            
            status['agents'][agent_name] = {
                'name': agent.name,
                'url': agent.url,
                'health': agent.health_status,
                'is_healthy': is_healthy,
                'enterprise_accounts': agent.enterprise_accounts,
                'max_connections': agent.max_connections,
                'has_api_key': bool(agent.api_key)
            }
            
            if is_healthy:
                status['healthy_agents'] += 1
            else:
                status['unhealthy_agents'] += 1
        
        return status
    
    def get_enterprise_status(self) -> Dict:
        """Get status of all enterprise configurations"""
        
        status = {
            'total_enterprises': len(self.enterprises),
            'enterprises': {}
        }
        
        for enterprise_name, enterprise in self.enterprises.items():
            # Check if primary agent is healthy
            primary_healthy = False
            if enterprise.agent_preference in self.agents:
                primary_healthy = self._check_agent_health(self.agents[enterprise.agent_preference])
            
            # Count healthy fallback agents
            healthy_fallbacks = 0
            for fallback in enterprise.fallback_agents:
                if fallback in self.agents and self._check_agent_health(self.agents[fallback]):
                    healthy_fallbacks += 1
            
            status['enterprises'][enterprise_name] = {
                'display_name': enterprise.account_display_name,
                'tenant_id': enterprise.tenant_id,
                'primary_agent': enterprise.agent_preference,
                'primary_healthy': primary_healthy,
                'fallback_agents': enterprise.fallback_agents,
                'healthy_fallbacks': healthy_fallbacks,
                'classification_levels': enterprise.classification_levels,
                'has_wallet': bool(enterprise.wallet_id),
                'has_api_key': bool(enterprise.api_key)
            }
        
        return status
    
    def _get_access_rights_for_level(self, classification_level: str) -> List[str]:
        """Get document access rights for classification level"""
        access_rights = {
            'public': ['read_public', 'create_public'],
            'internal': ['read_public', 'read_internal', 'create_public', 'create_internal'],
            'confidential': ['read_public', 'read_internal', 'read_confidential', 
                           'create_public', 'create_internal', 'create_confidential'],
            'restricted': ['read_public', 'read_internal', 'read_confidential', 'read_restricted',
                          'create_public', 'create_internal', 'create_confidential', 'create_restricted']
        }
        return access_rights.get(classification_level, ['read_public'])

# Global multi-tenant client instance
multi_tenant_client = MultiTenantIdentusClient()