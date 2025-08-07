#!/usr/bin/env python3
"""
Configuration Management for Classification Document System
Handles different environments (development, testing, production)
and manages sensitive configuration data.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import timedelta

# Load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed, continue without it
    pass


@dataclass
class IdentusConfig:
    """Configuration for Hyperledger Identus agents"""
    issuer_url: str = "http://localhost:8000/cloud-agent"
    holder_url: str = "http://localhost:7000/cloud-agent"
    verifier_url: str = "http://localhost:9000/cloud-agent"
    bridge_ip: str = "172.17.0.1"
    timeout: int = 30
    health_check_interval: int = 60
    max_retry_attempts: int = 3
    retry_delay: int = 5


@dataclass
class DatabaseConfig:
    """Database configuration"""
    # Default to SQLite for development
    database_url: str = "sqlite:///classification_system.db"
    echo_sql: bool = False
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600


@dataclass
class SecurityConfig:
    """Security and encryption configuration"""
    secret_key: str = field(default_factory=lambda: os.urandom(32).hex())
    jwt_secret_key: str = field(default_factory=lambda: os.urandom(32).hex())
    jwt_access_token_expires: timedelta = timedelta(hours=1)
    password_salt_rounds: int = 12
    
    # Document encryption
    encryption_algorithm: str = "AES-256-GCM"
    key_derivation_iterations: int = 100000
    
    # Classification levels
    classification_levels: Dict[str, int] = field(default_factory=lambda: {
        "public": 1,
        "internal": 2, 
        "confidential": 3
    })


@dataclass
class DocumentConfig:
    """Document management configuration"""
    upload_folder: str = "uploads"
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    allowed_extensions: set = field(default_factory=lambda: {"pdf", "doc", "docx", "txt"})
    storage_encryption: bool = True
    auto_classification: bool = False
    
    # Document retention policies
    retention_days: Dict[str, int] = field(default_factory=lambda: {
        "public": 365 * 5,      # 5 years
        "internal": 365 * 7,    # 7 years  
        "confidential": 365 * 10 # 10 years
    })


@dataclass
class AuditConfig:
    """Audit and logging configuration"""
    enable_audit_logging: bool = True
    audit_log_file: str = "logs/audit.log"
    audit_retention_days: int = 365 * 7  # 7 years
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_log_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5


@dataclass
class AuthenticationConfig:
    """Authentication configuration for Working Package 1"""
    default_enterprise_account: str = 'DEFAULT_ENTERPRISE'
    identity_hash_algorithm: str = 'sha256'
    session_timeout: int = 3600  # 1 hour
    max_login_attempts: int = 5
    lockout_duration: int = 900  # 15 minutes
    password_min_length: int = 8
    password_require_special_chars: bool = True
    password_require_numbers: bool = True
    bcrypt_rounds: int = 12


@dataclass
class EnterpriseConfig:
    """Enterprise account management configuration"""
    allow_multiple_enterprise_accounts: bool = True
    require_enterprise_account_approval: bool = True
    auto_assign_enterprise_account: bool = False  # Auto-assign based on email domain
    enterprise_admin_roles: list = field(default_factory=lambda: ["admin", "enterprise_admin"])
    default_enterprise_display_name: str = "Default Enterprise Account"
    enable_enterprise_isolation: bool = True  # Isolate users by enterprise account
    
    # Email domain to enterprise account mapping
    domain_to_enterprise: Dict[str, str] = field(default_factory=lambda: {
        "example.com": "DEFAULT_ENTERPRISE",
        "acme.com": "ACME_CORP"
    })


@dataclass
class CredentialConfig:
    """Credential management configuration"""
    default_expiry_days: int = 365
    auto_approve_public: bool = False  # Require approval for all credentials
    require_department_approval: bool = True
    max_credentials_per_user: int = 3  # Max classification credentials per user
    enable_enterprise_recovery: bool = True  # Allow RA recovery using enterprise account
    
    # Credential types and their classification levels
    credential_types: Dict[str, int] = field(default_factory=lambda: {
        "basic_enterprise": 0,  # Enterprise access credential (no classification level)
        "public": 1,            # Public classification credential
        "internal": 2,          # Internal classification credential
        "confidential": 3       # Confidential classification credential
    })
    
    # Business justification requirements
    require_justification: Dict[str, bool] = field(default_factory=lambda: {
        "basic_enterprise": True,
        "public": True,
        "internal": True,
        "confidential": True
    })


@dataclass
class RecoveryConfig:
    """Credential recovery configuration"""
    recovery_token_expiry_hours: int = 24
    require_admin_approval_for_recovery: bool = True
    allow_self_service_recovery: bool = False  # Future feature
    recovery_audit_retention_days: int = 90
    max_recovery_attempts: int = 3
    recovery_cooldown_hours: int = 2  # Cooldown between recovery attempts
    
    # Admin authorization levels for recovery
    recovery_authorization_levels: Dict[str, list] = field(default_factory=lambda: {
        "password_reset": ["admin", "enterprise_admin"],
        "identity_recovery": ["admin", "enterprise_admin", "security_admin"],
        "bulk_recovery": ["admin", "security_admin"]
    })


@dataclass
class WebConfig:
    """Web application configuration"""
    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False
    threaded: bool = True
    
    # Session configuration
    session_timeout: int = 3600  # 1 hour
    permanent_session_lifetime: timedelta = timedelta(hours=1)
    
    # CORS settings
    cors_origins: list = field(default_factory=lambda: ["http://localhost:3000", "http://127.0.0.1:3000"])


class Config:
    """Main configuration class that combines all config sections"""
    
    def __init__(self, environment: str = None):
        self.environment = environment or os.getenv('FLASK_ENV', 'development')
        
        # Initialize configuration sections
        self.identus = IdentusConfig()
        self.database = DatabaseConfig()
        self.security = SecurityConfig()
        self.documents = DocumentConfig()
        self.audit = AuditConfig()
        self.web = WebConfig()
        
        # Working Package 1: New configuration sections
        self.authentication = AuthenticationConfig()
        self.enterprise = EnterpriseConfig()
        self.credentials = CredentialConfig()
        self.recovery = RecoveryConfig()
        
        # Load environment-specific settings
        self._load_environment_config()
        self._load_from_environment_variables()
        self._create_required_directories()
    
    def _load_environment_config(self):
        """Load environment-specific configuration"""
        if self.environment == 'production':
            self._load_production_config()
        elif self.environment == 'testing':
            self._load_testing_config()
        else:
            self._load_development_config()
    
    def _load_development_config(self):
        """Development environment configuration"""
        self.web.debug = True
        self.web.host = "127.0.0.1"
        self.database.echo_sql = True
        self.audit.log_level = "DEBUG"
        
        # Use local Identus agents
        self.identus.issuer_url = "http://localhost:8000/cloud-agent"
        self.identus.holder_url = "http://localhost:7000/cloud-agent"
        self.identus.verifier_url = "http://localhost:9000/cloud-agent"
    
    def _load_testing_config(self):
        """Testing environment configuration"""
        self.web.debug = False
        self.database.database_url = "sqlite:///:memory:"  # In-memory database
        self.documents.upload_folder = "test_uploads"
        self.audit.enable_audit_logging = False
        
        # Use test Identus agents (if available)
        self.identus.issuer_url = "http://localhost:18000/cloud-agent"
        self.identus.holder_url = "http://localhost:17000/cloud-agent"
        self.identus.verifier_url = "http://localhost:19000/cloud-agent"
    
    def _load_production_config(self):
        """Production environment configuration"""
        self.web.debug = False
        self.web.host = "0.0.0.0"
        self.database.echo_sql = False
        self.audit.log_level = "WARNING"
        self.security.encryption_algorithm = "AES-256-GCM"
        
        # Production should use proper PostgreSQL
        self.database.database_url = os.getenv(
            'DATABASE_URL', 
            'postgresql://user:password@localhost/classification_db'
        )
    
    def _load_from_environment_variables(self):
        """Load configuration from environment variables"""
        
        # Identus configuration
        self.identus.issuer_url = os.getenv('IDENTUS_ISSUER_URL', self.identus.issuer_url)
        self.identus.holder_url = os.getenv('IDENTUS_HOLDER_URL', self.identus.holder_url)
        self.identus.verifier_url = os.getenv('IDENTUS_VERIFIER_URL', self.identus.verifier_url)
        
        # Database configuration
        self.database.database_url = os.getenv('DATABASE_URL', self.database.database_url)
        
        # Security configuration
        if os.getenv('SECRET_KEY'):
            self.security.secret_key = os.getenv('SECRET_KEY')
        if os.getenv('JWT_SECRET_KEY'):
            self.security.jwt_secret_key = os.getenv('JWT_SECRET_KEY')
        
        # Web configuration
        self.web.host = os.getenv('FLASK_HOST', self.web.host)
        self.web.port = int(os.getenv('FLASK_PORT', self.web.port))
        
        # Document configuration
        self.documents.upload_folder = os.getenv('UPLOAD_FOLDER', self.documents.upload_folder)
        self.documents.max_file_size = int(os.getenv('MAX_FILE_SIZE', self.documents.max_file_size))
        
        # Authentication configuration (Working Package 1)
        self.authentication.default_enterprise_account = os.getenv(
            'DEFAULT_ENTERPRISE_ACCOUNT', self.authentication.default_enterprise_account)
        self.authentication.session_timeout = int(os.getenv(
            'SESSION_TIMEOUT', self.authentication.session_timeout))
        self.authentication.max_login_attempts = int(os.getenv(
            'MAX_LOGIN_ATTEMPTS', self.authentication.max_login_attempts))
        self.authentication.password_min_length = int(os.getenv(
            'PASSWORD_MIN_LENGTH', self.authentication.password_min_length))
        
        # Enterprise configuration
        self.enterprise.require_enterprise_account_approval = os.getenv(
            'REQUIRE_ENTERPRISE_APPROVAL', 'true').lower() == 'true'
        self.enterprise.auto_assign_enterprise_account = os.getenv(
            'AUTO_ASSIGN_ENTERPRISE', 'false').lower() == 'true'
        
        # Credential configuration
        self.credentials.default_expiry_days = int(os.getenv(
            'CREDENTIAL_EXPIRY_DAYS', self.credentials.default_expiry_days))
        self.credentials.auto_approve_public = os.getenv(
            'AUTO_APPROVE_PUBLIC', 'false').lower() == 'true'
        self.credentials.require_department_approval = os.getenv(
            'REQUIRE_DEPARTMENT_APPROVAL', 'true').lower() == 'true'
        
        # Recovery configuration
        self.recovery.recovery_token_expiry_hours = int(os.getenv(
            'RECOVERY_TOKEN_EXPIRY_HOURS', self.recovery.recovery_token_expiry_hours))
        self.recovery.require_admin_approval_for_recovery = os.getenv(
            'REQUIRE_ADMIN_RECOVERY_APPROVAL', 'true').lower() == 'true'
    
    def _create_required_directories(self):
        """Create required directories if they don't exist"""
        directories = [
            self.documents.upload_folder,
            os.path.dirname(self.audit.audit_log_file),
            "static/uploads",
            "static/encrypted",
            "logs"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def get_identus_config(self) -> IdentusConfig:
        """Get Identus configuration"""
        return self.identus
    
    def get_database_url(self) -> str:
        """Get database URL"""
        return self.database.database_url
    
    # Working Package 1: New configuration getters
    def get_authentication_config(self) -> AuthenticationConfig:
        """Get authentication configuration"""
        return self.authentication
    
    def get_enterprise_config(self) -> EnterpriseConfig:
        """Get enterprise account configuration"""
        return self.enterprise
    
    def get_credentials_config(self) -> CredentialConfig:
        """Get credential management configuration"""
        return self.credentials
    
    def get_recovery_config(self) -> RecoveryConfig:
        """Get credential recovery configuration"""
        return self.recovery
    
    def get_flask_config(self) -> Dict[str, Any]:
        """Get Flask application configuration as dictionary"""
        return {
            'SECRET_KEY': self.security.secret_key,
            'SQLALCHEMY_DATABASE_URI': self.database.database_url,
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'SQLALCHEMY_ECHO': self.database.echo_sql,
            'UPLOAD_FOLDER': self.documents.upload_folder,
            'MAX_CONTENT_LENGTH': self.documents.max_file_size,
            'PERMANENT_SESSION_LIFETIME': self.web.permanent_session_lifetime,
            'JWT_SECRET_KEY': self.security.jwt_secret_key,
            'JWT_ACCESS_TOKEN_EXPIRES': self.security.jwt_access_token_expires
        }
    
    def is_classification_valid(self, classification: str) -> bool:
        """Check if classification level is valid"""
        return classification.lower() in self.security.classification_levels
    
    def get_classification_level(self, classification: str) -> int:
        """Get numerical level for classification"""
        return self.security.classification_levels.get(classification.lower(), 0)
    
    def can_access_classification(self, user_level: str, document_level: str) -> bool:
        """Check if user can access document based on classification levels"""
        user_num = self.get_classification_level(user_level)
        doc_num = self.get_classification_level(document_level)
        
        # Strict level-based access - user must have EXACT level
        return user_num == doc_num
    
    # Working Package 1: Enterprise account utility methods
    def get_enterprise_account_from_email(self, email: str) -> str:
        """Get enterprise account based on email domain"""
        if not self.enterprise.auto_assign_enterprise_account:
            return self.authentication.default_enterprise_account
        
        domain = email.split('@')[1] if '@' in email else ''
        return self.enterprise.domain_to_enterprise.get(
            domain, self.authentication.default_enterprise_account)
    
    def is_credential_type_valid(self, credential_type: str) -> bool:
        """Check if credential type is valid"""
        return credential_type in self.credentials.credential_types
    
    def get_credential_classification_level(self, credential_type: str) -> int:
        """Get classification level for credential type"""
        return self.credentials.credential_types.get(credential_type, 0)
    
    def requires_business_justification(self, credential_type: str) -> bool:
        """Check if credential type requires business justification"""
        return self.credentials.require_justification.get(credential_type, True)
    
    def can_admin_perform_recovery(self, admin_role: str, recovery_type: str) -> bool:
        """Check if admin role can perform specific recovery type"""
        allowed_roles = self.recovery.recovery_authorization_levels.get(recovery_type, [])
        return admin_role in allowed_roles
    
    def validate_config(self) -> bool:
        """Validate configuration settings"""
        errors = []
        
        # Check required directories exist
        if not os.path.exists(self.documents.upload_folder):
            errors.append(f"Upload folder does not exist: {self.documents.upload_folder}")
        
        # Check Identus URLs are valid
        required_urls = [
            self.identus.issuer_url,
            self.identus.holder_url, 
            self.identus.verifier_url
        ]
        
        for url in required_urls:
            if not url.startswith(('http://', 'https://')):
                errors.append(f"Invalid URL format: {url}")
        
        # Check classification levels
        if len(self.security.classification_levels) < 3:
            errors.append("At least 3 classification levels required")
        
        if errors:
            print("Configuration validation errors:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        return True
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return (f"Config(environment={self.environment}, "
                f"enterprise_accounts={self.enterprise.allow_multiple_enterprise_accounts}, "
                f"identus_agents=3, db={self.database.database_url})")


# Global configuration instance
config = Config()


def get_config() -> Config:
    """Get the global configuration instance"""
    return config


def reload_config(environment: str = None) -> Config:
    """Reload configuration with optional environment override"""
    global config
    config = Config(environment)
    return config


# Convenience functions
def get_identus_config() -> IdentusConfig:
    """Get Identus configuration"""
    return config.get_identus_config()


def get_flask_config() -> Dict[str, Any]:
    """Get Flask configuration"""
    return config.get_flask_config()


def is_development() -> bool:
    """Check if running in development environment"""
    return config.environment == 'development'


def is_production() -> bool:
    """Check if running in production environment"""
    return config.environment == 'production'


if __name__ == "__main__":
    # Test configuration loading
    print(f"Configuration loaded: {config}")
    print(f"Environment: {config.environment}")
    print(f"Database URL: {config.database.database_url}")
    print(f"Identus Issuer: {config.identus.issuer_url}")
    print(f"Upload folder: {config.documents.upload_folder}")
    print(f"Classification levels: {config.security.classification_levels}")
    
    # Validate configuration
    if config.validate_config():
        print("✅ Configuration is valid")
    else:
        print("❌ Configuration has errors")
