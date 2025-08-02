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
        return f"Config(environment={self.environment}, identus_agents=3, db={self.database.database_url})"


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
