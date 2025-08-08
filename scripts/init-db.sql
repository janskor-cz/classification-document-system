-- Database initialization script for Classification Document System
-- Working Package 1: Registration Authority with Email/Password Hash Authentication

-- =====================================================================================
-- ENTERPRISE ACCOUNTS - Foundation for corporate control and user identity generation
-- =====================================================================================

-- Enterprise accounts table - used as salt for identity generation
CREATE TABLE IF NOT EXISTS enterprise_accounts (
    id SERIAL PRIMARY KEY,
    account_name VARCHAR(100) UNIQUE NOT NULL, -- Used as salt, e.g., "ACME_CORP"
    account_display_name VARCHAR(255) NOT NULL, -- e.g., "ACME Corporation"
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default enterprise account
INSERT INTO enterprise_accounts (account_name, account_display_name, description) 
VALUES ('DEFAULT_ENTERPRISE', 'Default Enterprise Account', 'Default enterprise account for credential management')
ON CONFLICT (account_name) DO NOTHING;

-- =====================================================================================
-- ENHANCED USER MANAGEMENT - Cryptographic identity with enterprise account salt
-- =====================================================================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- bcrypt hash of user password
    enterprise_account_id INTEGER REFERENCES enterprise_accounts(id) NOT NULL,
    enterprise_account_name VARCHAR(100) NOT NULL, -- Denormalized for performance
    identity_hash VARCHAR(64) UNIQUE NOT NULL, -- SHA256(email+password+enterprise_account_name)
    full_name VARCHAR(255) NOT NULL,
    department VARCHAR(100),
    job_title VARCHAR(100),
    employee_id VARCHAR(50),
    is_active BOOLEAN DEFAULT true,
    has_enterprise_credential BOOLEAN DEFAULT false, -- Track if user has basic enterprise credential
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (enterprise_account_name) REFERENCES enterprise_accounts(account_name)
);

-- =====================================================================================
-- TWO-STAGE CREDENTIAL SYSTEM - Enterprise + Classification credentials
-- =====================================================================================

-- Two-stage credential requests: Enterprise + Classification
CREATE TABLE IF NOT EXISTS credential_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    identity_hash VARCHAR(64) NOT NULL,
    enterprise_account_name VARCHAR(100) NOT NULL,
    credential_category VARCHAR(50) NOT NULL, -- 'enterprise', 'classification'
    credential_type VARCHAR(50) NOT NULL, -- 'basic_enterprise', 'public', 'internal', 'confidential'
    status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'approved', 'denied'
    business_justification TEXT,
    department_approval VARCHAR(100),
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP,
    processed_by VARCHAR(100),
    denial_reason TEXT,
    identus_record_id VARCHAR(500), -- Identus credential record ID when issued
    UNIQUE(identity_hash, credential_type)
);

-- Track issued credentials with classification levels
CREATE TABLE IF NOT EXISTS issued_credentials (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    identity_hash VARCHAR(64) NOT NULL,
    enterprise_account_name VARCHAR(100) NOT NULL,
    credential_category VARCHAR(50) NOT NULL, -- 'enterprise', 'classification'
    credential_type VARCHAR(50) NOT NULL, -- 'basic_enterprise', 'public', 'internal', 'confidential'
    classification_level INTEGER, -- NULL for enterprise, 1=public, 2=internal, 3=confidential
    identus_record_id VARCHAR(500) NOT NULL,
    invitation_url TEXT,
    credential_claims JSONB,
    status VARCHAR(50) DEFAULT 'issued', -- 'issued', 'revoked', 'expired'
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    revocation_reason TEXT
);

-- =====================================================================================
-- ENHANCED DOCUMENT MANAGEMENT - Classification control with user authorization
-- =====================================================================================

-- Enhanced documents table with classification control
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT,
    mime_type VARCHAR(100),
    classification_level INTEGER NOT NULL, -- 1=public, 2=internal, 3=confidential
    classification_label VARCHAR(50) NOT NULL, -- 'public', 'internal', 'confidential'
    created_by_user_id INTEGER REFERENCES users(id),
    created_by_identity_hash VARCHAR(64) NOT NULL,
    creator_max_classification_level INTEGER NOT NULL, -- User's max classification level when created
    enterprise_account_name VARCHAR(100) NOT NULL,
    is_encrypted BOOLEAN DEFAULT false,
    encryption_key_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Document access attempts log
CREATE TABLE IF NOT EXISTS document_access_log (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id),
    user_id INTEGER REFERENCES users(id),
    identity_hash VARCHAR(64) NOT NULL,
    enterprise_account_name VARCHAR(100) NOT NULL,
    access_type VARCHAR(50) NOT NULL, -- 'view', 'download'
    document_classification_level INTEGER NOT NULL,
    user_classification_level INTEGER, -- User's classification level at time of access
    access_granted BOOLEAN NOT NULL,
    denial_reason TEXT,
    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================================================
-- AUDIT AND COMPLIANCE - Comprehensive tracking for enterprise accounts
-- =====================================================================================

-- Audit trail for all credential operations
CREATE TABLE IF NOT EXISTS credential_audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    identity_hash VARCHAR(64),
    enterprise_account_name VARCHAR(100),
    action VARCHAR(100) NOT NULL, -- 'request', 'approve', 'deny', 'issue', 'revoke', 'recover'
    credential_category VARCHAR(50), -- 'enterprise', 'classification'
    credential_type VARCHAR(50),
    details JSONB,
    performed_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Recovery requests for lost credentials
CREATE TABLE IF NOT EXISTS credential_recovery_requests (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    enterprise_account_name VARCHAR(100) NOT NULL,
    recovery_type VARCHAR(50) DEFAULT 'lost_password', -- 'lost_password', 'account_locked'
    recovery_token VARCHAR(64),
    token_expires_at TIMESTAMP,
    status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'approved', 'denied', 'completed'
    requested_by_admin BOOLEAN DEFAULT false,
    approved_by VARCHAR(100),
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Enhanced audit logs for all system operations
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    identity_hash VARCHAR(64),
    enterprise_account_name VARCHAR(100),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100) NOT NULL,
    details JSONB NULL,
    ip_address INET NULL,
    user_agent TEXT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================================================
-- HELPER FUNCTIONS - Utility functions for classification level management
-- =====================================================================================

-- Helper function to get user's maximum classification level
CREATE OR REPLACE FUNCTION get_user_max_classification_level(user_identity_hash VARCHAR(64))
RETURNS INTEGER AS $$
DECLARE
    max_level INTEGER := 0;
BEGIN
    SELECT COALESCE(MAX(classification_level), 0)
    INTO max_level
    FROM issued_credentials 
    WHERE identity_hash = user_identity_hash 
    AND credential_category = 'classification' 
    AND status = 'issued'
    AND (expires_at IS NULL OR expires_at > NOW());
    
    RETURN max_level;
END;
$$ LANGUAGE plpgsql;

-- Function to check if user can classify at specific level
CREATE OR REPLACE FUNCTION can_user_classify_at_level(user_identity_hash VARCHAR(64), requested_level INTEGER)
RETURNS BOOLEAN AS $$
DECLARE
    max_level INTEGER;
BEGIN
    max_level := get_user_max_classification_level(user_identity_hash);
    RETURN max_level >= requested_level;
END;
$$ LANGUAGE plpgsql;

-- Function to check if user can access document at specific level
CREATE OR REPLACE FUNCTION can_user_access_level(user_identity_hash VARCHAR(64), required_level INTEGER)
RETURNS BOOLEAN AS $$
DECLARE
    has_exact_level BOOLEAN := false;
BEGIN
    SELECT COUNT(*) > 0
    INTO has_exact_level
    FROM issued_credentials 
    WHERE identity_hash = user_identity_hash 
    AND credential_category = 'classification' 
    AND classification_level = required_level
    AND status = 'issued'
    AND (expires_at IS NULL OR expires_at > NOW());
    
    RETURN has_exact_level;
END;
$$ LANGUAGE plpgsql;

-- =====================================================================================
-- PERFORMANCE INDEXES
-- =====================================================================================

-- Enterprise accounts indexes
CREATE INDEX IF NOT EXISTS idx_enterprise_accounts_name ON enterprise_accounts(account_name);
CREATE INDEX IF NOT EXISTS idx_enterprise_accounts_active ON enterprise_accounts(is_active);

-- Users indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_identity_hash ON users(identity_hash);
CREATE INDEX IF NOT EXISTS idx_users_enterprise_account ON users(enterprise_account_name);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);

-- Credential requests indexes
CREATE INDEX IF NOT EXISTS idx_credential_requests_user ON credential_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_credential_requests_identity ON credential_requests(identity_hash);
CREATE INDEX IF NOT EXISTS idx_credential_requests_status ON credential_requests(status);
CREATE INDEX IF NOT EXISTS idx_credential_requests_category ON credential_requests(credential_category);

-- Issued credentials indexes
CREATE INDEX IF NOT EXISTS idx_issued_credentials_user ON issued_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_issued_credentials_identity ON issued_credentials(identity_hash);
CREATE INDEX IF NOT EXISTS idx_issued_credentials_status ON issued_credentials(status);
CREATE INDEX IF NOT EXISTS idx_issued_credentials_level ON issued_credentials(classification_level);
CREATE INDEX IF NOT EXISTS idx_issued_credentials_category ON issued_credentials(credential_category);

-- Documents indexes
CREATE INDEX IF NOT EXISTS idx_documents_created_by ON documents(created_by_user_id);
CREATE INDEX IF NOT EXISTS idx_documents_identity ON documents(created_by_identity_hash);
CREATE INDEX IF NOT EXISTS idx_documents_classification ON documents(classification_level);
CREATE INDEX IF NOT EXISTS idx_documents_enterprise ON documents(enterprise_account_name);

-- Access log indexes
CREATE INDEX IF NOT EXISTS idx_document_access_document ON document_access_log(document_id);
CREATE INDEX IF NOT EXISTS idx_document_access_user ON document_access_log(user_id);
CREATE INDEX IF NOT EXISTS idx_document_access_time ON document_access_log(accessed_at);

-- Audit log indexes
CREATE INDEX IF NOT EXISTS idx_credential_audit_user ON credential_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_credential_audit_identity ON credential_audit_log(identity_hash);
CREATE INDEX IF NOT EXISTS idx_credential_audit_action ON credential_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_credential_audit_time ON credential_audit_log(created_at);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_identity ON audit_logs(identity_hash);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- =====================================================================================
-- TIMESTAMP TRIGGERS
-- =====================================================================================

-- Create a function to update timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_enterprise_accounts_updated_at BEFORE UPDATE ON enterprise_accounts 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_documents_updated_at BEFORE UPDATE ON documents 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================================================
-- IDENTUS USERS AND PERMISSIONS
-- =====================================================================================

-- Create pollux application user for Identus agents if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pollux-application-user') THEN
        CREATE USER "pollux-application-user" WITH PASSWORD 'pollux_pass';
    END IF;
END
$$;

-- Create connect application user for Identus agents if not exists  
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'connect-application-user') THEN
        CREATE USER "connect-application-user" WITH PASSWORD 'connect_pass';
    END IF;
END
$$;

-- Create agent application user for Identus agents if not exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'agent-application-user') THEN
        CREATE USER "agent-application-user" WITH PASSWORD 'agent_pass';
    END IF;
END
$$;

-- Grant identus_user admin privileges so it can create roles if needed
ALTER USER identus_user CREATEDB CREATEROLE;

-- Grant necessary permissions to all users
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO identus_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO identus_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "pollux-application-user";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "pollux-application-user";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "connect-application-user";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "connect-application-user";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "agent-application-user";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "agent-application-user";

-- Grant future table/sequence privileges as well
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO identus_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO identus_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "pollux-application-user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "pollux-application-user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "connect-application-user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "connect-application-user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "agent-application-user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "agent-application-user";

-- =====================================================================================
-- SAMPLE DATA FOR TESTING
-- =====================================================================================

-- Insert sample enterprise accounts
INSERT INTO enterprise_accounts (account_name, account_display_name, description) VALUES 
    ('ACME_CORP', 'ACME Corporation', 'ACME Corporation enterprise account for employees'),
    ('TECH_DIVISION', 'Technology Division', 'Technology Division enterprise account')
ON CONFLICT (account_name) DO NOTHING;

-- Insert sample users with enterprise account structure
INSERT INTO users (
    email, password_hash, enterprise_account_id, enterprise_account_name, 
    identity_hash, full_name, department, job_title, employee_id, has_enterprise_credential
) VALUES 
    ('john.doe@company.com', '$2b$12$GwEAkC3i0834N.6dljUiKuhmo/cKtvwF0dacvFF150GqdA4wSnJFu', 1, 'DEFAULT_ENTERPRISE', 
     'f51bf4b4f472276b722dd7f3a0f1d24636985c862eac00012cf8560f0abbb7c2', 'John Doe', 'Engineering', 'Senior Developer', 'EMP-001', true),
    ('jane.smith@company.com', '$2b$12$Y5HMuYyl8R07gIrd71h4U.tM4B9QHRsa28fFP9cqSDP9igy33vr3u', 1, 'DEFAULT_ENTERPRISE', 
     '84f78145acd8b68994a4c054a28c011fd4044b4b70838e61456fb1ffb9e989b0', 'Jane Smith', 'Data Science', 'Data Scientist', 'EMP-002', true),
    ('admin@company.com', '$2b$12$O5ZEfsAarLKp20pL5hcnhebpEMQo7LvKpD/r2Oa4M1lglX2KBBj42', 1, 'DEFAULT_ENTERPRISE', 
     'd7e19308bf73560c2e20c1958a74dc36a7c20299047e4704671e49d1d0a84433', 'Admin User', 'Administration', 'System Administrator', 'EMP-003', true)
ON CONFLICT (email) DO NOTHING;

-- Insert sample credential requests
INSERT INTO credential_requests (
    user_id, identity_hash, enterprise_account_name, credential_category, credential_type, 
    status, business_justification, requested_at
) VALUES 
    (1, 'sample_identity_hash_john_doe_12345678', 'DEFAULT_ENTERPRISE', 'classification', 'public', 
     'approved', 'Need to label public documents for machine learning project', NOW() - INTERVAL '2 days'),
    (2, 'sample_identity_hash_jane_smith_87654321', 'DEFAULT_ENTERPRISE', 'classification', 'internal', 
     'pending', 'Require access to internal datasets for analysis project', NOW() - INTERVAL '1 day')
ON CONFLICT (identity_hash, credential_type) DO NOTHING;

-- Insert sample issued credentials
INSERT INTO issued_credentials (
    user_id, identity_hash, enterprise_account_name, credential_category, credential_type, 
    classification_level, identus_record_id, status, issued_at
) VALUES 
    (1, 'sample_identity_hash_john_doe_12345678', 'DEFAULT_ENTERPRISE', 'enterprise', 'basic_enterprise', 
     NULL, 'sample_enterprise_record_123', 'issued', NOW() - INTERVAL '7 days'),
    (1, 'sample_identity_hash_john_doe_12345678', 'DEFAULT_ENTERPRISE', 'classification', 'public', 
     1, 'sample_public_record_456', 'issued', NOW() - INTERVAL '5 days'),
    (2, 'sample_identity_hash_jane_smith_87654321', 'DEFAULT_ENTERPRISE', 'enterprise', 'basic_enterprise', 
     NULL, 'sample_enterprise_record_789', 'issued', NOW() - INTERVAL '6 days')
ON CONFLICT DO NOTHING;

-- =====================================================================================
-- WORKING PACKAGE 3: EPHEMERAL DID-BASED DOCUMENT ENCRYPTION
-- =====================================================================================

-- Track ephemeral DIDs for document access sessions
CREATE TABLE IF NOT EXISTS document_access_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    user_identity_hash VARCHAR(64) NOT NULL,
    enterprise_account_name VARCHAR(100) NOT NULL,
    document_id INTEGER REFERENCES documents(id),
    ephemeral_did VARCHAR(500) NOT NULL, -- User-generated ephemeral DID:key
    ephemeral_public_key JSONB NOT NULL, -- Public key for encryption (JWK format)
    session_token VARCHAR(64) NOT NULL UNIQUE,
    classification_level INTEGER NOT NULL,
    classification_verified BOOLEAN DEFAULT false,
    document_encrypted_with_ephemeral_key BOOLEAN DEFAULT false,
    access_granted BOOLEAN DEFAULT false,
    expires_at TIMESTAMP NOT NULL, -- Short expiration (e.g., 1 hour)
    accessed_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (enterprise_account_name) REFERENCES enterprise_accounts(account_name)
);

-- Enhanced documents table with ephemeral encryption support
ALTER TABLE documents ADD COLUMN IF NOT EXISTS encrypted_with_ephemeral_did BOOLEAN DEFAULT false;
ALTER TABLE documents ADD COLUMN IF NOT EXISTS original_encryption_method VARCHAR(50) DEFAULT 'classification'; -- 'classification', 'ephemeral'

-- Document encryption metadata for ephemeral access
CREATE TABLE IF NOT EXISTS document_ephemeral_encryption (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id),
    access_session_id INTEGER REFERENCES document_access_sessions(id),
    ephemeral_did VARCHAR(500) NOT NULL,
    encrypted_document_path VARCHAR(500) NOT NULL,
    encryption_algorithm VARCHAR(50) DEFAULT 'ECIES-P256', -- Elliptic Curve encryption
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    accessed_at TIMESTAMP,
    expired_at TIMESTAMP
);

-- Audit log for ephemeral DID document access
CREATE TABLE IF NOT EXISTS ephemeral_did_audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    user_identity_hash VARCHAR(64),
    enterprise_account_name VARCHAR(100),
    document_id INTEGER REFERENCES documents(id),
    ephemeral_did VARCHAR(500),
    action VARCHAR(100) NOT NULL, -- 'did_generated', 'access_requested', 'document_encrypted', 'document_decrypted', 'session_expired'
    classification_level INTEGER,
    session_token VARCHAR(64),
    success BOOLEAN DEFAULT true,
    error_details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (enterprise_account_name) REFERENCES enterprise_accounts(account_name)
);

-- =====================================================================================
-- EPHEMERAL DID PERFORMANCE INDEXES
-- =====================================================================================

-- Indexes for ephemeral access sessions
CREATE INDEX IF NOT EXISTS idx_access_sessions_user_id ON document_access_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_access_sessions_document_id ON document_access_sessions(document_id);
CREATE INDEX IF NOT EXISTS idx_access_sessions_ephemeral_did ON document_access_sessions(ephemeral_did);
CREATE INDEX IF NOT EXISTS idx_access_sessions_session_token ON document_access_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_access_sessions_expires_at ON document_access_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_sessions_user_identity ON document_access_sessions(user_identity_hash);
CREATE INDEX IF NOT EXISTS idx_access_sessions_enterprise ON document_access_sessions(enterprise_account_name);

-- Indexes for ephemeral encryption
CREATE INDEX IF NOT EXISTS idx_ephemeral_encryption_document_id ON document_ephemeral_encryption(document_id);
CREATE INDEX IF NOT EXISTS idx_ephemeral_encryption_session_id ON document_ephemeral_encryption(access_session_id);
CREATE INDEX IF NOT EXISTS idx_ephemeral_encryption_did ON document_ephemeral_encryption(ephemeral_did);
CREATE INDEX IF NOT EXISTS idx_ephemeral_encryption_expired_at ON document_ephemeral_encryption(expired_at);

-- Indexes for ephemeral audit log
CREATE INDEX IF NOT EXISTS idx_ephemeral_audit_user_id ON ephemeral_did_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_ephemeral_audit_document_id ON ephemeral_did_audit_log(document_id);
CREATE INDEX IF NOT EXISTS idx_ephemeral_audit_action ON ephemeral_did_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_ephemeral_audit_session_token ON ephemeral_did_audit_log(session_token);
CREATE INDEX IF NOT EXISTS idx_ephemeral_audit_time ON ephemeral_did_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_ephemeral_audit_user_identity ON ephemeral_did_audit_log(user_identity_hash);

-- =====================================================================================
-- EPHEMERAL DID HELPER FUNCTIONS
-- =====================================================================================

-- Function to validate ephemeral DID format
CREATE OR REPLACE FUNCTION validate_ephemeral_did_format(ephemeral_did VARCHAR(500))
RETURNS BOOLEAN AS $$
BEGIN
    -- Check if DID follows did:key format
    RETURN ephemeral_did ~ '^did:key:z[A-Za-z0-9]+$';
END;
$$ LANGUAGE plpgsql;

-- Function to check for ephemeral DID reuse
CREATE OR REPLACE FUNCTION check_ephemeral_did_reuse(ephemeral_did VARCHAR(500), hours_window INTEGER DEFAULT 24)
RETURNS BOOLEAN AS $$
DECLARE
    reuse_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO reuse_count
    FROM document_access_sessions 
    WHERE ephemeral_did = ephemeral_did 
    AND created_at > NOW() - (hours_window || ' hours')::INTERVAL;
    
    RETURN reuse_count > 0;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup expired ephemeral sessions
CREATE OR REPLACE FUNCTION cleanup_expired_ephemeral_sessions()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    -- Count expired sessions first
    SELECT COUNT(*)
    INTO expired_count
    FROM document_access_sessions 
    WHERE expires_at < NOW() AND completed_at IS NULL;
    
    -- Mark expired sessions as completed
    UPDATE document_access_sessions 
    SET completed_at = NOW()
    WHERE expires_at < NOW() AND completed_at IS NULL;
    
    -- Log cleanup operation
    INSERT INTO ephemeral_did_audit_log (
        action, success, error_details, created_at
    ) VALUES (
        'session_cleanup', true, 'Cleaned up ' || expired_count || ' expired sessions', NOW()
    );
    
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get user's active ephemeral sessions
CREATE OR REPLACE FUNCTION get_user_active_ephemeral_sessions(user_identity_hash VARCHAR(64))
RETURNS TABLE (
    session_id INTEGER,
    document_id INTEGER,
    ephemeral_did VARCHAR(500),
    session_token VARCHAR(64),
    classification_level INTEGER,
    expires_at TIMESTAMP,
    created_at TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        das.id,
        das.document_id,
        das.ephemeral_did,
        das.session_token,
        das.classification_level,
        das.expires_at,
        das.created_at
    FROM document_access_sessions das
    WHERE das.user_identity_hash = user_identity_hash
    AND das.expires_at > NOW()
    AND das.completed_at IS NULL
    ORDER BY das.created_at DESC;
END;
$$ LANGUAGE plpgsql;

-- =====================================================================================
-- EPHEMERAL DID TRIGGERS
-- =====================================================================================

-- Trigger to validate ephemeral DID format on insert/update
CREATE OR REPLACE FUNCTION validate_ephemeral_did_trigger()
RETURNS TRIGGER AS $$
BEGIN
    IF NOT validate_ephemeral_did_format(NEW.ephemeral_did) THEN
        RAISE EXCEPTION 'Invalid ephemeral DID format: %', NEW.ephemeral_did;
    END IF;
    
    -- Log DID generation
    INSERT INTO ephemeral_did_audit_log (
        user_id, user_identity_hash, enterprise_account_name, document_id,
        ephemeral_did, action, classification_level, session_token, success
    ) VALUES (
        NEW.user_id, NEW.user_identity_hash, NEW.enterprise_account_name, NEW.document_id,
        NEW.ephemeral_did, 'did_generated', NEW.classification_level, NEW.session_token, true
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER validate_ephemeral_did_on_insert 
    BEFORE INSERT ON document_access_sessions
    FOR EACH ROW EXECUTE FUNCTION validate_ephemeral_did_trigger();

-- =====================================================================================
-- COMPLETION MESSAGE
-- =====================================================================================

DO $$
BEGIN
    RAISE NOTICE '=================================================================================';
    RAISE NOTICE 'Classification Document System Database - WP1 + WP3 - INITIALIZED!';
    RAISE NOTICE '=================================================================================';
    RAISE NOTICE 'Enterprise Account System (WP1):';
    RAISE NOTICE '  ✓ Enterprise accounts with corporate control';
    RAISE NOTICE '  ✓ Cryptographic identity generation with enterprise salt';
    RAISE NOTICE '  ✓ Registration Authority recovery capabilities';
    RAISE NOTICE '';
    RAISE NOTICE 'Two-Stage Credential System (WP1):';
    RAISE NOTICE '  ✓ Enterprise credentials (foundation access)';
    RAISE NOTICE '  ✓ Classification credentials (document control)';
    RAISE NOTICE '  ✓ Approval workflow with business justification';
    RAISE NOTICE '';
    RAISE NOTICE 'Document Classification Control (WP1):';
    RAISE NOTICE '  ✓ Classification-based upload restrictions';
    RAISE NOTICE '  ✓ Exact-level access control (no hierarchical access)';
    RAISE NOTICE '  ✓ Comprehensive access logging';
    RAISE NOTICE '';
    RAISE NOTICE 'Ephemeral DID-Based Document Encryption (WP3):';
    RAISE NOTICE '  ✓ Ephemeral DID session tracking';
    RAISE NOTICE '  ✓ Client-side key generation support';
    RAISE NOTICE '  ✓ Perfect forward secrecy architecture';
    RAISE NOTICE '  ✓ Session expiration and cleanup';
    RAISE NOTICE '  ✓ DID format validation and reuse prevention';
    RAISE NOTICE '  ✓ Comprehensive ephemeral access auditing';
    RAISE NOTICE '';
    RAISE NOTICE 'Tables Created:';
    RAISE NOTICE '  WP1 Tables:';
    RAISE NOTICE '  • enterprise_accounts - Corporate control foundation';
    RAISE NOTICE '  • users - Enhanced with cryptographic identity';
    RAISE NOTICE '  • credential_requests - Two-stage request workflow'; 
    RAISE NOTICE '  • issued_credentials - Comprehensive credential tracking';
    RAISE NOTICE '  • documents - Classification-controlled document storage';
    RAISE NOTICE '  • document_access_log - Access attempt auditing';
    RAISE NOTICE '  • credential_audit_log - Credential operation auditing';
    RAISE NOTICE '  • credential_recovery_requests - Enterprise recovery system';
    RAISE NOTICE '  • audit_logs - Comprehensive system auditing';
    RAISE NOTICE '';
    RAISE NOTICE '  WP3 Tables:';
    RAISE NOTICE '  • document_access_sessions - Ephemeral DID session tracking';
    RAISE NOTICE '  • document_ephemeral_encryption - Ephemeral encryption metadata';
    RAISE NOTICE '  • ephemeral_did_audit_log - Ephemeral access auditing';
    RAISE NOTICE '';
    RAISE NOTICE 'Helper Functions:';
    RAISE NOTICE '  WP1 Functions:';
    RAISE NOTICE '  • get_user_max_classification_level()';
    RAISE NOTICE '  • can_user_classify_at_level()';
    RAISE NOTICE '  • can_user_access_level()';
    RAISE NOTICE '';
    RAISE NOTICE '  WP3 Functions:';
    RAISE NOTICE '  • validate_ephemeral_did_format()';
    RAISE NOTICE '  • check_ephemeral_did_reuse()';
    RAISE NOTICE '  • cleanup_expired_ephemeral_sessions()';
    RAISE NOTICE '  • get_user_active_ephemeral_sessions()';
    RAISE NOTICE '';
    RAISE NOTICE 'Sample Data:';
    RAISE NOTICE '  • 3 enterprise accounts (DEFAULT_ENTERPRISE, ACME_CORP, TECH_DIVISION)';
    RAISE NOTICE '  • 3 sample users with enterprise account structure';
    RAISE NOTICE '  • Sample credential requests and issued credentials';
    RAISE NOTICE '=================================================================================';
END $$;