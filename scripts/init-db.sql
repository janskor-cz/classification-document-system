-- Database initialization script for Classification Document System

-- Create database users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(200) UNIQUE NOT NULL,
    department VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create applications table for credential requests
CREATE TABLE IF NOT EXISTS applications (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    name VARCHAR(200) NOT NULL,
    email VARCHAR(200) NOT NULL,
    specialization VARCHAR(100),
    experience_level VARCHAR(50),
    qualifications TEXT[],
    status VARCHAR(20) DEFAULT 'pending',
    submitted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_date TIMESTAMP NULL,
    denied_date TIMESTAMP NULL,
    denial_reason TEXT NULL,
    labeler_id VARCHAR(50) UNIQUE,
    real_credential BOOLEAN DEFAULT FALSE,
    credential_id VARCHAR(100) NULL,
    invitation_url TEXT NULL,
    processed_by VARCHAR(100) NULL
);

-- Create documents table for classified documents
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    classification_level VARCHAR(20) NOT NULL CHECK (classification_level IN ('public', 'internal', 'confidential')),
    encrypted BOOLEAN DEFAULT FALSE,
    encryption_key_id VARCHAR(100) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100) NOT NULL,
    details JSONB NULL,
    ip_address INET NULL,
    user_agent TEXT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create credentials table to track issued credentials
CREATE TABLE IF NOT EXISTS credentials (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    credential_type VARCHAR(50) NOT NULL,
    credential_id VARCHAR(100) UNIQUE NOT NULL,
    did VARCHAR(500) NOT NULL,
    schema_uri VARCHAR(500) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    revoked_at TIMESTAMP NULL,
    revocation_reason TEXT NULL
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_applications_user_id ON applications(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_classification ON documents(classification_level);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);

-- Insert sample data for testing
INSERT INTO users (username, email, department) VALUES 
    ('john_doe', 'john.doe@company.com', 'Engineering'),
    ('jane_smith', 'jane.smith@company.com', 'Data Science'),
    ('admin_user', 'admin@company.com', 'Administration')
ON CONFLICT (username) DO NOTHING;

-- Insert sample applications for testing
INSERT INTO applications (
    user_id, name, email, specialization, experience_level, 
    qualifications, status, labeler_id
) VALUES 
    (1, 'John Doe', 'john.doe@company.com', 'Image Classification', 'Advanced', 
     ARRAY['Computer Vision', 'Machine Learning'], 'pending', 'LAB' || extract(epoch from now())::bigint),
    (2, 'Jane Smith', 'jane.smith@company.com', 'Text Annotation', 'Expert', 
     ARRAY['NLP', 'Deep Learning'], 'approved', 'LAB' || (extract(epoch from now())::bigint + 1))
ON CONFLICT (labeler_id) DO NOTHING;

-- Create a function to update timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_documents_updated_at BEFORE UPDATE ON documents 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO identus_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO identus_user;

-- Completion message
DO $$
BEGIN
    RAISE NOTICE 'Classification Document System database initialized successfully!';
    RAISE NOTICE 'Created tables: users, applications, documents, audit_logs, credentials';
    RAISE NOTICE 'Sample data inserted for testing';
END $$;