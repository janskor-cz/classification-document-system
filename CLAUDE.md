# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Classification Document System** - a comprehensive Flask-based web application that integrates with Hyperledger Identus for advanced credential management and document classification. The system features a complete Self-Sovereign Identity (SSI) workflow with admin approval processes, supports three classification levels (public, internal, confidential), and provides professional Verifiable Credential management with W3C compliance.

## Key Commands

### Starting the Application

**🚀 MAIN STARTUP SCRIPT (Recommended)**:
```bash
# Complete system startup with all components
./start.sh

# This single command handles:
# - Python virtual environment setup
# - PostgreSQL database with proper configuration (max_connections=300)
# - All 3 Identus agents (issuer, holder, verifier) with vault containers
# - Flask application with full SSI functionality
# - Health checks and status monitoring
```

**Other Start Options**:
```bash
./start.sh quick     # Start Flask app only (requires existing setup)
./start.sh database  # Setup PostgreSQL database only
./start.sh agents    # Setup Identus agents only
./start.sh status    # Show current system status
./start.sh cleanup   # Stop and remove all services
./start.sh help      # Show help with all options
```

**Manual Setup Method**:
```bash
# 1. Setup PostgreSQL database with all required databases and users
./scripts/setup-database.sh

# 2. Setup all 3 Identus agents (issuer, holder, verifier) with vault containers
./scripts/setup-agents.sh

# 3. Start Flask application (full SSI functionality available)
python app.py
```

**Docker Compose Method**:
```bash
# Start all services using Docker Compose
docker-compose up -d

# Start Flask application
python app.py
```

### Environment Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your specific settings
```

### Service Health Checks

```bash
# Check Flask application
curl http://localhost:5000/health

# Check Identus Agents
curl http://localhost:8080/_system/health  # Issuer
curl http://localhost:7000/_system/health  # Holder  
curl http://localhost:9000/_system/health  # Verifier

# Check agent status
./scripts/check-identus-status.sh
```

## 🚀 Multi-Tenant Architecture

### Enterprise-Based Multi-Tenancy

The system implements Hyperledger Identus multi-tenancy with enterprise-based agent routing, supporting multiple cloud agents and tenant isolation.

**Multi-Agent Configuration**:
- **Primary Agent Cluster**: Production agents (ports 8080, 7000, 9000)
- **Secondary Agent Cluster**: Backup/DR agents (ports 8081, 7001, 9001) 
- **Enterprise-Specific Agents**: Government/specialized agents (port 8082)

**Enterprise Accounts**:
- **DEFAULT_ENTERPRISE**: Basic classification levels (public, internal)
- **ENTERPRISE_A**: Full classification access (public, internal, confidential)
- **ENTERPRISE_B**: Business-focused access (public, internal)
- **GOVERNMENT_AGENCY**: Maximum security levels (public, internal, confidential, restricted)

**Security Features**:
- API Key Authentication with SHA-256 hashing
- Tenant ID separation and isolated wallets
- Enterprise-specific agent routing with fallback chains
- Classification-based access control per enterprise

### Multi-Tenant API Endpoints

**Agent Management**:
- `GET /api/multi-tenant/agents/status` - Health status of all agents
- `GET /api/multi-tenant/enterprises/status` - Enterprise configuration
- `GET /api/multi-tenant/test/connectivity` - Connectivity testing

**Enterprise Operations**:
- `POST /api/multi-tenant/enterprise/set` - Set enterprise context
- `POST /api/multi-tenant/credential/issue` - Issue credentials with tenant isolation
- `POST /api/multi-tenant/credential/verify` - Verify credentials within tenant

**Admin Interface**:
- `/admin/multi-tenant` - Multi-tenant administration dashboard
- Real-time agent health monitoring
- Enterprise configuration management
- Interactive operations testing

## 🔐 Features & SSI System

### Admin Panel & User Management

- **Admin Panel**: `/admin` - Complete credential request management
- **Role-Based Access**: Secure authentication for admin functions
- **Approval Workflow**: One-click approve/deny with audit trail
- **Real-time Statistics**: Pending requests, user metrics, activity tracking

### Credential Management

- **W3C-Compliant VCs**: Full Verifiable Credential support
- **Request System**: Dashboard-integrated credential requests
- **Business Justification**: Required documentation for requests
- **Expiration Management**: Color-coded warnings and notifications

### SSI Workflow

1. **User Request**: Submit credential request via dashboard
2. **Admin Review**: Review request with business justification
3. **Approval Decision**: One-click approve/deny
4. **Credential Issuance**: Automatic credential creation
5. **User Notification**: Immediate dashboard update

**Credential Types**:
- **Enterprise Access** (Level 0): Basic system access
- **Public Classification** (Level 1): Public document permissions
- **Internal Classification** (Level 2): Internal document access
- **Confidential Classification** (Level 3): Highest security level

## 📋 Login Credentials

### Admin Users
- **Email**: `admin@company.com`
- **Password**: `admin123`
- **Access**: Full admin panel, credential approval, user management

### Regular Users
- **John Doe**: `john.doe@company.com` / `john123` - Engineering
- **Jane Smith**: `jane.smith@company.com` / `jane123` - Data Science

## Architecture

### Core Components

1. **Flask Application** (`app.py`) - Main web server and API endpoints
2. **Configuration** (`config.py`) - Environment-aware configuration
3. **Identus Integration** (`identus_wrapper.py`) - Hyperledger Identus wrapper
4. **Multi-Tenant Manager** (`multi_tenant_identus.py`) - Enterprise routing and isolation
5. **Frontend** (`frontend/`) - HTML templates with Bootstrap UI

### Key Directories

- `frontend/templates/` - Jinja2 HTML templates
  - `base.html` - Main layout with navigation
  - `dashboard.html` - User dashboard with credentials
  - `admin/` - Admin panel templates
  - `documents/` - Document management interfaces
- `frontend/static/` - CSS and JavaScript assets  
- `scripts/` - Database and agent setup scripts
- `schemas/` - Credential schema definitions
- `logs/` - Application and audit logs
- `uploads/` - Document storage

### Database Schema

PostgreSQL tables:
- `users` - User accounts and profiles
- `applications` - Credential applications and workflow
- `documents` - Classified document metadata
- `credentials` - Issued credentials tracking
- `issued_credentials` - Active credential records
- `audit_logs` - Security and access audit trail
- `ephemeral_sessions` - Temporary access sessions

### Identus Multi-Agent System

**3-Agent SSI Setup**:
- **Issuer Agent** (8080/8090) - Issues verifiable credentials
- **Holder Agent** (7000/7001) - Manages user DIDs and wallets
- **Verifier Agent** (9000/9001) - Verifies credentials for access

**Infrastructure**:
- PostgreSQL with multiple databases and users
- HashiCorp Vault for key management
- Host networking for optimal connectivity
- Automatic health monitoring and recovery

## Configuration

### Environment Variables

Key settings in `.env`:
- `FLASK_ENV` - Environment mode (development/production)
- `DATABASE_URL` - Database connection string
- `SECRET_KEY` - Session security key
- `IDENTUS_ISSUER_URL` - Issuer agent endpoint
- `IDENTUS_HOLDER_URL` - Holder agent endpoint
- `IDENTUS_VERIFIER_URL` - Verifier agent endpoint
- `UPLOAD_FOLDER` - Document storage location
- `MAX_FILE_SIZE` - Maximum upload size

### Classification Levels

- `public` (level 1) - Public access
- `internal` (level 2) - Internal company use
- `confidential` (level 3) - Restricted access

## Development Workflow

### Quick Start

```bash
# 1. Setup database
./scripts/setup-database.sh

# 2. Start agents
./scripts/setup-agents.sh

# 3. Run application
python app.py

# 4. Access at http://localhost:5000
```

### Management Commands

```bash
# Check system status
./scripts/setup-agents.sh status

# Stop and cleanup
./scripts/setup-agents.sh cleanup

# Restart agents
./scripts/setup-database.sh && ./scripts/setup-agents.sh
```

### Testing

- Health endpoints for service monitoring
- Manual testing via Flask development server
- Admin panel for credential workflow testing
- Multi-tenant dashboard for enterprise testing

## Security Considerations

- Document upload validation by file type and size
- Classification levels enforce access control
- All credential operations are audited
- Enterprise isolation with tenant-specific wallets
- API key authentication for enterprise access
- Session management with expiration handling

## Current Implementation Status

### ✅ Working Features
- Complete multi-tenant architecture
- Full SSI workflow (request → approval → issuance)
- Admin panel with approval system
- Enterprise-based agent routing
- Document classification system
- Ephemeral DID sessions
- W3C-compliant Verifiable Credentials

### 🚧 Known Limitations
- DIDComm handshake requires manual connection acceptance
- Real holder wallet integration pending
- WebSocket connectivity for real-time messaging not implemented
- Out-of-band credential delivery in development

## Scripts

### Main Startup Script: `start.sh`
The **primary way to start the entire system**. This comprehensive script handles:
- ✅ Prerequisites checking (Docker, Python)
- ✅ Python virtual environment creation and activation
- ✅ Dependencies installation from requirements.txt
- ✅ PostgreSQL setup with max_connections=300 (prevents connection exhaustion)
- ✅ Database schema initialization
- ✅ Security fixes (proper password hashes, identity hashes)
- ✅ All 3 Identus agents (Issuer on 8080, Holder on 7000, Verifier on 9000)
- ✅ Vault services for each agent (ports 8200, 7200, 9200)
- ✅ Environment configuration (.env file)
- ✅ Flask application startup
- ✅ Health checks and status monitoring

### Supporting Scripts in `./scripts/`:
- `setup-database.sh` - PostgreSQL setup with all databases
- `setup-agents.sh` - Complete 3-agent system setup (called by start.sh)
- `populate-database.sh` - Database initialization
- `init-db.sql` - Application schema (applied by start.sh)

### Script Usage Examples:
```bash
# RECOMMENDED: Use start.sh for everything
./start.sh              # Complete setup and start
./start.sh quick        # Start Flask app only (faster for restarts)
./start.sh status       # Check what's running
./start.sh cleanup      # Stop everything

# Manual approach (if needed)
./scripts/setup-database.sh
./scripts/setup-agents.sh
python app.py

# Agent management
./scripts/setup-agents.sh status         # Check current status
./scripts/setup-agents.sh cleanup        # Stop and remove all agents
```