# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Classification Document System** - a comprehensive Flask-based web application that integrates with Hyperledger Identus for advanced credential management and document classification. The system features a complete Self-Sovereign Identity (SSI) workflow with admin approval processes, supports three classification levels (public, internal, confidential), and provides professional Verifiable Credential management with W3C compliance.

## Key Commands

### Starting the Application

**Complete Multi-Agent Setup (Recommended)**:
```bash
# 1. Setup PostgreSQL database with all required databases and users
./scripts/setup-database.sh

# 2. Setup all 3 Identus agents (issuer, holder, verifier) with vault containers
./scripts/setup-agents.sh

# 3. Start Flask application (full SSI functionality available)
python app.py
```

**Alternative Method (Database Only)**:
```bash
# Start supporting services only  
docker-compose up -d postgres redis

# Start Flask application (basic functionality without credential issuance)
python app.py
```

**Environment Setup**:
```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env
# Edit .env with your specific settings
```

### Database Operations

```bash
# Initialize database (PostgreSQL via Docker Compose)
docker-compose exec postgres psql -U identus_user -d identus_db -f /docker-entrypoint-initdb.d/init-db.sql

# Connect to database
docker-compose exec postgres psql -U identus_user -d identus_db
```

### Python Dependencies

```bash
# Install dependencies
pip install -r requirements.txt

# Recommended: Use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
```

### Service Health Checks

```bash
# Check Flask application
curl http://localhost:5000/health

# Check Identus Issuer Agent (if running)
curl http://localhost:8080/_system/health

# Check agent status
./scripts/check-identus-status.sh
```

### Managing Identus Multi-Agent System

```bash
# Start complete 3-agent system (issuer, holder, verifier)
./scripts/setup-agents.sh

# Check system status
./scripts/setup-agents.sh status

# Stop and cleanup all agents and vaults
./scripts/setup-agents.sh cleanup

# Health checks for individual agents
curl http://localhost:8080/_system/health  # Issuer
curl http://localhost:7000/_system/health  # Holder  
curl http://localhost:9000/_system/health  # Verifier
```

## 🚀 New Features & Comprehensive SSI System

### 🔐 Complete Admin Panel & User Management

**Admin Authentication & Access Control**:
- **Secure Role-Based Access**: Only users with specific job titles or email patterns can access admin functions
- **Admin Panel URL**: `/admin` - comprehensive interface for managing credential requests
- **Navigation Integration**: Admin link appears only for authorized users
- **Multi-level Security**: Both route-level and API-level permission checks

**Admin Capabilities**:
- **View Pending Requests**: See all credential requests awaiting approval with user details
- **Approve/Deny Workflow**: One-click approval or denial with reason tracking
- **Real-time Statistics**: Pending requests count, unique users, high-level requests
- **Audit Trail**: Complete logging of all admin actions with timestamps

### 📋 Enhanced Dashboard & Credential Management

**Professional Credential Display**:
- **Complete Verifiable Credential Viewer**: Expandable cards showing full W3C-compliant VC JSON
- **Smart VC Fallback System**: Creates realistic mock VCs from database data when real VCs unavailable
- **Interactive Features**: Copy-to-clipboard, JSON formatting, visual indicators for real vs demo VCs
- **Expiration Management**: Color-coded expiration warnings (red for <7 days, yellow for <30 days)

**Credential Request System**:
- **User-Friendly Request Form**: Integrated into dashboard with classification level selection
- **Business Justification Required**: Ensures proper documentation for all requests
- **Department Approval Workflow**: Optional department approver field
- **Real-time Feedback**: Success/error messages with automatic dashboard refresh

### 🎯 Complete SSI Workflow Implementation

**Request → Approval → Issuance Pipeline**:
1. **User Request**: Submit credential request through dashboard form
2. **Admin Review**: Admin views request details and business justification
3. **Approval Decision**: One-click approve/deny with automatic processing
4. **Credential Issuance**: Automatic creation of issued credential upon approval
5. **User Notification**: New credential appears in user's dashboard immediately

**Credential Types Supported**:
- **Enterprise Access** (Level 0): Basic enterprise system access
- **Public Classification** (Level 1): Public document handling permissions
- **Internal Classification** (Level 2): Internal document access rights
- **Confidential Classification** (Level 3): Highest security clearance level

### 🔧 Technical Enhancements & Security

**Authentication System Improvements**:
- **Working Login Credentials**: All sample users have functional bcrypt-hashed passwords
- **Identity Hash System**: Cryptographic identity generation using enterprise account salt
- **Session Management**: Proper user session handling with authentication state

**Database & API Enhancements**:
- **Complete CRUD Operations**: Full create, read, update, delete for all credential operations
- **Audit Logging**: Comprehensive tracking of all system operations for compliance
- **Error Handling**: Robust error handling with user-friendly messages
- **Performance Optimization**: Efficient database queries with proper indexing

### 📱 User Experience & Interface

**Modern UI Components**:
- **Responsive Design**: Works seamlessly on desktop and mobile devices
- **Professional Styling**: Clean, corporate-grade interface with Bootstrap 5
- **Interactive Elements**: Smooth animations, loading states, and visual feedback
- **Accessibility**: Proper ARIA labels, keyboard navigation, and screen reader support

**Dashboard Features**:
- **Real-time Stats**: Live credential counts, document access metrics, security scores
- **Quick Actions**: Fast access to common operations (upload documents, request credentials)
- **Recent Activity**: Timeline of user actions and system events

## 🔑 Login Credentials (Updated)

### Admin Users (Full Admin Panel Access)
- **Email**: `admin@company.com`
- **Password**: `admin123`
- **Role**: System Administrator
- **Access**: ✅ Complete admin panel, credential approval, user management

### Regular Users (Standard Dashboard Access)
- **John Doe** (Senior Developer)
  - Email: `john.doe@company.com`
  - Password: `john123`
  - Department: Engineering

- **Jane Smith** (Data Scientist)
  - Email: `jane.smith@company.com` 
  - Password: `jane123`
  - Department: Data Science

### Quick Start for Testing
1. **Login as Admin**: Use admin credentials to access admin panel
2. **View Pending Requests**: See credential requests from sample users
3. **Test Approval Process**: Approve/deny requests and see real-time updates
4. **Switch Users**: Login as regular users to see approved credentials
5. **Request New Credentials**: Test the complete request → approval workflow

## Architecture Overview

### Core Components

1. **Flask Web Application** (`app.py`) - Main web server with HTML templates and REST API endpoints
2. **Configuration Management** (`config.py`) - Environment-aware configuration using dataclasses with support for development/testing/production environments
3. **Identus Integration** (`identus_wrapper.py`) - Wrapper for Hyperledger Identus credential operations with auto-detection of GitHub Codespaces vs local environments
4. **Frontend** (`frontend/`) - HTML templates with Bootstrap UI and vanilla JavaScript

### Application Architecture

**Request Flow**:
- HTTP requests → Flask routes in `app.py` 
- Configuration loaded via `config.py` with environment-specific settings
- Identus operations handled by `identus_wrapper.py` 
- Templates rendered from `frontend/templates/` with static assets from `frontend/static/`
- Database operations use raw SQL migrations from `scripts/init-db.sql`

**State Management**:
- Application data stored in global `applications_db` list (loads from Identus on startup)
- User session simulated via `current_user` dict (production should implement proper auth)
- Configuration managed through environment-aware Config class with dataclass sections
- Real-time Identus integration with fallback to mock data when agents unavailable

### Key Directories

- `frontend/templates/` - Jinja2 HTML templates
  - `base.html` - Main layout with admin navigation
  - `dashboard.html` - Enhanced user dashboard with VC viewer and request form
  - `admin/credential-requests.html` - Complete admin panel for credential management
  - `documents/upload.html` - Document upload interface
- `frontend/static/` - CSS and JavaScript assets  
- `scripts/` - Database initialization and Identus setup scripts
- `logs/` - Application and audit logs (created at runtime)
- `uploads/` - Document storage (created at runtime)

### Key Endpoints & Features

**User Routes**:
- `/` - Enhanced dashboard with VC viewer and credential request form
- `/login` - User authentication
- `/documents/upload` - Document upload with classification

**Admin Routes**:
- `/admin` - **NEW**: Complete admin panel for credential management
- `/api/admin/credential-requests/<id>` - **NEW**: Approve/deny credential requests

**API Endpoints**:
- `/api/credentials/request` - **NEW**: Submit credential requests
- `/api/identus/status` - Identus system health check
- `/api/applications` - Legacy application management

### Database Schema

The system uses PostgreSQL with these main tables:
- `users` - User accounts and profiles
- `applications` - Credential applications and approval workflow
- `documents` - Classified document metadata
- `credentials` - Issued Identus credentials tracking
- `audit_logs` - Security and access audit trail

### Identus Multi-Agent Integration

**COMPLETE SSI SYSTEM**: Full 3-Agent Setup
- **Issuer Agent** (port 8080) - Issues verifiable credentials to approved data labelers
- **Holder Agent** (port 7000) - Manages user DIDs and credential wallets
- **Verifier Agent** (port 9000) - Verifies credentials for access control and document classification

**Service Endpoints**:
- **Issuer HTTP**: `http://localhost:8080` | **DIDComm**: `http://localhost:8090`
- **Holder HTTP**: `http://localhost:7000` | **DIDComm**: `http://localhost:7001`  
- **Verifier HTTP**: `http://localhost:9000` | **DIDComm**: `http://localhost:9001`

**Infrastructure Requirements**:
- **PostgreSQL**: Agent-specific databases (`issuer_identus_db`, `holder_identus_db`, `verifier_identus_db`) plus global databases (`pollux`, `connect`, `agent`, `node_db`)
- **Vault Services**: Individual vault containers for secure key management (ports 8200, 7200, 9200)
- **Global Users**: `pollux-application-user`, `connect-application-user`, `agent-application-user` required by all agents
- **Host Networking**: Required for proper agent connectivity and vault communication

Credentials are issued with a custom schema for data labeler certification containing fields like `fullName`, `email`, `specialization`, `experienceLevel`, and `labelerID`.

## Configuration

### Environment Configuration

The application uses environment-based configuration with three modes:
- `development` - Local development with SQLite, debug enabled
- `testing` - In-memory database, minimal logging  
- `production` - PostgreSQL, security hardening, audit logging

### Key Environment Variables

Copy `.env.example` to `.env` and configure:
- `FLASK_ENV` - Environment mode (development/testing/production)
- `DATABASE_URL` - Database connection string (defaults to SQLite for dev, PostgreSQL for production)
- `SECRET_KEY` / `JWT_SECRET_KEY` - Security keys for sessions/tokens (auto-generated if not provided)
- `IDENTUS_ISSUER_URL` - Identus issuer agent endpoint (http://localhost:8080/cloud-agent)
- `IDENTUS_HOLDER_URL` - Holder agent endpoint (http://localhost:7000/cloud-agent)
- `IDENTUS_VERIFIER_URL` - Verifier agent endpoint (http://localhost:9000/cloud-agent)
- `UPLOAD_FOLDER` - Document storage location (defaults to 'uploads')
- `MAX_FILE_SIZE` - Maximum document upload size (defaults to 100MB)
- `CODESPACES` - Auto-detected in GitHub Codespaces for environment configuration

**Important**: The `.env.example` file contains comprehensive configuration options with documentation for each setting.

### Classification Levels

The system supports three document classification levels:
- `public` (level 1) - Public access
- `internal` (level 2) - Internal company use
- `confidential` (level 3) - Restricted access

## Development Workflows

### Starting Development Environment

**Recommended Full-Stack Approach**:
1. **Setup Database**: `./scripts/setup-database.sh` (includes all required user accounts)
2. **Setup Identus Agents**: `./scripts/setup-agents.sh` (complete 3-agent SSI system)
3. **Start Flask App**: `python app.py`
4. **Access Application**: http://localhost:5000
5. **Test Admin Panel**: Login as `admin@company.com` / `admin123` → Click "Admin"
6. **Test User Experience**: Login as `john.doe@company.com` / `john123` → Request credentials

**Alternative Approach** (Database Only):
1. Start supporting services: `docker-compose up -d postgres redis`
2. Initialize database: `sudo docker exec -i identus-postgres psql -U postgres -d identus_db < scripts/init-db.sql`
3. Run Flask app: `python app.py` (basic functionality with mock VCs)

### Database Migrations

The system uses raw SQL migrations in `scripts/init-db.sql`. For schema changes:
1. Update the SQL script
2. Restart the PostgreSQL container to apply changes
3. Or execute SQL manually via `psql`

### Adding New Features

Key patterns to follow:
- Use environment-aware configuration from `config.py`
- Add audit logging for security-sensitive operations
- Follow Flask blueprint patterns for route organization
- Use the Identus client for credential operations
- Maintain classification level access controls

### Complete Development Workflow

**1. Initial Setup**:
```bash
# Clone and setup environment
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Edit as needed
```

**2. Start Infrastructure**:
```bash
# Start database with all required databases and users
./scripts/setup-database.sh

# Start complete 3-agent SSI system
./scripts/setup-agents.sh

# Verify all services are healthy
curl http://localhost:8080/_system/health  # {"version":"1.33.0"}
curl http://localhost:7000/_system/health  # {"version":"1.33.0"}  
curl http://localhost:9000/_system/health  # {"version":"1.33.0"}
```

**3. Run Application**:
```bash
# Start Flask application with full SSI capabilities
python app.py
# Access at: http://localhost:5000
```

**4. Development Lifecycle**:
```bash
# Check system status anytime
./scripts/setup-agents.sh status

# Stop everything cleanly
./scripts/setup-agents.sh cleanup  # Stops agents and vaults
sudo docker stop identus-postgres  # Stop database when done

# Quick restart
./scripts/setup-database.sh && ./scripts/setup-agents.sh
```

**SSI Development Features Available**:
- **Full Credential Issuance**: Issue verifiable credentials to approved data labelers
- **DID Management**: Complete decentralized identifier lifecycle
- **Verification Workflows**: Verify credentials for document access control
- **Multi-Agent Interactions**: Test complete issuer→holder→verifier flows
- **Production Architecture**: Develop against production-equivalent SSI infrastructure

### Testing and Code Quality

**Note**: No formal testing framework is currently configured. For testing:
- Manual testing via Flask development server
- Use health check endpoints for integration testing
- Test Identus integration via status endpoints

**Code Quality**:
- No linting tools configured (consider adding flake8, black, or pylint)
- Follow PEP 8 conventions manually
- Use type hints where appropriate (some files already use typing module)

### Debugging Identus Issues

**Quick Status Check**:
```bash
# Check agent health
curl http://localhost:8080/_system/health

# Comprehensive status check
./scripts/check-identus-status.sh
```

**Common Troubleshooting**:
- Verify Issuer agent is healthy: `curl http://localhost:8080/_system/health`
- Check agent initialization status via `/api/identus/status`
- Use `/api/identus/reinitialize` to reset connection
- Check Docker container logs: `sudo docker logs issuer-agent`
- Restart agent: `./scripts/setup-issuer-only.sh`

**Known Issues & Solutions**:
- **Port conflicts**: Ensure ports 8080, 8090, 8200, 5432 are free
- **Slow startup**: Agent can take 30-60 seconds to be ready
- **Host networking**: Required - custom Docker networks don't work
- **Multiple databases**: Agent requires `pollux`, `connect`, `agent`, `node_db` databases
- **Vault required**: Agent needs Vault for secrets management
- **GitHub Codespaces**: System auto-detects Codespaces environment and configures accordingly
- **Configuration URLs**: Use port 8080 for agent HTTP, port 8090 for DIDComm
- **Database connection**: Flask app can run without Identus; only credential operations require working agent

## Security Considerations

- Document uploads are validated by file type and size
- Classification levels enforce access control
- All credential operations are audited
- Secret keys should be rotated regularly
- Database credentials are managed via environment variables
- CORS is configured for local development origins

## Important Notes

### Identus Setup - PROVEN WORKING CONFIGURATION

The current working setup uses:

1. **Single Issuer Agent**: Only the issuer agent is fully working and tested
2. **Host Networking**: Docker host networking mode is required
3. **Multiple PostgreSQL Databases**: `identus_db`, `pollux`, `connect`, `agent`, `node_db`
4. **Multiple Database Users**: `postgres`, `pollux-application-user`, `connect-application-user`, `agent-application-user`, `identus_user`
5. **Vault Integration**: HashiCorp Vault in development mode with root token
6. **Version**: Hyperledger Identus Cloud Agent 1.33.0 (proven stable)

### Multi-Agent System Architecture

**Required Containers**:
- `identus-postgres` - PostgreSQL with multiple databases and global users
- `issuer-vault` - Vault in development mode (port 8200)
- `holder-vault` - Vault in development mode (port 7200)  
- `verifier-vault` - Vault in development mode (port 9200)
- `issuer-agent` - Identus Cloud Agent (ports 8080, 8090)
- `holder-agent` - Identus Cloud Agent (ports 7000, 7001)
- `verifier-agent` - Identus Cloud Agent (ports 9000, 9001)

**Database Structure**:
- **Agent Databases**: `issuer_identus_db`, `holder_identus_db`, `verifier_identus_db`
- **Global Databases**: `pollux`, `connect`, `agent`, `node_db`, `identus_db`
- **Global Users**: `pollux-application-user`, `connect-application-user`, `agent-application-user` 
- **Agent Users**: `issuer_user`, `holder_user`, `verifier_user`

**Port Allocation**:
```
Database:     5432
Issuer:       8080 (HTTP), 8090 (DIDComm), 8200 (Vault)
Holder:       7000 (HTTP), 7001 (DIDComm), 7200 (Vault)
Verifier:     9000 (HTTP), 9001 (DIDComm), 9200 (Vault)
```

### Script Locations

**Essential Scripts** in `./scripts/`:
- `setup-database.sh` - **REQUIRED FIRST** - PostgreSQL database setup with health checks
- `populate-database.sh` - Database population with Identus-specific databases and users
- `setup-agents.sh` - **MAIN SCRIPT** - Complete Identus agents setup (issuer, holder, verifier)
- `init-db.sql` - PostgreSQL schema for Flask application tables

**Usage Workflow**:
```bash
# 1. Setup database first (required)
./scripts/setup-database.sh

# 2. Setup all Identus agents (issuer, holder, verifier)
./scripts/setup-agents.sh

# Management commands
./scripts/setup-agents.sh status         # Check current status
./scripts/setup-agents.sh cleanup        # Stop and remove all agents
```

**What Each Script Does**:
- `setup-database.sh`: Creates PostgreSQL container with health checks and basic database setup
- `populate-database.sh`: Creates all agent databases, global users, and grants proper privileges automatically
- `setup-agents.sh`: **COMPLETE SSI SYSTEM** - Starts all 3 agents with dedicated vaults, includes global user validation
- `init-db.sql`: PostgreSQL schema for Flask application tables (users, applications, documents, credentials, audit_logs)

**Advanced Features**:
- **Auto-Detection**: Scripts automatically detect missing global users and run population as needed
- **Error Recovery**: Built-in validation and self-healing capabilities
- **Health Monitoring**: Comprehensive health checks for all services with retry logic
- **Status Reporting**: Detailed status information for troubleshooting and monitoring

### Complete Multi-Agent SSI System

The scripts provide a full Self-Sovereign Identity infrastructure:

1. **Production-Ready Architecture**: Complete issuer-holder-verifier triangle for full SSI workflows
2. **Robust Database Management**: Automatic creation of all required databases and global users that agents expect
3. **Sequential Startup**: Agents start individually to prevent database initialization conflicts
4. **Comprehensive Health Monitoring**: Multi-level health checks for agents, vaults, and database connectivity
5. **Host Network Optimization**: Uses proven host networking for optimal performance and connectivity
6. **Automatic Error Recovery**: Scripts detect missing users/databases and auto-populate as needed
7. **Easy Management**: Simple commands for complete system lifecycle management

**Key Features**:
- **3-Agent Setup**: Full SSI triangle (issuer → holder ← verifier)
- **Isolated Vault Security**: Each agent has dedicated vault for key management
- **Global User Management**: Automatically creates `pollux-application-user`, `connect-application-user`, `agent-application-user`  
- **Self-Healing**: Detects configuration issues and automatically runs population scripts
- **Production Ready**: Suitable for development, testing, and production deployments