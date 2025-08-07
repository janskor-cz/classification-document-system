# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Classification Document System** - a Flask-based web application that integrates with Hyperledger Identus for credential management and document classification. The system handles document classification with three levels (public, internal, confidential) and issues verifiable credentials to approved data labelers.

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

- `frontend/templates/` - Jinja2 HTML templates (base.html, dashboard.html, login.html, etc.)
- `frontend/static/` - CSS and JavaScript assets  
- `scripts/` - Database initialization and Identus setup scripts
- `logs/` - Application and audit logs (created at runtime)
- `uploads/` - Document storage (created at runtime)

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

**Recommended Approach**:
1. Start Identus Issuer Agent: `./scripts/setup-issuer-only.sh`
2. Wait for agent to be healthy (script includes health checks)
3. Run Flask app: `python app.py`
4. Access at: http://localhost:5000

**Alternative Approach** (without Identus):
1. Start supporting services: `docker-compose up -d postgres redis`
2. Run Flask app: `python app.py` (basic functionality without credential issuance)

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