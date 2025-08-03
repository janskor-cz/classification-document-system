# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Classification Document System** - a Flask-based web application that integrates with Hyperledger Identus for credential management and document classification. The system handles document classification with three levels (public, internal, confidential) and issues verifiable credentials to approved data labelers.

## Key Commands

### Starting the Application

**Working Method (Issuer Agent Only)**:
```bash
# Start Identus Issuer Agent (proven working setup)
./scripts/setup-issuer-only.sh

# Start Flask application (after agent is running)
python app.py
```

**Alternative Method (Full Docker Compose)**:
```bash
# Start supporting services only
docker-compose up -d postgres redis

# Start Flask application (will work without Identus for basic functionality)
python app.py
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

### Managing Identus Agents

```bash
# Start Issuer Agent (WORKING)
./scripts/setup-issuer-only.sh

# Check agent status
./scripts/check-identus-status.sh

# Stop agents
./scripts/stop-identus-agents.sh

# Manual cleanup
sudo docker stop issuer-postgres issuer-vault issuer-agent
sudo docker rm issuer-postgres issuer-vault issuer-agent
```

## Architecture Overview

### Core Components

1. **Flask Web Application** (`app.py`) - Main web server with HTML templates and REST API
2. **Configuration Management** (`config.py`) - Environment-aware configuration with dataclasses
3. **Identus Integration** (`identus_wrapper.py`) - Wrapper for Hyperledger Identus credential operations
4. **Frontend** (`frontend/`) - HTML templates with Bootstrap UI and vanilla JavaScript

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

### Identus Integration

**WORKING SETUP**: Single Identus Issuer Agent
- **Issuer Agent** (port 8080) - Issues credentials to approved labelers
- **Health Check**: `http://localhost:8080/_system/health`
- **DIDComm Endpoint**: `http://localhost:8090`

**Infrastructure Requirements**:
- **PostgreSQL**: Multiple databases (`identus_db`, `pollux`, `connect`, `agent`, `node_db`)
- **Vault**: Development mode for secrets management
- **Host Networking**: Required for proper agent connectivity

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
- `DATABASE_URL` - Database connection string
- `SECRET_KEY` / `JWT_SECRET_KEY` - Security keys for sessions/tokens
- `IDENTUS_ISSUER_URL` - Identus issuer agent endpoint (http://localhost:8080/cloud-agent)
- `UPLOAD_FOLDER` - Document storage location

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

### Key Technical Requirements

**Required Containers**:
- `issuer-postgres` - PostgreSQL with multiple databases and users
- `issuer-vault` - Vault in development mode (port 8200)
- `issuer-agent` - Identus Cloud Agent (ports 8080, 8090)

**Required Environment Variables for Agent**:
```
API_KEY_ENABLED=false
AGENT_VERSION=1.33.0  
PORT=8080
PG_HOST=localhost
PG_PORT=5432
PG_DATABASE=identus_db
PG_USERNAME=postgres
PG_PASSWORD=postgres
VAULT_DEV_ROOT_TOKEN_ID=root
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=root
```

### Script Locations

Working Identus management scripts in `./scripts/`:
- `setup-issuer-only.sh` - **WORKING** - Start Issuer agent with all requirements
- `check-identus-status.sh` - Health check for agents
- `stop-identus-agents.sh` - Stop all agents
- `init-db.sql` - Database initialization for Flask app

### Migration from Docker Compose

The original docker-compose setup had connectivity issues. For Identus functionality:

1. Use the working script: `./scripts/setup-issuer-only.sh`
2. The Flask app works with or without Identus
3. Credential issuance requires the working Identus setup