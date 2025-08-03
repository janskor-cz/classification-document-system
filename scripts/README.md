# Hyperledger Identus Agent Scripts

This directory contains scripts for managing Hyperledger Identus Cloud Agents based on the official documentation.

## Scripts Overview

### 🚀 `setup-identus-agents.sh`
**Purpose**: Sets up and starts all three Identus agents (Issuer, Holder, Verifier)

**Features**:
- Auto-detects platform (macOS/Linux)
- Downloads official Identus Cloud Agent repository
- Creates proper environment configurations
- Starts agents with health checks
- Uses latest stable version (1.40.0)

**Usage**:
```bash
./scripts/setup-identus-agents.sh
```

### 🛑 `stop-identus-agents.sh`
**Purpose**: Stops all running Identus agents and cleans up resources

**Features**:
- Gracefully stops all agents
- Removes Docker containers
- Cleans up network resources
- Provides status confirmation

**Usage**:
```bash
./scripts/stop-identus-agents.sh
```

### 🔍 `check-identus-status.sh`
**Purpose**: Comprehensive health check for all Identus agents

**Features**:
- Health endpoint monitoring
- Docker container status
- Network connectivity tests
- API endpoint validation
- Detailed status reporting

**Usage**:
```bash
./scripts/check-identus-status.sh
```

## Quick Start

1. **Start all agents**:
   ```bash
   ./scripts/setup-identus-agents.sh
   ```

2. **Check status**:
   ```bash
   ./scripts/check-identus-status.sh
   ```

3. **Stop all agents**:
   ```bash
   ./scripts/stop-identus-agents.sh
   ```

## Agent Endpoints

Once running, the agents will be available at:

- **Issuer Agent**: `http://localhost:8000/cloud-agent`
- **Holder Agent**: `http://localhost:7000/cloud-agent`
- **Verifier Agent**: `http://localhost:9000/cloud-agent`

## Health Check URLs

- **Issuer**: `http://localhost:8000/_system/health`
- **Holder**: `http://localhost:7000/_system/health`
- **Verifier**: `http://localhost:9000/_system/health`

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 7000, 8000, 9000 are free
2. **Docker issues**: Make sure Docker is running
3. **Network problems**: Check Docker network configuration
4. **Slow startup**: Agents can take 30-60 seconds to be ready

### Debug Commands

```bash
# Check if ports are in use
netstat -ln | grep -E ':(7000|8000|9000) '

# Check Docker containers
docker ps

# Check Docker networks
docker network ls

# View agent logs
docker logs issuer
docker logs holder
docker logs verifier
```

### Alternative Docker Compose

If the scripts don't work, you can fall back to the original docker-compose:

```bash
# Start supporting services only
docker-compose up -d postgres redis

# Then use the scripts for agents
./scripts/setup-identus-agents.sh
```

## Configuration Details

The scripts create environment files with these key settings:

- **Version**: Identus 1.40.0 (latest stable)
- **Network**: Custom Docker network for isolation
- **Database**: Separate PostgreSQL ports for each agent
- **Security**: API keys disabled for development
- **Endpoints**: Proper local IP detection for connectivity

## Prerequisites

- Docker Desktop installed and running
- Git installed
- macOS or Linux (Windows requires WSL)
- At least 4GB RAM available for Docker
- Ports 7000, 7001, 8000, 8001, 9000, 9001 available

## Based on Official Documentation

These scripts follow the official Hyperledger Identus documentation:
- https://hyperledger-identus.github.io/docs/
- https://github.com/hyperledger/identus-cloud-agent