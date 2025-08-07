#!/bin/bash

# Hyperledger Identus Multi-Agent Setup Script
# 
# This script sets up a complete 3-agent SSI (Self-Sovereign Identity) infrastructure:
# - Issuer Agent (port 8080) - Issues verifiable credentials
# - Holder Agent (port 7000) - Manages user DIDs and credentials  
# - Verifier Agent (port 9000) - Verifies credentials for access control
#
# Prerequisites:
# - Docker must be installed and running
# - PostgreSQL database container must be running (use ./setup-database.sh)
#
# Architecture:
# - All agents use host networking for optimal connectivity
# - Each agent has dedicated Vault container for secure key management
# - Shared PostgreSQL database with agent-specific schemas
# - Standard Identus users created for all agents
#
# Usage:
#   ./setup-agent.sh          # Start all agents
#   ./setup-agent.sh cleanup  # Stop and remove all containers
#   ./setup-agent.sh status   # Show current status
#
# Example Workflow:
#   1. ./setup-database.sh    # Set up PostgreSQL database
#   2. ./setup-agent.sh       # Set up all 3 agents and vaults
#   3. ./setup-agent.sh status # Verify everything is running
#
# Ports Used:
#   8080 - Issuer Agent HTTP
#   8090 - Issuer Agent DIDComm
#   8200 - Issuer Vault
#   7000 - Holder Agent HTTP
#   7001 - Holder Agent DIDComm  
#   7200 - Holder Vault
#   9000 - Verifier Agent HTTP
#   9001 - Verifier Agent DIDComm
#   9200 - Verifier Vault
#   5432 - PostgreSQL Database

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Database configuration
POSTGRES_CONTAINER="identus-postgres"
POSTGRES_HOST="localhost"
POSTGRES_PORT="5432"
POSTGRES_USER="postgres"
POSTGRES_PASSWORD="postgres"

# Agent configuration
AGENT_VERSION="1.33.0"
AGENT_IMAGE="ghcr.io/hyperledger/identus-cloud-agent:${AGENT_VERSION}"

# Vault ports for each agent
ISSUER_VAULT_PORT="8200"
HOLDER_VAULT_PORT="7200"
VERIFIER_VAULT_PORT="9200"

echo -e "${BLUE}🚀 Identus Agents Setup${NC}"
echo -e "${BLUE}=================================================${NC}"
echo -e "${CYAN}Agent Version: $AGENT_VERSION${NC}"
echo -e "${CYAN}Database: $POSTGRES_HOST:$POSTGRES_PORT${NC}"
echo ""

# Clean up function
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up agents and networks...${NC}"
    
    # Stop and remove agent containers
    sudo docker stop issuer-agent holder-agent verifier-agent 2>/dev/null || true
    sudo docker rm issuer-agent holder-agent verifier-agent 2>/dev/null || true
    
    # Stop and remove vault containers  
    sudo docker stop issuer-vault holder-vault verifier-vault 2>/dev/null || true
    sudo docker rm issuer-vault holder-vault verifier-vault 2>/dev/null || true
    
}

# Check if database container is running
check_database() {
    echo -e "${YELLOW}🔍 Checking database connectivity...${NC}"
    
    if ! sudo docker ps | grep -q $POSTGRES_CONTAINER; then
        echo -e "${RED}❌ Database container '$POSTGRES_CONTAINER' not found${NC}"
        echo -e "${CYAN}💡 Please run './scripts/setup-database.sh' first${NC}"
        return 1
    fi
    
    # Test database connection
    if ! sudo docker exec $POSTGRES_CONTAINER pg_isready -U $POSTGRES_USER > /dev/null 2>&1; then
        echo -e "${RED}❌ Database is not ready${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ Database is accessible${NC}"
    return 0
}

# Check if database and user exist for an agent
check_agent_database() {
    local agent_name=$1
    local db_name="${agent_name}_identus_db"
    local user_name="${agent_name}_user"
    
    echo -e "${YELLOW}🔍 Checking database setup for $agent_name agent...${NC}"
    
    # Check if database exists
    local db_exists=$(sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -t -c "SELECT 1 FROM pg_database WHERE datname='$db_name';" | xargs)
    
    # Check if user exists
    local user_exists=$(sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -t -c "SELECT 1 FROM pg_roles WHERE rolname='$user_name';" | xargs)
    
    if [ "$db_exists" = "1" ] && [ "$user_exists" = "1" ]; then
        echo -e "${GREEN}✅ Database '$db_name' and user '$user_name' exist${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  Database setup incomplete for $agent_name${NC}"
        echo -e "${CYAN}  Database exists: $([ "$db_exists" = "1" ] && echo "Yes" || echo "No")${NC}"
        echo -e "${CYAN}  User exists: $([ "$user_exists" = "1" ] && echo "Yes" || echo "No")${NC}"
        return 1
    fi
}

# Check all agent databases and populate if needed
check_and_populate_databases() {
    echo -e "${YELLOW}🔍 Checking agent database configurations...${NC}"
    
    local needs_population=false
    
    # Check each agent database
    for agent in issuer holder verifier; do
        if ! check_agent_database $agent; then
            needs_population=true
        fi
    done
    
    # Check if global users exist (required by Identus agents)
    local global_users=("pollux-application-user" "connect-application-user" "agent-application-user")
    for user in "${global_users[@]}"; do
        local user_exists=$(sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -t -c "SELECT 1 FROM pg_roles WHERE rolname='$user';" | xargs)
        if [ "$user_exists" != "1" ]; then
            echo -e "${YELLOW}⚠️  Global user '$user' missing${NC}"
            needs_population=true
        fi
    done
    
    if [ "$needs_population" = true ]; then
        echo -e "${YELLOW}📝 Database population needed. Running populate script...${NC}"
        
        # Check if populate script exists
        if [ -f "./scripts/populate-database.sh" ]; then
            ./scripts/populate-database.sh
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ Database population completed${NC}"
            else
                echo -e "${RED}❌ Database population failed${NC}"
                return 1
            fi
        else
            echo -e "${RED}❌ Database populate script not found at './scripts/populate-database.sh'${NC}"
            return 1
        fi
    else
        echo -e "${GREEN}✅ All agent databases are properly configured${NC}"
    fi
    
    return 0
}


# Setup vault for an agent (simplified host networking)
setup_vault() {
    local agent_name=$1
    local vault_port=$2
    local vault_token="${agent_name}_root"
    
    echo -e "${YELLOW}🔐 Setting up $agent_name vault...${NC}"
    
    sudo docker run -d \
        --name ${agent_name}-vault \
        --network host \
        -e VAULT_DEV_ROOT_TOKEN_ID=$vault_token \
        -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:$vault_port \
        -e VAULT_ADDR=http://localhost:$vault_port \
        hashicorp/vault:latest
    
    echo -e "${GREEN}✅ $agent_name vault started on port $vault_port${NC}"
    
    # Wait for vault to be ready
    local attempt=1
    while [ $attempt -le 10 ]; do
        if curl -s http://localhost:$vault_port/v1/sys/health > /dev/null 2>&1; then
            echo -e "${GREEN}✅ $agent_name vault is ready${NC}"
            return 0
        fi
        echo -e "${YELLOW}  Attempt $attempt/10: $agent_name vault not ready yet${NC}"
        sleep 3
        ((attempt++))
    done
    
    echo -e "${RED}❌ $agent_name vault failed to start${NC}"
    return 1
}

# Setup agent
setup_agent() {
    local agent_name=$1
    local http_port=$2
    local didcomm_port=$3
    local vault_port=$4
    local db_name="${agent_name}_identus_db"
    local vault_token="${agent_name}_root"
    
    echo -e "${YELLOW}🚀 Starting $agent_name agent...${NC}"
    
    sudo docker run -d \
        --name ${agent_name}-agent \
        --network host \
        -p $http_port:$http_port \
        -p $didcomm_port:$didcomm_port \
        -e API_KEY_ENABLED=false \
        -e AGENT_VERSION=$AGENT_VERSION \
        -e PORT=$http_port \
        -e PG_HOST=$POSTGRES_HOST \
        -e PG_PORT=$POSTGRES_PORT \
        -e PG_DATABASE=$db_name \
        -e PG_USERNAME=$POSTGRES_USER \
        -e PG_PASSWORD=$POSTGRES_PASSWORD \
        -e AGENT_HTTP_PORT=$http_port \
        -e AGENT_DIDCOMM_PORT=$didcomm_port \
        -e AGENT_HTTP_ENDPOINT="http://localhost:$http_port" \
        -e VAULT_DEV_ROOT_TOKEN_ID=$vault_token \
        -e VAULT_ADDR=http://localhost:$vault_port \
        -e VAULT_TOKEN=$vault_token \
        -e DEFAULT_WALLET_ENABLED=true \
        $AGENT_IMAGE
    
    echo -e "${GREEN}✅ $agent_name agent started on port $http_port${NC}"
    
    # Wait for agent to initialize database (avoid conflicts)
    echo -e "${YELLOW}  Waiting for $agent_name to initialize database...${NC}"
    sleep 20
}

# Test agent health
test_agent() {
    local agent_name=$1
    local http_port=$2
    
    echo -e "${YELLOW}🔍 Testing $agent_name agent health...${NC}"
    
    local attempt=1
    while [ $attempt -le 8 ]; do
        local response=$(curl -s -w "%{http_code}" -o /tmp/${agent_name}_health "http://localhost:$http_port/_system/health" 2>/dev/null || echo "000")
        
        if [ "$response" = "200" ]; then
            local health_content=$(cat /tmp/${agent_name}_health)
            echo -e "${GREEN}✅ $agent_name agent is healthy: $health_content${NC}"
            return 0
        elif [ "$response" = "000" ]; then
            echo -e "${YELLOW}  Attempt $attempt/8: $agent_name connection refused${NC}"
        else
            echo -e "${YELLOW}  Attempt $attempt/8: $agent_name HTTP $response${NC}"
        fi
        
        sleep 8
        ((attempt++))
    done
    
    echo -e "${RED}❌ $agent_name agent health check failed${NC}"
    return 1
}

# Show final status
show_status() {
    echo -e "${BLUE}📊 Identus Multi-Agent Status:${NC}"
    echo ""
    
    echo -e "${YELLOW}Running Containers:${NC}"
    sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(agent|vault|identus-postgres|PORTS)" || echo "No containers running"
    echo ""
    
    echo -e "${YELLOW}Service Information:${NC}"
    echo -e "${CYAN}  Database:       $POSTGRES_HOST:$POSTGRES_PORT${NC}"
    echo -e "${CYAN}  Issuer Agent:   http://localhost:8080 (Credential Issuing)${NC}"
    echo -e "${CYAN}  Holder Agent:   http://localhost:7000 (DID & Wallet Management)${NC}"
    echo -e "${CYAN}  Verifier Agent: http://localhost:9000 (Credential Verification)${NC}"
    echo ""
    
    echo -e "${YELLOW}Vault Services:${NC}"
    echo -e "${CYAN}  Issuer Vault:   http://localhost:$ISSUER_VAULT_PORT${NC}"
    echo -e "${CYAN}  Holder Vault:   http://localhost:$HOLDER_VAULT_PORT${NC}"
    echo -e "${CYAN}  Verifier Vault: http://localhost:$VERIFIER_VAULT_PORT${NC}"
    echo ""
    
    echo -e "${YELLOW}Health Check Commands:${NC}"
    echo -e "${CYAN}  curl http://localhost:8080/_system/health  # Issuer${NC}"
    echo -e "${CYAN}  curl http://localhost:7000/_system/health  # Holder${NC}"
    echo -e "${CYAN}  curl http://localhost:9000/_system/health  # Verifier${NC}"
    echo ""
    
    echo -e "${YELLOW}Management Commands:${NC}"
    echo -e "${CYAN}  Stop All:       ./scripts/setup-agent.sh cleanup${NC}"
    echo -e "${CYAN}  Check Status:   ./scripts/setup-agent.sh status${NC}"
    echo -e "${CYAN}  Database Setup: ./scripts/setup-database.sh${NC}"
}

# Main setup function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} Starting Agents Setup${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Clean up any existing setup
    cleanup
    sleep 2
    
    # Check database connectivity
    if ! check_database; then
        echo -e "${RED}❌ Database check failed${NC}"
        return 1
    fi
    
    # Check and populate databases if needed
    if ! check_and_populate_databases; then
        echo -e "${RED}❌ Database setup failed${NC}"
        return 1
    fi
    
    # Setup vaults (using host networking)
    setup_vault "issuer" $ISSUER_VAULT_PORT &
    setup_vault "holder" $HOLDER_VAULT_PORT &
    setup_vault "verifier" $VERIFIER_VAULT_PORT &
    
    # Wait for vaults to start
    wait
    sleep 5
    
    # Setup agents ONE AT A TIME to avoid PostgreSQL conflicts
    echo -e "${CYAN}🔄 Starting agents sequentially to avoid database conflicts...${NC}"
    
    echo -e "${BLUE}Step 1: Starting Issuer Agent${NC}"
    setup_agent "issuer" 8080 8090 $ISSUER_VAULT_PORT
    
    echo -e "${BLUE}Step 2: Starting Holder Agent${NC}"  
    setup_agent "holder" 7000 7001 $HOLDER_VAULT_PORT
    
    echo -e "${BLUE}Step 3: Starting Verifier Agent${NC}"
    setup_agent "verifier" 9000 9001 $VERIFIER_VAULT_PORT
    
    # Wait for agents to initialize
    echo -e "${YELLOW}⏳ Waiting additional 30 seconds for full initialization...${NC}"
    sleep 30
    
    # Test agents
    local all_healthy=true
    test_agent "issuer" 8080 || all_healthy=false
    test_agent "holder" 7000 || all_healthy=false
    test_agent "verifier" 9000 || all_healthy=false
    
    echo ""
    if [ "$all_healthy" = true ]; then
        echo -e "${BLUE}===============================================${NC}"
        echo -e "${GREEN}🎉 SUCCESS: All agents are running!${NC}"
        echo -e "${BLUE}===============================================${NC}"
    else
        echo -e "${BLUE}===============================================${NC}"
        echo -e "${YELLOW}⚠️  Some agents may have issues${NC}"
        echo -e "${BLUE}===============================================${NC}"
    fi
    
    show_status
}

# Handle cleanup command
if [ "$1" = "cleanup" ]; then
    cleanup
    echo -e "${GREEN}✅ Agents cleanup completed${NC}"
    exit 0
fi

# Handle status command
if [ "$1" = "status" ]; then
    show_status
    exit 0
fi

# Run main function
main "$@"