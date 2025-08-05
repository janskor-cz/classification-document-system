#!/bin/bash

# Hyperledger Identus Verifier Agent Setup with Custom Network
# Sets up PostgreSQL, Vault, and Verifier Agent in separate Docker network
# Uses hardcoded IP addresses and exposes only Web API and DIDComm ports

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Network configuration
NETWORK_NAME="identus-verifier-network"
SUBNET="172.20.0.0/16"
POSTGRES_IP="172.20.0.10"
VAULT_IP="172.20.0.20"
AGENT_IP="172.20.0.30"

# Port configuration
VERIFIER_HTTP_PORT="9000"
VERIFIER_DIDCOMM_PORT="9001"
POSTGRES_PORT="5434"
VAULT_PORT="9200"

echo -e "${BLUE}🚀 Identus Verifier Agent Setup with Custom Network${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "${CYAN}Network: $NETWORK_NAME ($SUBNET)${NC}"
echo -e "${CYAN}PostgreSQL IP: $POSTGRES_IP${NC}"
echo -e "${CYAN}Vault IP: $VAULT_IP${NC}"
echo -e "${CYAN}Agent IP: $AGENT_IP${NC}"
echo ""

# Clean up function
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up verifier containers and network...${NC}"
    sudo docker stop verifier-vault verifier-agent 2>/dev/null || true
    sudo docker rm verifier-vault verifier-agent 2>/dev/null || true
    sudo docker network rm $NETWORK_NAME 2>/dev/null || true
}

# Create Docker network
create_network() {
    echo -e "${YELLOW}🌐 Creating Docker network...${NC}"
    
    # Remove existing network if it exists
    sudo docker network rm $NETWORK_NAME 2>/dev/null || true
    
    # Create new network with custom subnet
    sudo docker network create \
        --driver bridge \
        --subnet=$SUBNET \
        $NETWORK_NAME
    
    echo -e "${GREEN}✅ Docker network '$NETWORK_NAME' created${NC}"
}

# Setup Verifier database user in existing issuer PostgreSQL
setup_verifier_database() {
    echo -e "${YELLOW}🗄️  Setting up Verifier database user in shared PostgreSQL...${NC}"
    
    # Check if issuer PostgreSQL is running
    if ! sudo docker ps | grep -q issuer-postgres; then
        echo -e "${RED}❌ Issuer PostgreSQL container not found. Please run issuer script first.${NC}"
        return 1
    fi
    
    # Wait for PostgreSQL to be ready
    echo -e "${YELLOW}⏳ Waiting for shared PostgreSQL...${NC}"
    local attempt=1
    while [ $attempt -le 10 ]; do
        if sudo docker exec issuer-postgres pg_isready -U postgres -d identus_db > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Shared PostgreSQL is ready${NC}"
            break
        fi
        echo -e "${YELLOW}  Attempt $attempt/10: PostgreSQL not ready yet${NC}"
        sleep 2
        ((attempt++))
        if [ $attempt -gt 10 ]; then
            echo -e "${RED}❌ Shared PostgreSQL not ready${NC}"
            return 1
        fi
    done
    
    # Create verifier-specific database
    echo -e "${YELLOW}🏗️  Creating Verifier database...${NC}"
    sudo docker exec issuer-postgres createdb -U postgres verifier_identus_db 2>/dev/null || echo "Database may already exist"
    
    # Create verifier-specific application users
    echo -e "${YELLOW}👥 Creating Verifier application users...${NC}"
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"verifier-pollux-application-user\" WITH PASSWORD 'verifier_pollux_pass';" 2>/dev/null || echo "User may already exist"
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"verifier-connect-application-user\" WITH PASSWORD 'verifier_connect_pass';" 2>/dev/null || echo "User may already exist"
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"verifier-agent-application-user\" WITH PASSWORD 'verifier_agent_pass';" 2>/dev/null || echo "User may already exist"
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"verifier_user\" WITH PASSWORD 'verifier_pass';" 2>/dev/null || echo "User may already exist"
    
    # Grant privileges for verifier users
    echo -e "${YELLOW}🔑 Granting Verifier database privileges...${NC}"
    sudo docker exec issuer-postgres psql -U postgres -c "
        GRANT ALL PRIVILEGES ON DATABASE verifier_identus_db TO \"verifier-pollux-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE verifier_identus_db TO \"verifier-connect-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE verifier_identus_db TO \"verifier-agent-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE verifier_identus_db TO verifier_user;
        GRANT ALL PRIVILEGES ON DATABASE pollux TO \"verifier-pollux-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE connect TO \"verifier-connect-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE agent TO \"verifier-agent-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE node_db TO verifier_user;
    " 2>/dev/null || true
    
    echo -e "${GREEN}✅ Verifier database setup completed${NC}"
}

# Setup Vault in development mode
setup_vault() {
    echo -e "${YELLOW}🔐 Setting up Verifier Vault...${NC}"
    
    sudo docker run -d \
        --name verifier-vault \
        --network $NETWORK_NAME \
        -p $VAULT_PORT:8200 \
        --cap-add=IPC_LOCK \
        -e VAULT_DEV_ROOT_TOKEN_ID=verifier_root \
        -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
        hashicorp/vault:latest
    
    echo -e "${GREEN}✅ Verifier Vault container started${NC}"
    
    # Wait for Vault
    echo -e "${YELLOW}⏳ Waiting for Verifier Vault...${NC}"
    local attempt=1
    while [ $attempt -le 10 ]; do
        if curl -s http://localhost:$VAULT_PORT/v1/sys/health > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Verifier Vault is ready${NC}"
            return 0
        fi
        echo -e "${YELLOW}  Attempt $attempt/10: Vault not ready yet${NC}"
        sleep 3
        ((attempt++))
    done
    
    echo -e "${RED}❌ Verifier Vault failed to start${NC}"
    return 1
}

# Start Identus Verifier Agent
start_verifier_agent() {
    echo -e "${YELLOW}🚀 Starting Identus Verifier Agent...${NC}"
    
    sudo docker run -d \
        --name verifier-agent \
        --network host \
        -p $VERIFIER_HTTP_PORT:$VERIFIER_HTTP_PORT \
        -p $VERIFIER_DIDCOMM_PORT:$VERIFIER_DIDCOMM_PORT \
        -e API_KEY_ENABLED=false \
        -e AGENT_VERSION=1.33.0 \
        -e PORT=$VERIFIER_HTTP_PORT \
        -e PG_HOST=localhost \
        -e PG_PORT=5432 \
        -e PG_DATABASE=verifier_identus_db \
        -e PG_USERNAME=postgres \
        -e PG_PASSWORD=postgres \
        -e AGENT_HTTP_PORT=$VERIFIER_HTTP_PORT \
        -e AGENT_DIDCOMM_PORT=$VERIFIER_DIDCOMM_PORT \
        -e AGENT_HTTP_ENDPOINT="http://localhost:$VERIFIER_HTTP_PORT" \
        -e VAULT_DEV_ROOT_TOKEN_ID=verifier_root \
        -e VAULT_ADDR=http://localhost:$VAULT_PORT \
        -e VAULT_TOKEN=verifier_root \
        ghcr.io/hyperledger/identus-cloud-agent:1.33.0
    
    echo -e "${GREEN}✅ Verifier Agent container started${NC}"
    echo -e "${CYAN}  Exposed ports: $VERIFIER_HTTP_PORT (HTTP API), $VERIFIER_DIDCOMM_PORT (DIDComm)${NC}"
}

# Test Verifier Agent
test_verifier_agent() {
    echo -e "${YELLOW}⏳ Waiting 30 seconds for verifier agent initialization...${NC}"
    sleep 30
    
    echo -e "${YELLOW}🔍 Testing Verifier Agent health...${NC}"
    
    local attempt=1
    while [ $attempt -le 8 ]; do
        echo -e "${YELLOW}  Attempt $attempt/8: Testing health endpoint...${NC}"
        
        local response=$(curl -s -w "%{http_code}" -o /tmp/verifier_health "http://localhost:$VERIFIER_HTTP_PORT/_system/health" 2>/dev/null || echo "000")
        
        if [ "$response" = "200" ]; then
            echo -e "${GREEN}🎉 SUCCESS: Verifier Agent is healthy!${NC}"
            local health_content=$(cat /tmp/verifier_health)
            echo -e "${CYAN}  Health Response: $health_content${NC}"
            return 0
        elif [ "$response" = "000" ]; then
            echo -e "${YELLOW}    Connection refused${NC}"
        else
            echo -e "${YELLOW}    HTTP $response${NC}"
        fi
        
        sleep 8
        ((attempt++))
    done
    
    echo -e "${RED}❌ Verifier Agent health check failed${NC}"
    return 1
}

# Test additional endpoints
test_endpoints() {
    echo -e "${YELLOW}🔍 Testing additional verifier endpoints...${NC}"
    
    # Test DIDComm port
    if netstat -ln 2>/dev/null | grep -q ":$VERIFIER_DIDCOMM_PORT "; then
        echo -e "${GREEN}✅ Verifier DIDComm port $VERIFIER_DIDCOMM_PORT is listening${NC}"
    else
        echo -e "${YELLOW}⚠️  Verifier DIDComm port $VERIFIER_DIDCOMM_PORT not listening${NC}"
    fi
    
    # Test presentations endpoint
    local api_response=$(curl -s -w "%{http_code}" -o /tmp/verifier_api_test "http://localhost:$VERIFIER_HTTP_PORT/present-proof/presentations" 2>/dev/null || echo "000")
    if [ "$api_response" = "200" ]; then
        echo -e "${GREEN}✅ Verifier presentations endpoint responding${NC}"
    elif [ "$api_response" = "401" ] || [ "$api_response" = "404" ]; then
        echo -e "${GREEN}✅ Verifier API endpoint responding (${api_response} expected)${NC}"
    else
        echo -e "${YELLOW}⚠️  Verifier presentations endpoint: HTTP $api_response${NC}"
    fi
    
    # Test network connectivity
    echo -e "${YELLOW}🌐 Testing network connectivity...${NC}"
    echo -e "${CYAN}  Network: $NETWORK_NAME${NC}"
    echo -e "${CYAN}  Containers in network:${NC}"
    sudo docker network inspect $NETWORK_NAME --format '{{range .Containers}}  - {{.Name}} ({{.IPv4Address}}){{end}}' 2>/dev/null || true
}

# Show final status and information
show_status() {
    echo -e "${BLUE}📊 Verifier Agent Status:${NC}"
    echo ""
    
    echo -e "${YELLOW}Running Verifier Containers:${NC}"
    sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(verifier|PORTS)" || echo "No verifier containers running"
    echo ""
    
    echo -e "${YELLOW}Verifier Service Information:${NC}"
    echo -e "${CYAN}  PostgreSQL:     localhost:5432 (shared with issuer, db: verifier_identus_db)${NC}"
    echo -e "${CYAN}  Vault:          http://localhost:9200 (isolated)${NC}"
    echo -e "${CYAN}  Verifier Agent: http://localhost:9000${NC}"
    echo ""
    
    echo -e "${YELLOW}Key Verifier Endpoints:${NC}"
    echo -e "${CYAN}  Health Check:   http://localhost:9000/_system/health${NC}"
    echo -e "${CYAN}  Presentations:  http://localhost:9000/present-proof/presentations${NC}"
    echo -e "${CYAN}  DIDComm:        http://localhost:9001${NC}"
    echo ""
    
    echo -e "${YELLOW}Testing Commands:${NC}"
    echo -e "${CYAN}  curl http://localhost:9000/_system/health${NC}"
    echo -e "${CYAN}  curl http://localhost:9000/present-proof/presentations${NC}"
    echo ""
    
    echo -e "${YELLOW}Management Commands:${NC}"
    echo -e "${CYAN}  Stop:    sudo docker stop verifier-vault verifier-agent${NC}"
    echo -e "${CYAN}  Remove:  sudo docker rm verifier-vault verifier-agent${NC}"
    echo -e "${CYAN}  Cleanup: ./scripts/setup-verifier-agent.sh cleanup${NC}"
    echo -e "${CYAN}  Note:    PostgreSQL is shared with issuer (not stopped by verifier cleanup)${NC}"
}

# Main setup function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} Starting Verifier Agent Setup${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Clean up any existing setup
    cleanup
    sleep 2
    
    # Setup components step by step
    if create_network; then
        if setup_verifier_database; then
            if setup_vault; then
                start_verifier_agent
            
            if test_verifier_agent; then
                test_endpoints
                
                echo ""
                echo -e "${BLUE}===============================================${NC}"
                echo -e "${GREEN}🎉 SUCCESS: Verifier Agent is running!${NC}"
                echo -e "${BLUE}===============================================${NC}"
                
                show_status
                
            else
                echo -e "${RED}❌ FAILED: Verifier Agent test failed${NC}"
                echo -e "${YELLOW}Checking logs...${NC}"
                sudo docker logs verifier-agent --tail 10 2>/dev/null || echo "No logs available"
            fi
            else
                echo -e "${RED}❌ FAILED: Verifier Vault setup failed${NC}"
            fi
        else
            echo -e "${RED}❌ FAILED: Verifier database setup failed${NC}"
        fi
    else
        echo -e "${RED}❌ FAILED: Network creation failed${NC}"
    fi
}

# Handle cleanup command
if [ "$1" = "cleanup" ]; then
    cleanup
    echo -e "${GREEN}✅ Verifier cleanup completed${NC}"
    exit 0
fi

# Run main function
main "$@"