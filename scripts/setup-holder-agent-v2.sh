#!/bin/bash

# Hyperledger Identus Holder Agent Setup with Custom Network
# Uses shared PostgreSQL from issuer, creates isolated network for vault-agent
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
NETWORK_NAME="identus-holder-network"
SUBNET="172.21.0.0/16"
VAULT_IP="172.21.0.20"
AGENT_IP="172.21.0.30"

# Port configuration
HOLDER_HTTP_PORT="7000"
HOLDER_DIDCOMM_PORT="7001"
VAULT_PORT="7200"

echo -e "${BLUE}🚀 Identus Holder Agent Setup with Custom Network${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "${CYAN}Network: $NETWORK_NAME ($SUBNET)${NC}"
echo -e "${CYAN}Vault IP: $VAULT_IP${NC}"
echo -e "${CYAN}Agent IP: $AGENT_IP${NC}"
echo ""

# Clean up function
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up holder containers and network...${NC}"
    sudo docker stop holder-vault holder-agent 2>/dev/null || true
    sudo docker rm holder-vault holder-agent 2>/dev/null || true
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

# Setup Holder database user in existing issuer PostgreSQL
setup_holder_database() {
    echo -e "${YELLOW}🗄️  Setting up Holder database user in shared PostgreSQL...${NC}"
    
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
    
    # Create holder-specific database
    echo -e "${YELLOW}🏗️  Creating Holder database...${NC}"
    sudo docker exec issuer-postgres createdb -U postgres holder_identus_db 2>/dev/null || echo "Database may already exist"
    
    # Create holder-specific application users
    echo -e "${YELLOW}👥 Creating Holder application users...${NC}"
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"holder-pollux-application-user\" WITH PASSWORD 'holder_pollux_pass';" 2>/dev/null || echo "User may already exist"
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"holder-connect-application-user\" WITH PASSWORD 'holder_connect_pass';" 2>/dev/null || echo "User may already exist"
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"holder-agent-application-user\" WITH PASSWORD 'holder_agent_pass';" 2>/dev/null || echo "User may already exist"
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"holder_user\" WITH PASSWORD 'holder_pass';" 2>/dev/null || echo "User may already exist"
    
    # Grant privileges for holder users
    echo -e "${YELLOW}🔑 Granting Holder database privileges...${NC}"
    sudo docker exec issuer-postgres psql -U postgres -c "
        GRANT ALL PRIVILEGES ON DATABASE holder_identus_db TO \"holder-pollux-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE holder_identus_db TO \"holder-connect-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE holder_identus_db TO \"holder-agent-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE holder_identus_db TO holder_user;
        GRANT ALL PRIVILEGES ON DATABASE pollux TO \"holder-pollux-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE connect TO \"holder-connect-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE agent TO \"holder-agent-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE node_db TO holder_user;
    " 2>/dev/null || true
    
    echo -e "${GREEN}✅ Holder database setup completed${NC}"
}

# Setup Vault in development mode
setup_vault() {
    echo -e "${YELLOW}🔐 Setting up Holder Vault...${NC}"
    
    sudo docker run -d \
        --name holder-vault \
        --network $NETWORK_NAME \
        --ip $VAULT_IP \
        -p $VAULT_PORT:8200 \
        --cap-add=IPC_LOCK \
        -e VAULT_DEV_ROOT_TOKEN_ID=holder_root \
        -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
        hashicorp/vault:latest
    
    echo -e "${GREEN}✅ Holder Vault container started${NC}"
    
    # Wait for Vault
    echo -e "${YELLOW}⏳ Waiting for Holder Vault...${NC}"
    local attempt=1
    while [ $attempt -le 10 ]; do
        if curl -s http://localhost:$VAULT_PORT/v1/sys/health > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Holder Vault is ready${NC}"
            return 0
        fi
        echo -e "${YELLOW}  Attempt $attempt/10: Vault not ready yet${NC}"
        sleep 3
        ((attempt++))
    done
    
    echo -e "${RED}❌ Holder Vault failed to start${NC}"
    return 1
}

# Start Identus Holder Agent
start_holder_agent() {
    echo -e "${YELLOW}🚀 Starting Identus Holder Agent...${NC}"
    
    sudo docker run -d \
        --name holder-agent \
        --network host \
        -p $HOLDER_HTTP_PORT:$HOLDER_HTTP_PORT \
        -p $HOLDER_DIDCOMM_PORT:$HOLDER_DIDCOMM_PORT \
        -e API_KEY_ENABLED=false \
        -e AGENT_VERSION=1.33.0 \
        -e PORT=$HOLDER_HTTP_PORT \
        -e PG_HOST=localhost \
        -e PG_PORT=5432 \
        -e PG_DATABASE=holder_identus_db \
        -e PG_USERNAME=postgres \
        -e PG_PASSWORD=postgres \
        -e AGENT_HTTP_PORT=$HOLDER_HTTP_PORT \
        -e AGENT_DIDCOMM_PORT=$HOLDER_DIDCOMM_PORT \
        -e AGENT_HTTP_ENDPOINT="http://localhost:$HOLDER_HTTP_PORT" \
        -e VAULT_DEV_ROOT_TOKEN_ID=holder_root \
        -e VAULT_ADDR=http://localhost:$VAULT_PORT \
        -e VAULT_TOKEN=holder_root \
        ghcr.io/hyperledger/identus-cloud-agent:1.33.0
    
    echo -e "${GREEN}✅ Holder Agent container started${NC}"
    echo -e "${CYAN}  Exposed ports: $HOLDER_HTTP_PORT (HTTP API), $HOLDER_DIDCOMM_PORT (DIDComm)${NC}"
}

# Test Holder Agent
test_holder_agent() {
    echo -e "${YELLOW}⏳ Waiting 30 seconds for holder agent initialization...${NC}"
    sleep 30
    
    echo -e "${YELLOW}🔍 Testing Holder Agent health...${NC}"
    
    local attempt=1
    while [ $attempt -le 8 ]; do
        echo -e "${YELLOW}  Attempt $attempt/8: Testing health endpoint...${NC}"
        
        local response=$(curl -s -w "%{http_code}" -o /tmp/holder_health "http://localhost:$HOLDER_HTTP_PORT/_system/health" 2>/dev/null || echo "000")
        
        if [ "$response" = "200" ]; then
            echo -e "${GREEN}🎉 SUCCESS: Holder Agent is healthy!${NC}"
            local health_content=$(cat /tmp/holder_health)
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
    
    echo -e "${RED}❌ Holder Agent health check failed${NC}"
    return 1
}

# Test additional endpoints
test_endpoints() {
    echo -e "${YELLOW}🔍 Testing additional holder endpoints...${NC}"
    
    # Test DIDComm port
    if netstat -ln 2>/dev/null | grep -q ":$HOLDER_DIDCOMM_PORT "; then
        echo -e "${GREEN}✅ Holder DIDComm port $HOLDER_DIDCOMM_PORT is listening${NC}"
    else
        echo -e "${YELLOW}⚠️  Holder DIDComm port $HOLDER_DIDCOMM_PORT not listening${NC}"
    fi
    
    # Test credentials endpoint
    local api_response=$(curl -s -w "%{http_code}" -o /tmp/holder_api_test "http://localhost:$HOLDER_HTTP_PORT/issue-credentials/records" 2>/dev/null || echo "000")
    if [ "$api_response" = "200" ]; then
        echo -e "${GREEN}✅ Holder credentials endpoint responding${NC}"
    elif [ "$api_response" = "401" ] || [ "$api_response" = "404" ]; then
        echo -e "${GREEN}✅ Holder API endpoint responding (${api_response} expected)${NC}"
    else
        echo -e "${YELLOW}⚠️  Holder credentials endpoint: HTTP $api_response${NC}"
    fi
    
    # Test network connectivity
    echo -e "${YELLOW}🌐 Testing network connectivity...${NC}"
    echo -e "${CYAN}  Network: $NETWORK_NAME${NC}"
    echo -e "${CYAN}  Containers in network:${NC}"
    sudo docker network inspect $NETWORK_NAME --format '{{range .Containers}}  - {{.Name}} ({{.IPv4Address}}){{end}}' 2>/dev/null || true
}

# Show final status and information
show_status() {
    echo -e "${BLUE}📊 Holder Agent Status:${NC}"
    echo ""
    
    echo -e "${YELLOW}Running Holder Containers:${NC}"
    sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(holder|PORTS)" || echo "No holder containers running"
    echo ""
    
    echo -e "${YELLOW}Holder Service Information:${NC}"
    echo -e "${CYAN}  PostgreSQL:     localhost:5432 (shared with issuer, db: holder_identus_db)${NC}"
    echo -e "${CYAN}  Vault:          http://localhost:7200 (isolated network)${NC}"
    echo -e "${CYAN}  Holder Agent:   http://localhost:7000${NC}"
    echo ""
    
    echo -e "${YELLOW}Key Holder Endpoints:${NC}"
    echo -e "${CYAN}  Health Check:   http://localhost:7000/_system/health${NC}"
    echo -e "${CYAN}  Credentials:    http://localhost:7000/issue-credentials/records${NC}"
    echo -e "${CYAN}  DIDComm:        http://localhost:7001${NC}"
    echo ""
    
    echo -e "${YELLOW}Testing Commands:${NC}"
    echo -e "${CYAN}  curl http://localhost:7000/_system/health${NC}"
    echo -e "${CYAN}  curl http://localhost:7000/issue-credentials/records${NC}"
    echo ""
    
    echo -e "${YELLOW}Management Commands:${NC}"
    echo -e "${CYAN}  Stop:    sudo docker stop holder-vault holder-agent${NC}"
    echo -e "${CYAN}  Remove:  sudo docker rm holder-vault holder-agent${NC}"
    echo -e "${CYAN}  Cleanup: ./scripts/setup-holder-agent-v2.sh cleanup${NC}"
    echo -e "${CYAN}  Note:    PostgreSQL is shared with issuer (not stopped by holder cleanup)${NC}"
}

# Main setup function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} Starting Holder Agent Setup${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Clean up any existing setup
    cleanup
    sleep 2
    
    # Setup components step by step
    if create_network; then
        if setup_holder_database; then
            if setup_vault; then
                start_holder_agent
            
                if test_holder_agent; then
                    test_endpoints
                    
                    echo ""
                    echo -e "${BLUE}===============================================${NC}"
                    echo -e "${GREEN}🎉 SUCCESS: Holder Agent is running!${NC}"
                    echo -e "${BLUE}===============================================${NC}"
                    
                    show_status
                    
                else
                    echo -e "${RED}❌ FAILED: Holder Agent test failed${NC}"
                    echo -e "${YELLOW}Checking logs...${NC}"
                    sudo docker logs holder-agent --tail 10 2>/dev/null || echo "No logs available"
                fi
            else
                echo -e "${RED}❌ FAILED: Holder Vault setup failed${NC}"
            fi
        else
            echo -e "${RED}❌ FAILED: Holder database setup failed${NC}"
        fi
    else
        echo -e "${RED}❌ FAILED: Network creation failed${NC}"
    fi
}

# Handle cleanup command
if [ "$1" = "cleanup" ]; then
    cleanup
    echo -e "${GREEN}✅ Holder cleanup completed${NC}"
    exit 0
fi

# Run main function
main "$@"