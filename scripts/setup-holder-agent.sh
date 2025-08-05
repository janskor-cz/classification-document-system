#!/bin/bash

# Hyperledger Identus Holder Agent Setup
# Sets up PostgreSQL, Vault, and Holder Agent on port 7000

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Identus Holder Agent Setup${NC}"
echo -e "${BLUE}==============================${NC}"
echo ""

# Clean up function
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up holder containers...${NC}"
    sudo docker stop holder-vault holder-agent 2>/dev/null || true
    sudo docker rm holder-vault holder-agent 2>/dev/null || true
}

# Setup PostgreSQL with required configuration
setup_postgresql() {
    echo -e "${YELLOW}🗄️  Setting up Holder PostgreSQL...${NC}"
    
    # Use custom port for holder postgres to avoid conflicts
    sudo docker run -d \
        --name holder-postgres \
        --network host \
        -e POSTGRES_DB=holder_identus_db \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD=postgres \
        -e PGPORT=5433 \
        postgres:15 \
        -p 5433
    
    echo -e "${GREEN}✅ Holder PostgreSQL container started${NC}"
    
    # Wait for PostgreSQL
    echo -e "${YELLOW}⏳ Waiting for Holder PostgreSQL...${NC}"
    local attempt=1
    while [ $attempt -le 12 ]; do
        if sudo docker exec holder-postgres pg_isready -U postgres -d holder_identus_db > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Holder PostgreSQL is ready${NC}"
            break
        fi
        echo -e "${YELLOW}  Attempt $attempt/12: PostgreSQL not ready yet${NC}"
        sleep 3
        ((attempt++))
        if [ $attempt -gt 12 ]; then
            echo -e "${RED}❌ Holder PostgreSQL failed to start${NC}"
            return 1
        fi
    done
    
    # Create required databases for Identus Holder
    echo -e "${YELLOW}🏗️  Creating Holder Identus databases...${NC}"
    sudo docker exec holder-postgres createdb -U postgres pollux 2>/dev/null || true
    sudo docker exec holder-postgres createdb -U postgres connect 2>/dev/null || true
    sudo docker exec holder-postgres createdb -U postgres agent 2>/dev/null || true
    sudo docker exec holder-postgres createdb -U postgres node_db 2>/dev/null || true
    
    # Create required application users
    echo -e "${YELLOW}👥 Creating holder application users...${NC}"
    sudo docker exec holder-postgres psql -U postgres -c "CREATE USER \"pollux-application-user\" WITH PASSWORD 'pollux_pass';" 2>/dev/null || true
    sudo docker exec holder-postgres psql -U postgres -c "CREATE USER \"connect-application-user\" WITH PASSWORD 'connect_pass';" 2>/dev/null || true
    sudo docker exec holder-postgres psql -U postgres -c "CREATE USER \"agent-application-user\" WITH PASSWORD 'agent_pass';" 2>/dev/null || true
    sudo docker exec holder-postgres psql -U postgres -c "CREATE USER \"holder_identus_user\" WITH PASSWORD 'holder_identus_pass';" 2>/dev/null || true
    
    # Grant all necessary privileges
    echo -e "${YELLOW}🔑 Granting holder database privileges...${NC}"
    sudo docker exec holder-postgres psql -U postgres -c "
        GRANT ALL PRIVILEGES ON DATABASE pollux TO \"pollux-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE connect TO \"connect-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE agent TO \"agent-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE holder_identus_db TO holder_identus_user;
        GRANT ALL PRIVILEGES ON DATABASE node_db TO holder_identus_user;
        GRANT ALL PRIVILEGES ON DATABASE holder_identus_db TO \"pollux-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE holder_identus_db TO \"connect-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE holder_identus_db TO \"agent-application-user\";
    " 2>/dev/null || true
    
    echo -e "${GREEN}✅ Holder PostgreSQL setup completed${NC}"
}

# Setup Vault in development mode
setup_vault() {
    echo -e "${YELLOW}🔐 Setting up Holder Vault...${NC}"
    
    sudo docker run -d \
        --name holder-vault \
        --network host \
        --cap-add=IPC_LOCK \
        -e VAULT_DEV_ROOT_TOKEN_ID=holder_root \
        -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:7200 \
        hashicorp/vault:latest
    
    echo -e "${GREEN}✅ Holder Vault container started${NC}"
    
    # Wait for Vault
    echo -e "${YELLOW}⏳ Waiting for Holder Vault...${NC}"
    local attempt=1
    while [ $attempt -le 10 ]; do
        if curl -s http://localhost:7200/v1/sys/health > /dev/null 2>&1; then
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
        -e API_KEY_ENABLED=false \
        -e AGENT_VERSION=1.33.0 \
        -e PORT=7000 \
        -e PG_HOST=localhost \
        -e PG_PORT=5432 \
        -e PG_DATABASE=holder_identus_db \
        -e PG_USERNAME=postgres \
        -e PG_PASSWORD=postgres \
        -e AGENT_HTTP_PORT=7000 \
        -e AGENT_DIDCOMM_PORT=7001 \
        -e AGENT_HTTP_ENDPOINT="http://localhost:7000" \
        -e VAULT_DEV_ROOT_TOKEN_ID=holder_root \
        -e VAULT_ADDR=http://localhost:7200 \
        -e VAULT_TOKEN=holder_root \
        ghcr.io/hyperledger/identus-cloud-agent:1.33.0
    
    echo -e "${GREEN}✅ Holder Agent container started${NC}"
}

# Test Holder Agent
test_holder_agent() {
    echo -e "${YELLOW}⏳ Waiting 30 seconds for holder agent initialization...${NC}"
    sleep 30
    
    echo -e "${YELLOW}🔍 Testing Holder Agent health...${NC}"
    
    local attempt=1
    while [ $attempt -le 8 ]; do
        echo -e "${YELLOW}  Attempt $attempt/8: Testing health endpoint...${NC}"
        
        local response=$(curl -s -w "%{http_code}" -o /tmp/holder_health "http://localhost:7000/_system/health" 2>/dev/null || echo "000")
        
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
    if netstat -ln 2>/dev/null | grep -q ":7001 "; then
        echo -e "${GREEN}✅ Holder DIDComm port 7001 is listening${NC}"
    else
        echo -e "${YELLOW}⚠️  Holder DIDComm port 7001 not listening${NC}"
    fi
    
    # Test main API endpoint
    local api_response=$(curl -s -w "%{http_code}" -o /tmp/holder_api_test "http://localhost:7000/connections" 2>/dev/null || echo "000")
    if [ "$api_response" = "200" ]; then
        echo -e "${GREEN}✅ Holder API endpoint responding${NC}"
    else
        echo -e "${YELLOW}⚠️  Holder API endpoint: HTTP $api_response${NC}"
    fi
}

# Show final status and information
show_status() {
    echo -e "${BLUE}📊 Holder Agent Status:${NC}"
    echo ""
    
    echo -e "${YELLOW}Running Holder Containers:${NC}"
    sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(holder|PORTS)" || echo "No holder containers running"
    echo ""
    
    echo -e "${YELLOW}Holder Service Information:${NC}"
    echo -e "${CYAN}  PostgreSQL:     localhost:5433 (holder_identus_db)${NC}"
    echo -e "${CYAN}  Vault:          http://localhost:7200${NC}"
    echo -e "${CYAN}  Holder Agent:   http://localhost:7000${NC}"
    echo ""
    
    echo -e "${YELLOW}Holder Key Endpoints:${NC}"
    echo -e "${CYAN}  Health Check:   http://localhost:7000/_system/health${NC}"
    echo -e "${CYAN}  Connections:    http://localhost:7000/connections${NC}"
    echo -e "${CYAN}  DIDComm:        http://localhost:7001${NC}"
    echo ""
    
    echo -e "${YELLOW}Testing Commands:${NC}"
    echo -e "${CYAN}  curl http://localhost:7000/_system/health${NC}"
    echo -e "${CYAN}  curl http://localhost:7000/connections${NC}"
    echo ""
    
    echo -e "${YELLOW}Management Commands:${NC}"
    echo -e "${CYAN}  Stop:    sudo docker stop holder-postgres holder-vault holder-agent${NC}"
    echo -e "${CYAN}  Remove:  sudo docker rm holder-postgres holder-vault holder-agent${NC}"
    echo -e "${CYAN}  Cleanup: ./scripts/setup-holder-agent.sh cleanup${NC}"
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
    if true; then  # Skip PostgreSQL setup, use shared from issuer
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
        echo -e "${RED}❌ FAILED: Holder PostgreSQL setup failed${NC}"
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