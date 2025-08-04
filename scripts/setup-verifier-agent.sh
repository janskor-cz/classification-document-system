#!/bin/bash

# Minimal Hyperledger Identus Verifier Agent Setup
# Sets up PostgreSQL, Vault, and Verifier Agent on port 9000
# Based on the proven working issuer setup

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Minimal Identus Verifier Agent Setup${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Clean up function
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up verifier containers...${NC}"
    sudo docker stop verifier-postgres verifier-vault verifier-agent 2>/dev/null || true
    sudo docker rm verifier-postgres verifier-vault verifier-agent 2>/dev/null || true
}

# Setup PostgreSQL with required configuration
setup_postgresql() {
    echo -e "${YELLOW}🗄️  Setting up Verifier PostgreSQL...${NC}"
    
    # Use custom port for verifier postgres to avoid conflicts
    sudo docker run -d \
        --name verifier-postgres \
        --network host \
        -e POSTGRES_DB=verifier_identus_db \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD=postgres \
        -e PGPORT=5434 \
        postgres:15 \
        -p 5434
    
    echo -e "${GREEN}✅ Verifier PostgreSQL container started${NC}"
    
    # Wait for PostgreSQL
    echo -e "${YELLOW}⏳ Waiting for Verifier PostgreSQL...${NC}"
    local attempt=1
    while [ $attempt -le 12 ]; do
        if sudo docker exec verifier-postgres pg_isready -U postgres -d verifier_identus_db > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Verifier PostgreSQL is ready${NC}"
            break
        fi
        echo -e "${YELLOW}  Attempt $attempt/12: PostgreSQL not ready yet${NC}"
        sleep 3
        ((attempt++))
        if [ $attempt -gt 12 ]; then
            echo -e "${RED}❌ Verifier PostgreSQL failed to start${NC}"
            return 1
        fi
    done
    
    # Create required databases for Identus
    echo -e "${YELLOW}🏗️  Creating Verifier Identus databases...${NC}"
    sudo docker exec verifier-postgres createdb -U postgres pollux 2>/dev/null || true
    sudo docker exec verifier-postgres createdb -U postgres connect 2>/dev/null || true
    sudo docker exec verifier-postgres createdb -U postgres agent 2>/dev/null || true
    sudo docker exec verifier-postgres createdb -U postgres node_db 2>/dev/null || true
    
    # Create required application users
    echo -e "${YELLOW}👥 Creating Verifier application users...${NC}"
    sudo docker exec verifier-postgres psql -U postgres -c "CREATE USER \"verifier-pollux-application-user\" WITH PASSWORD 'verifier_pollux_pass';" 2>/dev/null || true
    sudo docker exec verifier-postgres psql -U postgres -c "CREATE USER \"verifier-connect-application-user\" WITH PASSWORD 'verifier_connect_pass';" 2>/dev/null || true
    sudo docker exec verifier-postgres psql -U postgres -c "CREATE USER \"verifier-agent-application-user\" WITH PASSWORD 'verifier_agent_pass';" 2>/dev/null || true
    sudo docker exec verifier-postgres psql -U postgres -c "CREATE USER \"verifier_identus_user\" WITH PASSWORD 'verifier_identus_pass';" 2>/dev/null || true
    
    # Grant all necessary privileges
    echo -e "${YELLOW}🔑 Granting Verifier database privileges...${NC}"
    sudo docker exec verifier-postgres psql -U postgres -c "
        GRANT ALL PRIVILEGES ON DATABASE pollux TO \"verifier-pollux-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE connect TO \"verifier-connect-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE agent TO \"verifier-agent-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE verifier_identus_db TO verifier_identus_user;
        GRANT ALL PRIVILEGES ON DATABASE node_db TO verifier_identus_user;
        GRANT ALL PRIVILEGES ON DATABASE verifier_identus_db TO \"verifier-pollux-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE verifier_identus_db TO \"verifier-connect-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE verifier_identus_db TO \"verifier-agent-application-user\";
    " 2>/dev/null || true
    
    echo -e "${GREEN}✅ Verifier PostgreSQL setup completed${NC}"
}

# Setup Vault in development mode
setup_vault() {
    echo -e "${YELLOW}🔐 Setting up Verifier Vault...${NC}"
    
    sudo docker run -d \
        --name verifier-vault \
        --network host \
        --cap-add=IPC_LOCK \
        -e VAULT_DEV_ROOT_TOKEN_ID=verifier_root \
        -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:9200 \
        hashicorp/vault:latest
    
    echo -e "${GREEN}✅ Verifier Vault container started${NC}"
    
    # Wait for Vault
    echo -e "${YELLOW}⏳ Waiting for Verifier Vault...${NC}"
    local attempt=1
    while [ $attempt -le 10 ]; do
        if curl -s http://localhost:9200/v1/sys/health > /dev/null 2>&1; then
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
        -e API_KEY_ENABLED=false \
        -e AGENT_VERSION=1.33.0 \
        -e PORT=9000 \
        -e PG_HOST=localhost \
        -e PG_PORT=5434 \
        -e PG_DATABASE=verifier_identus_db \
        -e PG_USERNAME=postgres \
        -e PG_PASSWORD=postgres \
        -e AGENT_HTTP_PORT=9000 \
        -e AGENT_DIDCOMM_PORT=9001 \
        -e AGENT_HTTP_ENDPOINT="http://localhost:9000" \
        -e VAULT_DEV_ROOT_TOKEN_ID=verifier_root \
        -e VAULT_ADDR=http://localhost:9200 \
        -e VAULT_TOKEN=verifier_root \
        ghcr.io/hyperledger/identus-cloud-agent:1.33.0
    
    echo -e "${GREEN}✅ Verifier Agent container started${NC}"
}

# Test Verifier Agent
test_verifier_agent() {
    echo -e "${YELLOW}⏳ Waiting 30 seconds for verifier agent initialization...${NC}"
    sleep 30
    
    echo -e "${YELLOW}🔍 Testing Verifier Agent health...${NC}"
    
    local attempt=1
    while [ $attempt -le 8 ]; do
        echo -e "${YELLOW}  Attempt $attempt/8: Testing health endpoint...${NC}"
        
        local response=$(curl -s -w "%{http_code}" -o /tmp/verifier_health "http://localhost:9000/_system/health" 2>/dev/null || echo "000")
        
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
    if netstat -ln 2>/dev/null | grep -q ":9001 "; then
        echo -e "${GREEN}✅ Verifier DIDComm port 9001 is listening${NC}"
    else
        echo -e "${YELLOW}⚠️  Verifier DIDComm port 9001 not listening${NC}"
    fi
    
    # Test presentations endpoint
    local api_response=$(curl -s -w "%{http_code}" -o /tmp/verifier_api_test "http://localhost:9000/present-proof/presentations" 2>/dev/null || echo "000")
    if [ "$api_response" = "200" ]; then
        echo -e "${GREEN}✅ Verifier presentations endpoint responding${NC}"
    elif [ "$api_response" = "401" ] || [ "$api_response" = "404" ]; then
        echo -e "${GREEN}✅ Verifier API endpoint responding (${api_response} expected)${NC}"
    else
        echo -e "${YELLOW}⚠️  Verifier presentations endpoint: HTTP $api_response${NC}"
    fi
}

# Show final status and information
show_status() {
    echo -e "${BLUE}📊 Verifier Agent Status:${NC}"
    echo ""
    
    echo -e "${YELLOW}Running Verifier Containers:${NC}"
    sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(verifier|PORTS)" || echo "No verifier containers running"
    echo ""
    
    echo -e "${YELLOW}Verifier Service Information:${NC}"
    echo -e "${CYAN}  PostgreSQL:     localhost:5434 (verifier_identus_db)${NC}"
    echo -e "${CYAN}  Vault:          http://localhost:9200${NC}"
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
    echo -e "${CYAN}  Stop:    sudo docker stop verifier-postgres verifier-vault verifier-agent${NC}"
    echo -e "${CYAN}  Remove:  sudo docker rm verifier-postgres verifier-vault verifier-agent${NC}"
    echo -e "${CYAN}  Cleanup: ./scripts/setup-verifier-agent.sh cleanup${NC}"
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
    if setup_postgresql; then
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
        echo -e "${RED}❌ FAILED: Verifier PostgreSQL setup failed${NC}"
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