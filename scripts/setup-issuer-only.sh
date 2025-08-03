#!/bin/bash

# Minimal Hyperledger Identus Issuer Agent Setup
# Sets up only PostgreSQL, Vault, and Issuer Agent - PROVEN WORKING CONFIGURATION

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Minimal Identus Issuer Agent Setup${NC}"
echo -e "${BLUE}====================================${NC}"
echo ""

# Clean up function
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up containers...${NC}"
    sudo docker stop issuer-postgres issuer-vault issuer-agent 2>/dev/null || true
    sudo docker rm issuer-postgres issuer-vault issuer-agent 2>/dev/null || true
}

# Setup PostgreSQL with required configuration
setup_postgresql() {
    echo -e "${YELLOW}🗄️  Setting up PostgreSQL...${NC}"
    
    sudo docker run -d \
        --name issuer-postgres \
        --network host \
        -e POSTGRES_DB=identus_db \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD=postgres \
        postgres:15
    
    echo -e "${GREEN}✅ PostgreSQL container started${NC}"
    
    # Wait for PostgreSQL
    echo -e "${YELLOW}⏳ Waiting for PostgreSQL...${NC}"
    local attempt=1
    while [ $attempt -le 12 ]; do
        if sudo docker exec issuer-postgres pg_isready -U postgres -d identus_db > /dev/null 2>&1; then
            echo -e "${GREEN}✅ PostgreSQL is ready${NC}"
            break
        fi
        echo -e "${YELLOW}  Attempt $attempt/12: PostgreSQL not ready yet${NC}"
        sleep 3
        ((attempt++))
        if [ $attempt -gt 12 ]; then
            echo -e "${RED}❌ PostgreSQL failed to start${NC}"
            return 1
        fi
    done
    
    # Create required databases for Identus
    echo -e "${YELLOW}🏗️  Creating Identus databases...${NC}"
    sudo docker exec issuer-postgres createdb -U postgres pollux 2>/dev/null || true
    sudo docker exec issuer-postgres createdb -U postgres connect 2>/dev/null || true
    sudo docker exec issuer-postgres createdb -U postgres agent 2>/dev/null || true
    sudo docker exec issuer-postgres createdb -U postgres node_db 2>/dev/null || true
    
    # Create required application users
    echo -e "${YELLOW}👥 Creating application users...${NC}"
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"pollux-application-user\" WITH PASSWORD 'pollux_pass';" 2>/dev/null || true
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"connect-application-user\" WITH PASSWORD 'connect_pass';" 2>/dev/null || true
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"agent-application-user\" WITH PASSWORD 'agent_pass';" 2>/dev/null || true
    sudo docker exec issuer-postgres psql -U postgres -c "CREATE USER \"identus_user\" WITH PASSWORD 'identus_pass';" 2>/dev/null || true
    
    # Grant all necessary privileges
    echo -e "${YELLOW}🔑 Granting database privileges...${NC}"
    sudo docker exec issuer-postgres psql -U postgres -c "
        GRANT ALL PRIVILEGES ON DATABASE pollux TO \"pollux-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE connect TO \"connect-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE agent TO \"agent-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE identus_db TO identus_user;
        GRANT ALL PRIVILEGES ON DATABASE node_db TO identus_user;
        GRANT ALL PRIVILEGES ON DATABASE identus_db TO \"pollux-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE identus_db TO \"connect-application-user\";
        GRANT ALL PRIVILEGES ON DATABASE identus_db TO \"agent-application-user\";
    " 2>/dev/null || true
    
    echo -e "${GREEN}✅ PostgreSQL setup completed${NC}"
}

# Setup Vault in development mode
setup_vault() {
    echo -e "${YELLOW}🔐 Setting up Vault...${NC}"
    
    sudo docker run -d \
        --name issuer-vault \
        --network host \
        --cap-add=IPC_LOCK \
        -e VAULT_DEV_ROOT_TOKEN_ID=root \
        -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
        hashicorp/vault:latest
    
    echo -e "${GREEN}✅ Vault container started${NC}"
    
    # Wait for Vault
    echo -e "${YELLOW}⏳ Waiting for Vault...${NC}"
    local attempt=1
    while [ $attempt -le 10 ]; do
        if curl -s http://localhost:8200/v1/sys/health > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Vault is ready${NC}"
            return 0
        fi
        echo -e "${YELLOW}  Attempt $attempt/10: Vault not ready yet${NC}"
        sleep 3
        ((attempt++))
    done
    
    echo -e "${RED}❌ Vault failed to start${NC}"
    return 1
}

# Start Identus Issuer Agent
start_issuer_agent() {
    echo -e "${YELLOW}🚀 Starting Identus Issuer Agent...${NC}"
    
    sudo docker run -d \
        --name issuer-agent \
        --network host \
        -e API_KEY_ENABLED=false \
        -e AGENT_VERSION=1.33.0 \
        -e PORT=8080 \
        -e PG_HOST=localhost \
        -e PG_PORT=5432 \
        -e PG_DATABASE=identus_db \
        -e PG_USERNAME=postgres \
        -e PG_PASSWORD=postgres \
        -e AGENT_HTTP_PORT=8080 \
        -e AGENT_DIDCOMM_PORT=8090 \
        -e AGENT_HTTP_ENDPOINT="http://localhost:8080" \
        -e VAULT_DEV_ROOT_TOKEN_ID=root \
        -e VAULT_ADDR=http://localhost:8200 \
        -e VAULT_TOKEN=root \
        ghcr.io/hyperledger/identus-cloud-agent:1.33.0
    
    echo -e "${GREEN}✅ Issuer Agent container started${NC}"
}

# Test Issuer Agent
test_issuer_agent() {
    echo -e "${YELLOW}⏳ Waiting 30 seconds for agent initialization...${NC}"
    sleep 30
    
    echo -e "${YELLOW}🔍 Testing Issuer Agent health...${NC}"
    
    local attempt=1
    while [ $attempt -le 8 ]; do
        echo -e "${YELLOW}  Attempt $attempt/8: Testing health endpoint...${NC}"
        
        local response=$(curl -s -w "%{http_code}" -o /tmp/issuer_health "http://localhost:8080/_system/health" 2>/dev/null || echo "000")
        
        if [ "$response" = "200" ]; then
            echo -e "${GREEN}🎉 SUCCESS: Issuer Agent is healthy!${NC}"
            local health_content=$(cat /tmp/issuer_health)
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
    
    echo -e "${RED}❌ Issuer Agent health check failed${NC}"
    return 1
}

# Test additional endpoints
test_endpoints() {
    echo -e "${YELLOW}🔍 Testing additional endpoints...${NC}"
    
    # Test DIDComm port
    if netstat -ln 2>/dev/null | grep -q ":8090 "; then
        echo -e "${GREEN}✅ DIDComm port 8090 is listening${NC}"
    else
        echo -e "${YELLOW}⚠️  DIDComm port 8090 not listening${NC}"
    fi
    
    # Test main API endpoint
    local api_response=$(curl -s -w "%{http_code}" -o /tmp/api_test "http://localhost:8080/cloud-agent" 2>/dev/null || echo "000")
    if [ "$api_response" = "404" ]; then
        echo -e "${GREEN}✅ Main API endpoint responding (404 expected for root)${NC}"
    elif [ "$api_response" = "200" ]; then
        echo -e "${GREEN}✅ Main API endpoint responding${NC}"
    else
        echo -e "${YELLOW}⚠️  Main API endpoint: HTTP $api_response${NC}"
    fi
}

# Show final status and information
show_status() {
    echo -e "${BLUE}📊 Issuer Agent Status:${NC}"
    echo ""
    
    echo -e "${YELLOW}Running Containers:${NC}"
    sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(issuer|PORTS)" || echo "No containers running"
    echo ""
    
    echo -e "${YELLOW}Service Information:${NC}"
    echo -e "${CYAN}  PostgreSQL:     localhost:5432${NC}"
    echo -e "${CYAN}  Vault:          http://localhost:8200${NC}"
    echo -e "${CYAN}  Issuer Agent:   http://localhost:8080${NC}"
    echo ""
    
    echo -e "${YELLOW}Key Endpoints:${NC}"
    echo -e "${CYAN}  Health Check:   http://localhost:8080/_system/health${NC}"
    echo -e "${CYAN}  API Root:       http://localhost:8080/cloud-agent${NC}"
    echo -e "${CYAN}  DIDComm:        http://localhost:8090${NC}"
    echo ""
    
    echo -e "${YELLOW}Testing Commands:${NC}"
    echo -e "${CYAN}  curl http://localhost:8080/_system/health${NC}"
    echo -e "${CYAN}  curl http://localhost:8080/cloud-agent${NC}"
    echo ""
    
    echo -e "${YELLOW}Management Commands:${NC}"
    echo -e "${CYAN}  Stop:    sudo docker stop issuer-postgres issuer-vault issuer-agent${NC}"
    echo -e "${CYAN}  Remove:  sudo docker rm issuer-postgres issuer-vault issuer-agent${NC}"
    echo -e "${CYAN}  Cleanup: ./scripts/setup-issuer-only.sh cleanup${NC}"
}

# Main setup function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} Starting Issuer Agent Setup${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Clean up any existing setup
    cleanup
    sleep 2
    
    # Setup components step by step
    if setup_postgresql; then
        if setup_vault; then
            start_issuer_agent
            
            if test_issuer_agent; then
                test_endpoints
                
                echo ""
                echo -e "${BLUE}===============================================${NC}"
                echo -e "${GREEN}🎉 SUCCESS: Issuer Agent is running!${NC}"
                echo -e "${BLUE}===============================================${NC}"
                
                show_status
                
            else
                echo -e "${RED}❌ FAILED: Issuer Agent test failed${NC}"
                echo -e "${YELLOW}Checking logs...${NC}"
                sudo docker logs issuer-agent --tail 10 2>/dev/null || echo "No logs available"
            fi
        else
            echo -e "${RED}❌ FAILED: Vault setup failed${NC}"
        fi
    else
        echo -e "${RED}❌ FAILED: PostgreSQL setup failed${NC}"
    fi
}

# Handle cleanup command
if [ "$1" = "cleanup" ]; then
    cleanup
    echo -e "${GREEN}✅ Cleanup completed${NC}"
    exit 0
fi

# Run main function
main "$@"