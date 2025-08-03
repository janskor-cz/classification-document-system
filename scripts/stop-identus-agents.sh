#!/bin/bash

# Hyperledger Identus Cloud Agent Stop Script
# Stops all running Identus agents

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛑 Stopping Hyperledger Identus Cloud Agents${NC}"
echo ""

# Function to stop agent
stop_agent() {
    local agent_name=$1
    local repo_dir="./identus-cloud-agent"
    
    if [ -d "$repo_dir" ]; then
        echo -e "${YELLOW}🛑 Stopping $agent_name agent...${NC}"
        cd "$repo_dir"
        
        # Make stop script executable
        chmod +x infrastructure/local/stop.sh
        
        # Stop the specific agent
        ./infrastructure/local/stop.sh -n "$agent_name" || echo -e "${YELLOW}⚠️  $agent_name agent may not be running${NC}"
        
        cd ..
        echo -e "${GREEN}✅ $agent_name agent stopped${NC}"
    else
        echo -e "${YELLOW}⚠️  Identus repository not found, skipping $agent_name${NC}"
    fi
}

# Function to stop Docker containers by name pattern
stop_docker_containers() {
    echo -e "${YELLOW}🐳 Stopping Docker containers...${NC}"
    
    local containers=(
        "issuer"
        "holder" 
        "verifier"
    )
    
    for container in "${containers[@]}"; do
        if docker ps -q -f name="$container" | grep -q .; then
            echo -e "${YELLOW}🛑 Stopping container: $container${NC}"
            docker stop "$container" || echo -e "${YELLOW}⚠️  Failed to stop $container${NC}"
        else
            echo -e "${YELLOW}ℹ️  Container $container not running${NC}"
        fi
    done
}

# Function to remove Docker containers
remove_docker_containers() {
    echo -e "${YELLOW}🗑️  Removing Docker containers...${NC}"
    
    local containers=(
        "issuer"
        "holder"
        "verifier"
    )
    
    for container in "${containers[@]}"; do
        if docker ps -a -q -f name="$container" | grep -q .; then
            echo -e "${YELLOW}🗑️  Removing container: $container${NC}"
            docker rm "$container" || echo -e "${YELLOW}⚠️  Failed to remove $container${NC}"
        else
            echo -e "${YELLOW}ℹ️  Container $container not found${NC}"
        fi
    done
}

# Function to clean up network
cleanup_network() {
    local network_name="identus-network"
    
    if docker network ls | grep -q "$network_name"; then
        echo -e "${YELLOW}🔗 Removing Docker network: $network_name${NC}"
        docker network rm "$network_name" || echo -e "${YELLOW}⚠️  Failed to remove network${NC}"
    else
        echo -e "${YELLOW}ℹ️  Network $network_name not found${NC}"
    fi
}

# Function to check if any agents are still running
check_agent_status() {
    local ports=(8000 7000 9000)
    local agents=("Issuer" "Holder" "Verifier")
    local running_count=0
    
    echo -e "${YELLOW}🔍 Checking agent status...${NC}"
    
    for i in "${!ports[@]}"; do
        local port=${ports[$i]}
        local agent=${agents[$i]}
        
        if curl -f -s "http://localhost:$port/_system/health" > /dev/null 2>&1; then
            echo -e "${RED}⚠️  $agent agent still running on port $port${NC}"
            ((running_count++))
        else
            echo -e "${GREEN}✅ $agent agent stopped (port $port)${NC}"
        fi
    done
    
    if [ $running_count -eq 0 ]; then
        echo -e "${GREEN}✅ All agents successfully stopped${NC}"
    else
        echo -e "${YELLOW}⚠️  $running_count agent(s) may still be running${NC}"
    fi
}

# Main stop function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} Stopping Hyperledger Identus Cloud Agents${NC}"
    echo -e "${BLUE}================================================${NC}"
    
    # Stop agents using official scripts
    stop_agent "issuer"
    stop_agent "holder"
    stop_agent "verifier"
    
    sleep 5
    
    # Fallback: stop Docker containers directly
    stop_docker_containers
    
    sleep 2
    
    # Remove containers
    remove_docker_containers
    
    # Clean up network
    cleanup_network
    
    sleep 2
    
    # Final status check
    check_agent_status
    
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN} 🛑 All Identus agents stopped${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo -e "${YELLOW}💡 To start agents again, run: ./scripts/setup-identus-agents.sh${NC}"
}

# Run main function
main "$@"