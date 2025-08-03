#!/bin/bash

# Hyperledger Identus Cloud Agent Status Check Script
# Checks the health and status of all Identus agents

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Agent configuration
declare -A AGENTS=(
    ["Issuer"]="8000"
    ["Holder"]="7000"
    ["Verifier"]="9000"
)

# Function to check agent health
check_agent_health() {
    local agent_name=$1
    local port=$2
    
    echo -e "${CYAN}🔍 Checking $agent_name Agent (port $port)...${NC}"
    
    # Check if port is listening
    if ! netstat -ln 2>/dev/null | grep -q ":$port " && ! ss -ln 2>/dev/null | grep -q ":$port "; then
        echo -e "${RED}  ❌ Port $port is not listening${NC}"
        return 1
    fi
    
    # Check health endpoint
    local health_url="http://localhost:$port/_system/health"
    local response=$(curl -s -w "%{http_code}" -o /tmp/health_response_$port "$health_url" 2>/dev/null || echo "000")
    
    if [ "$response" = "200" ]; then
        echo -e "${GREEN}  ✅ $agent_name Agent is healthy${NC}"
        
        # Try to get additional info
        local info_url="http://localhost:$port/cloud-agent/_system/health"
        local info_response=$(curl -s "$info_url" 2>/dev/null || echo "{}")
        
        if [ "$info_response" != "{}" ]; then
            echo -e "${BLUE}  📊 Additional info available${NC}"
        fi
        
        return 0
    elif [ "$response" = "000" ]; then
        echo -e "${RED}  ❌ Connection refused or timeout${NC}"
        return 1
    else
        echo -e "${RED}  ❌ HTTP $response error${NC}"
        return 1
    fi
}

# Function to check Docker containers
check_docker_containers() {
    echo -e "${CYAN}🐳 Checking Docker containers...${NC}"
    
    local containers=("issuer" "holder" "verifier")
    local running_containers=0
    
    for container in "${containers[@]}"; do
        if docker ps --format "table {{.Names}}\t{{.Status}}" | grep -q "$container"; then
            local status=$(docker ps --format "table {{.Names}}\t{{.Status}}" | grep "$container" | awk '{$1=""; print $0}' | sed 's/^ *//')
            echo -e "${GREEN}  ✅ Container '$container': $status${NC}"
            ((running_containers++))
        else
            echo -e "${RED}  ❌ Container '$container': Not running${NC}"
        fi
    done
    
    echo -e "${BLUE}  📊 Running containers: $running_containers/3${NC}"
}

# Function to check network connectivity
check_network() {
    echo -e "${CYAN}🔗 Checking network connectivity...${NC}"
    
    if docker network ls | grep -q "identus-network"; then
        echo -e "${GREEN}  ✅ Docker network 'identus-network' exists${NC}"
    else
        echo -e "${RED}  ❌ Docker network 'identus-network' not found${NC}"
    fi
}

# Function to test API endpoints
test_api_endpoints() {
    echo -e "${CYAN}🔌 Testing API endpoints...${NC}"
    
    for agent_name in "${!AGENTS[@]}"; do
        local port=${AGENTS[$agent_name]}
        local api_url="http://localhost:$port/cloud-agent"
        
        echo -e "${YELLOW}  🔍 Testing $agent_name API: $api_url${NC}"
        
        local response=$(curl -s -w "%{http_code}" -o /dev/null "$api_url" 2>/dev/null || echo "000")
        
        if [ "$response" = "200" ] || [ "$response" = "404" ]; then
            echo -e "${GREEN}    ✅ API endpoint responding${NC}"
        else
            echo -e "${RED}    ❌ API endpoint not responding (HTTP $response)${NC}"
        fi
    done
}

# Function to show service URLs
show_service_urls() {
    echo -e "${CYAN}🌐 Service URLs:${NC}"
    echo -e "${BLUE}  Agent APIs:${NC}"
    echo -e "${BLUE}    Issuer:   http://localhost:8000/cloud-agent${NC}"
    echo -e "${BLUE}    Holder:   http://localhost:7000/cloud-agent${NC}"
    echo -e "${BLUE}    Verifier: http://localhost:9000/cloud-agent${NC}"
    echo ""
    echo -e "${BLUE}  Health Checks:${NC}"
    echo -e "${BLUE}    Issuer:   http://localhost:8000/_system/health${NC}"
    echo -e "${BLUE}    Holder:   http://localhost:7000/_system/health${NC}"
    echo -e "${BLUE}    Verifier: http://localhost:9000/_system/health${NC}"
    echo ""
    echo -e "${BLUE}  DIDComm Endpoints:${NC}"
    echo -e "${BLUE}    Issuer:   http://localhost:8001${NC}"
    echo -e "${BLUE}    Holder:   http://localhost:7001${NC}"
    echo -e "${BLUE}    Verifier: http://localhost:9001${NC}"
}

# Function to generate status summary
generate_summary() {
    local healthy_count=0
    local total_count=${#AGENTS[@]}
    
    echo -e "${CYAN}📋 Status Summary:${NC}"
    
    for agent_name in "${!AGENTS[@]}"; do
        local port=${AGENTS[$agent_name]}
        
        if curl -s -f "http://localhost:$port/_system/health" > /dev/null 2>&1; then
            echo -e "${GREEN}  ✅ $agent_name Agent: Healthy${NC}"
            ((healthy_count++))
        else
            echo -e "${RED}  ❌ $agent_name Agent: Unhealthy or not running${NC}"
        fi
    done
    
    echo ""
    echo -e "${BLUE}  📊 Overall Status: $healthy_count/$total_count agents healthy${NC}"
    
    if [ $healthy_count -eq $total_count ]; then
        echo -e "${GREEN}  🎉 All agents are running successfully!${NC}"
        return 0
    else
        echo -e "${YELLOW}  ⚠️  Some agents are not healthy${NC}"
        return 1
    fi
}

# Main function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} Hyperledger Identus Agent Status Check${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Check each agent
    for agent_name in "${!AGENTS[@]}"; do
        check_agent_health "$agent_name" "${AGENTS[$agent_name]}"
        echo ""
    done
    
    # Check Docker containers
    check_docker_containers
    echo ""
    
    # Check network
    check_network
    echo ""
    
    # Test API endpoints
    test_api_endpoints
    echo ""
    
    # Show service URLs
    show_service_urls
    echo ""
    
    # Generate summary
    generate_summary
    
    echo ""
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} Status check completed${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    echo -e "${YELLOW}💡 Commands:${NC}"
    echo -e "${YELLOW}  Start agents: ./scripts/setup-identus-agents.sh${NC}"
    echo -e "${YELLOW}  Stop agents:  ./scripts/stop-identus-agents.sh${NC}"
    echo -e "${YELLOW}  Check status: ./scripts/check-identus-status.sh${NC}"
}

# Run main function
main "$@"