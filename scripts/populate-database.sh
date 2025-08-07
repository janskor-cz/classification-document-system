#!/bin/bash

# Identus Database Population Script
# Creates databases, users, and grants privileges for all Identus agents
# Called automatically by setup-agents.sh when needed

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
POSTGRES_USER="postgres"

echo -e "${BLUE}📝 Identus Database Population${NC}"
echo -e "${BLUE}==============================${NC}"
echo -e "${CYAN}Container: $POSTGRES_CONTAINER${NC}"
echo ""

# Check if database container is running
check_database_container() {
    echo -e "${YELLOW}🔍 Checking database container...${NC}"
    
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
    
    echo -e "${GREEN}✅ Database container is accessible${NC}"
    return 0
}

# Create databases for an agent
create_agent_databases() {
    local agent_name=$1
    local main_db="${agent_name}_identus_db"
    
    echo -e "${YELLOW}🏗️  Creating databases for $agent_name agent...${NC}"
    
    # Create main database
    echo -e "${CYAN}  Creating database: $main_db${NC}"
    sudo docker exec $POSTGRES_CONTAINER createdb -U $POSTGRES_USER $main_db 2>/dev/null || echo "    Database may already exist"
    
    # Create Identus-specific databases (required for agent functionality)
    local identus_dbs=("pollux" "connect" "agent" "node_db")
    
    for db in "${identus_dbs[@]}"; do
        echo -e "${CYAN}  Creating database: $db${NC}"
        sudo docker exec $POSTGRES_CONTAINER createdb -U $POSTGRES_USER $db 2>/dev/null || echo "    Database may already exist"
    done
    
    echo -e "${GREEN}✅ Databases created for $agent_name${NC}"
}

# Create users for an agent
create_agent_users() {
    local agent_name=$1
    
    echo -e "${YELLOW}👥 Creating users for $agent_name agent...${NC}"
    
    # Define agent-specific users
    local agent_users=(
        "${agent_name}_user:${agent_name}_pass"
    )
    
    for user_info in "${agent_users[@]}"; do
        local username="${user_info%:*}"
        local password="${user_info#*:}"
        
        echo -e "${CYAN}  Creating agent user: $username${NC}"
        sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -c "CREATE USER \"$username\" WITH PASSWORD '$password';" 2>/dev/null || echo "    User may already exist"
    done
    
    echo -e "${GREEN}✅ Agent-specific users created for $agent_name${NC}"
}

# Create global users expected by Identus agents
create_global_identus_users() {
    echo -e "${YELLOW}👥 Creating global Identus application users...${NC}"
    
    # Define global users that all agents expect
    local global_users=(
        "pollux-application-user:pollux_pass"
        "connect-application-user:connect_pass" 
        "agent-application-user:agent_pass"
    )
    
    for user_info in "${global_users[@]}"; do
        local username="${user_info%:*}"
        local password="${user_info#*:}"
        
        echo -e "${CYAN}  Creating global user: $username${NC}"
        sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -c "CREATE USER \"$username\" WITH PASSWORD '$password';" 2>/dev/null || echo "    User may already exist"
    done
    
    echo -e "${GREEN}✅ Global Identus users created${NC}"
}

# Grant privileges for all users (global and agent-specific)
grant_all_privileges() {
    echo -e "${YELLOW}🔑 Granting privileges to all users on all databases...${NC}"
    
    # Grant privileges to global users on all databases
    local global_users=("pollux-application-user" "connect-application-user" "agent-application-user")
    local agents=("issuer" "holder" "verifier")
    local databases=("pollux" "connect" "agent" "node_db" "identus_db")
    
    # Add agent-specific databases
    for agent in "${agents[@]}"; do
        databases+=("${agent}_identus_db")
    done
    
    # Grant privileges to global users
    for user in "${global_users[@]}"; do
        for db in "${databases[@]}"; do
            echo -e "${CYAN}  Granting privileges on $db to $user${NC}"
            sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -c "GRANT ALL PRIVILEGES ON DATABASE $db TO \"$user\";" 2>/dev/null || true
        done
    done
    
    # Grant privileges to agent-specific users
    for agent in "${agents[@]}"; do
        local agent_user="${agent}_user"
        for db in "${databases[@]}"; do
            echo -e "${CYAN}  Granting privileges on $db to $agent_user${NC}"
            sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -c "GRANT ALL PRIVILEGES ON DATABASE $db TO \"$agent_user\";" 2>/dev/null || true
        done
    done
    
    echo -e "${GREEN}✅ All privileges granted${NC}"
}

# Setup complete agent database configuration
setup_agent_database() {
    local agent_name=$1
    
    echo -e "${BLUE}🔧 Setting up database configuration for $agent_name...${NC}"
    
    create_agent_databases $agent_name
    create_agent_users $agent_name
    
    echo -e "${GREEN}✅ Database setup for $agent_name completed${NC}"
    echo ""
}

# Verify agent database setup
verify_agent_setup() {
    local agent_name=$1
    local main_db="${agent_name}_identus_db"
    
    echo -e "${YELLOW}🔍 Verifying $agent_name database setup...${NC}"
    
    # Check if main database exists
    local db_exists=$(sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -t -c "SELECT 1 FROM pg_database WHERE datname='$main_db';" | xargs)
    
    # Check if main user exists
    local user_exists=$(sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -t -c "SELECT 1 FROM pg_roles WHERE rolname='${agent_name}_user';" | xargs)
    
    if [ "$db_exists" = "1" ] && [ "$user_exists" = "1" ]; then
        echo -e "${GREEN}✅ $agent_name database setup verified${NC}"
        return 0
    else
        echo -e "${RED}❌ $agent_name database setup verification failed${NC}"
        echo -e "${CYAN}  Database '$main_db' exists: $([ "$db_exists" = "1" ] && echo "Yes" || echo "No")${NC}"
        echo -e "${CYAN}  User '${agent_name}_user' exists: $([ "$user_exists" = "1" ] && echo "Yes" || echo "No")${NC}"
        return 1
    fi
}

# Show database information
show_database_info() {
    echo -e "${BLUE}📊 Database Information:${NC}"
    echo ""
    
    echo -e "${YELLOW}All Databases:${NC}"
    sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -l | grep -E "^\s+\w+\s+\|" | head -15
    echo ""
    
    echo -e "${YELLOW}All Users:${NC}"
    sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -c "SELECT rolname FROM pg_roles WHERE rolname LIKE '%identus%' OR rolname LIKE '%user' OR rolname LIKE '%application%' ORDER BY rolname;" | grep -v "^-" | grep -v "rolname" | grep -v "rows)" | head -15
    echo ""
    
    echo -e "${YELLOW}Database Sizes:${NC}"
    sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -c "SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size FROM pg_database WHERE datname LIKE '%identus%' OR datname IN ('pollux', 'connect', 'agent', 'node_db') ORDER BY datname;" | head -10
}

# Main population function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} Starting Database Population${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Check database container
    if ! check_database_container; then
        echo -e "${RED}❌ Database container check failed${NC}"
        exit 1
    fi
    
    # Setup each agent's database configuration
    local agents=("issuer" "holder" "verifier")
    local all_success=true
    
    for agent in "${agents[@]}"; do
        setup_agent_database $agent
        if ! verify_agent_setup $agent; then
            all_success=false
        fi
    done
    
    # Create global users that all agents expect
    create_global_identus_users
    
    # Grant all privileges
    grant_all_privileges
    
    echo ""
    if [ "$all_success" = true ]; then
        echo -e "${BLUE}===============================================${NC}"
        echo -e "${GREEN}🎉 SUCCESS: Database population completed!${NC}"
        echo -e "${BLUE}===============================================${NC}"
    else
        echo -e "${BLUE}===============================================${NC}"
        echo -e "${RED}❌ FAILED: Some database setups failed${NC}"
        echo -e "${BLUE}===============================================${NC}"
        exit 1
    fi
    
    show_database_info
    
    echo ""
    echo -e "${CYAN}💡 Database is now ready for Identus agents${NC}"
    echo -e "${CYAN}💡 You can now run './scripts/setup-agents.sh' to start the agents${NC}"
}

# Handle info command
if [ "$1" = "info" ]; then
    if check_database_container; then
        show_database_info
    fi
    exit 0
fi

# Run main function
main "$@"