#!/bin/bash

# Identus PostgreSQL Database Container Setup
# Creates shared PostgreSQL database for all Identus agents

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
POSTGRES_PORT="5432"
POSTGRES_USER="postgres"
POSTGRES_PASSWORD="postgres"
POSTGRES_DB="identus_db"

echo -e "${BLUE}🗄️  Identus PostgreSQL Database Setup${NC}"
echo -e "${BLUE}=====================================${NC}"
echo -e "${CYAN}Container: $POSTGRES_CONTAINER${NC}"
echo -e "${CYAN}Port: $POSTGRES_PORT${NC}"
echo -e "${CYAN}Database: $POSTGRES_DB${NC}"
echo ""

# Clean up function
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up database container...${NC}"
    sudo docker stop $POSTGRES_CONTAINER 2>/dev/null || true
    sudo docker rm $POSTGRES_CONTAINER 2>/dev/null || true
}

# Setup PostgreSQL database container
setup_database() {
    echo -e "${YELLOW}🗄️  Setting up PostgreSQL database container...${NC}"
    
    sudo docker run -d \
        --name $POSTGRES_CONTAINER \
        --network host \
        -e POSTGRES_DB=$POSTGRES_DB \
        -e POSTGRES_USER=$POSTGRES_USER \
        -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
        -e PGPORT=$POSTGRES_PORT \
        postgres:15 \
        -c max_connections=300 \
        -c shared_buffers=256MB \
        -c log_statement=all \
        -c log_destination=stderr
    
    echo -e "${GREEN}✅ PostgreSQL container started${NC}"
    
    # Wait for PostgreSQL to be ready
    echo -e "${YELLOW}⏳ Waiting for PostgreSQL to be ready...${NC}"
    local attempt=1
    while [ $attempt -le 15 ]; do
        if sudo docker exec $POSTGRES_CONTAINER pg_isready -U $POSTGRES_USER -d $POSTGRES_DB > /dev/null 2>&1; then
            echo -e "${GREEN}✅ PostgreSQL is ready${NC}"
            break
        fi
        echo -e "${YELLOW}  Attempt $attempt/15: PostgreSQL not ready yet${NC}"
        sleep 3
        ((attempt++))
        if [ $attempt -gt 15 ]; then
            echo -e "${RED}❌ PostgreSQL failed to start${NC}"
            return 1
        fi
    done
    
    # Show database info
    echo -e "${CYAN}📊 Database container information:${NC}"
    sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT version();" | head -1
    echo -e "${CYAN}  Max connections: $(sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -d $POSTGRES_DB -t -c "SHOW max_connections;" | xargs)${NC}"
    
    return 0
}

# Test database connectivity
test_database() {
    echo -e "${YELLOW}🔍 Testing database connectivity...${NC}"
    
    # Test connection
    if sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT 1;" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Database connection successful${NC}"
    else
        echo -e "${RED}❌ Database connection failed${NC}"
        return 1
    fi
    
    # Show existing databases
    echo -e "${CYAN}📋 Existing databases:${NC}"
    sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -l | grep -E "^\s+\w+\s+\|" | head -10
}

# Show database status
show_status() {
    echo -e "${BLUE}📊 Database Status:${NC}"
    echo ""
    
    echo -e "${YELLOW}Running Database Container:${NC}"
    sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "($POSTGRES_CONTAINER|PORTS)" || echo "No database container running"
    echo ""
    
    echo -e "${YELLOW}Database Service Information:${NC}"
    echo -e "${CYAN}  PostgreSQL:     localhost:$POSTGRES_PORT${NC}"
    echo -e "${CYAN}  Database:       $POSTGRES_DB${NC}"
    echo -e "${CYAN}  Username:       $POSTGRES_USER${NC}"
    echo ""
    
    echo -e "${YELLOW}Connection Commands:${NC}"
    echo -e "${CYAN}  Connect:        sudo docker exec -it $POSTGRES_CONTAINER psql -U $POSTGRES_USER -d $POSTGRES_DB${NC}"
    echo -e "${CYAN}  List DBs:       sudo docker exec $POSTGRES_CONTAINER psql -U $POSTGRES_USER -l${NC}"
    echo -e "${CYAN}  Test:           sudo docker exec $POSTGRES_CONTAINER pg_isready -U $POSTGRES_USER${NC}"
    echo ""
    
    echo -e "${YELLOW}Management Commands:${NC}"
    echo -e "${CYAN}  Stop:           sudo docker stop $POSTGRES_CONTAINER${NC}"
    echo -e "${CYAN}  Remove:         sudo docker rm $POSTGRES_CONTAINER${NC}"
    echo -e "${CYAN}  Restart:        ./scripts/setup-database.sh${NC}"
    echo -e "${CYAN}  Cleanup:        ./scripts/setup-database.sh cleanup${NC}"
}

# Main setup function
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE} Starting Database Setup${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Clean up any existing setup
    cleanup
    sleep 2
    
    # Setup database
    if setup_database; then
        if test_database; then
            echo ""
            echo -e "${BLUE}===============================================${NC}"
            echo -e "${GREEN}🎉 SUCCESS: Database is running!${NC}"
            echo -e "${BLUE}===============================================${NC}"
            
            show_status
        else
            echo -e "${RED}❌ FAILED: Database test failed${NC}"
        fi
    else
        echo -e "${RED}❌ FAILED: Database setup failed${NC}"
    fi
}

# Handle cleanup command
if [ "$1" = "cleanup" ]; then
    cleanup
    echo -e "${GREEN}✅ Database cleanup completed${NC}"
    exit 0
fi

# Handle status command
if [ "$1" = "status" ]; then
    show_status
    exit 0
fi

# Run main function
main "$@"