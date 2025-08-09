#!/bin/bash

# Classification Document System - Comprehensive Startup Script
# 
# This script provides an easy way to start the complete Classification Document System
# with full SSI (Self-Sovereign Identity) capabilities using Hyperledger Identus.
#
# Features:
# - Automated environment setup with virtual environment
# - Complete database initialization (PostgreSQL)
# - Full 3-agent Identus SSI system (Issuer, Holder, Verifier)
# - Flask application with comprehensive credential management
# - Health checks and status monitoring
# - Cleanup and management commands
#
# Usage:
#   ./start.sh                # Full startup (recommended)
#   ./start.sh quick          # Start Flask app only (basic functionality)
#   ./start.sh database       # Setup database only
#   ./start.sh agents         # Setup Identus agents only
#   ./start.sh status         # Show system status
#   ./start.sh cleanup        # Stop all services
#   ./start.sh help           # Show this help
#
# Prerequisites:
# - Docker must be installed and running
# - Python 3.8+ must be available
# - All required ports must be free (5000, 5432, 8080, 7000, 9000, 8200, 7200, 9200)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"
FLASK_APP="app.py"
FLASK_PORT="5000"

# Show banner
show_banner() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}🏢 Classification Document System${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo -e "${CYAN}A comprehensive Flask-based web application${NC}"
    echo -e "${CYAN}with Hyperledger Identus SSI integration${NC}"
    echo ""
    echo -e "${YELLOW}Features:${NC}"
    echo -e "${CYAN}  ✅ Document Classification (Public/Internal/Confidential)${NC}"
    echo -e "${CYAN}  ✅ Self-Sovereign Identity (SSI) with Verifiable Credentials${NC}"
    echo -e "${CYAN}  ✅ Admin Panel for Credential Management${NC}"
    echo -e "${CYAN}  ✅ Complete User Authentication & Authorization${NC}"
    echo -e "${CYAN}  ✅ Multi-Agent Identus Infrastructure${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}🔍 Checking prerequisites...${NC}"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker is required but not installed${NC}"
        echo -e "${CYAN}💡 Please install Docker: https://docs.docker.com/get-docker/${NC}"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker ps &> /dev/null; then
        echo -e "${RED}❌ Docker daemon is not running${NC}"
        echo -e "${CYAN}💡 Please start Docker daemon${NC}"
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 is required but not installed${NC}"
        echo -e "${CYAN}💡 Please install Python 3.8+${NC}"
        exit 1
    fi
    
    # Check sudo access for Docker
    if ! sudo docker ps &> /dev/null; then
        echo -e "${RED}❌ Sudo access required for Docker commands${NC}"
        echo -e "${CYAN}💡 Please ensure your user can run sudo docker commands${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ All prerequisites met${NC}"
}

# Setup Python virtual environment
setup_python_env() {
    echo -e "${YELLOW}🐍 Setting up Python environment...${NC}"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "${CYAN}  Creating virtual environment...${NC}"
        python3 -m venv "$VENV_DIR"
    fi
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip &> /dev/null
    
    # Install requirements
    if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        echo -e "${CYAN}  Installing Python dependencies...${NC}"
        pip install -r "$SCRIPT_DIR/requirements.txt" &> /dev/null
        echo -e "${GREEN}✅ Python dependencies installed${NC}"
    else
        echo -e "${YELLOW}⚠️  requirements.txt not found, skipping dependency installation${NC}"
    fi
}

# Setup environment file
setup_env_file() {
    echo -e "${YELLOW}📝 Setting up environment configuration...${NC}"
    
    if [ ! -f "$SCRIPT_DIR/.env" ] && [ -f "$SCRIPT_DIR/.env.example" ]; then
        echo -e "${CYAN}  Copying .env.example to .env${NC}"
        cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
        echo -e "${GREEN}✅ Environment file created${NC}"
        echo -e "${CYAN}💡 You may want to customize .env for your specific settings${NC}"
    elif [ -f "$SCRIPT_DIR/.env" ]; then
        echo -e "${GREEN}✅ Environment file already exists${NC}"
    else
        echo -e "${YELLOW}⚠️  No .env.example found, skipping environment setup${NC}"
    fi
}

# Setup database
setup_database() {
    echo -e "${YELLOW}🗄️  Setting up PostgreSQL database...${NC}"
    
    if [ -f "$SCRIPT_DIR/scripts/setup-database.sh" ]; then
        cd "$SCRIPT_DIR"
        ./scripts/setup-database.sh
        
        # Initialize Flask application database schema
        if [ -f "$SCRIPT_DIR/scripts/init-db.sql" ]; then
            echo -e "${CYAN}  Initializing Flask application schema...${NC}"
            sudo docker exec identus-postgres psql -U postgres -d identus_db -f /dev/stdin < "$SCRIPT_DIR/scripts/init-db.sql" &> /dev/null || true
            echo -e "${GREEN}✅ Flask application schema initialized${NC}"
        fi
    else
        echo -e "${RED}❌ Database setup script not found at scripts/setup-database.sh${NC}"
        exit 1
    fi
}

# Setup Identus agents
setup_agents() {
    echo -e "${YELLOW}🚀 Setting up Identus agents...${NC}"
    
    if [ -f "$SCRIPT_DIR/scripts/setup-agents.sh" ]; then
        cd "$SCRIPT_DIR"
        ./scripts/setup-agents.sh
    else
        echo -e "${RED}❌ Agents setup script not found at scripts/setup-agents.sh${NC}"
        exit 1
    fi
}

# Start Flask application
start_flask() {
    echo -e "${YELLOW}🌐 Starting Flask application...${NC}"
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Change to script directory
    cd "$SCRIPT_DIR"
    
    # Check if Flask app file exists
    if [ ! -f "$FLASK_APP" ]; then
        echo -e "${RED}❌ Flask application file '$FLASK_APP' not found${NC}"
        exit 1
    fi
    
    echo -e "${CYAN}  Starting Flask development server on port $FLASK_PORT...${NC}"
    echo -e "${CYAN}  Flask app: $FLASK_APP${NC}"
    echo -e "${CYAN}  Access URL: http://localhost:$FLASK_PORT${NC}"
    echo ""
    echo -e "${MAGENTA}🔑 Login Credentials:${NC}"
    echo -e "${CYAN}  Admin: admin@company.com / admin123${NC}"
    echo -e "${CYAN}  User:  john.doe@company.com / john123${NC}"
    echo -e "${CYAN}  User:  jane.smith@company.com / jane123${NC}"
    echo ""
    echo -e "${YELLOW}📖 Key Features:${NC}"
    echo -e "${CYAN}  • Document Upload & Classification${NC}"
    echo -e "${CYAN}  • Verifiable Credential Management${NC}"
    echo -e "${CYAN}  • Admin Panel (/admin)${NC}"
    echo -e "${CYAN}  • Complete SSI Workflow${NC}"
    echo ""
    echo -e "${YELLOW}Press Ctrl+C to stop the application${NC}"
    echo -e "${BLUE}================================================${NC}"
    
    # Start Flask app
    python "$FLASK_APP"
}

# Check system status
check_status() {
    echo -e "${YELLOW}📊 System Status Check${NC}"
    echo ""
    
    # Check database
    echo -e "${CYAN}Database Status:${NC}"
    if sudo docker ps | grep -q "identus-postgres"; then
        echo -e "${GREEN}✅ PostgreSQL database is running${NC}"
        if sudo docker exec identus-postgres pg_isready -U postgres &> /dev/null; then
            echo -e "${GREEN}✅ Database is accepting connections${NC}"
        else
            echo -e "${YELLOW}⚠️  Database is not ready${NC}"
        fi
    else
        echo -e "${RED}❌ PostgreSQL database is not running${NC}"
    fi
    echo ""
    
    # Check agents
    echo -e "${CYAN}Identus Agents Status:${NC}"
    local agents=("issuer-agent:8080" "holder-agent:7000" "verifier-agent:9000")
    for agent_info in "${agents[@]}"; do
        local agent_name=$(echo $agent_info | cut -d':' -f1)
        local agent_port=$(echo $agent_info | cut -d':' -f2)
        
        if sudo docker ps | grep -q "$agent_name"; then
            echo -e "${GREEN}✅ $agent_name is running${NC}"
            # Test health endpoint
            if curl -s "http://localhost:$agent_port/_system/health" &> /dev/null; then
                echo -e "${GREEN}  ✅ Health check passed${NC}"
            else
                echo -e "${YELLOW}  ⚠️  Health check failed or agent still starting${NC}"
            fi
        else
            echo -e "${RED}❌ $agent_name is not running${NC}"
        fi
    done
    echo ""
    
    # Check vaults
    echo -e "${CYAN}Vault Services Status:${NC}"
    local vaults=("issuer-vault:8200" "holder-vault:7200" "verifier-vault:9200")
    for vault_info in "${vaults[@]}"; do
        local vault_name=$(echo $vault_info | cut -d':' -f1)
        local vault_port=$(echo $vault_info | cut -d':' -f2)
        
        if sudo docker ps | grep -q "$vault_name"; then
            echo -e "${GREEN}✅ $vault_name is running${NC}"
        else
            echo -e "${RED}❌ $vault_name is not running${NC}"
        fi
    done
    echo ""
    
    # Check Flask app
    echo -e "${CYAN}Flask Application:${NC}"
    if curl -s "http://localhost:$FLASK_PORT/health" &> /dev/null; then
        echo -e "${GREEN}✅ Flask application is responding${NC}"
    else
        echo -e "${RED}❌ Flask application is not responding${NC}"
    fi
    echo ""
    
    # Show service URLs
    echo -e "${YELLOW}Service URLs:${NC}"
    echo -e "${CYAN}  Flask App:      http://localhost:5000${NC}"
    echo -e "${CYAN}  Admin Panel:    http://localhost:5000/admin${NC}"
    echo -e "${CYAN}  Issuer Agent:   http://localhost:8080${NC}"
    echo -e "${CYAN}  Holder Agent:   http://localhost:7000${NC}"
    echo -e "${CYAN}  Verifier Agent: http://localhost:9000${NC}"
}

# Cleanup all services
cleanup_all() {
    echo -e "${YELLOW}🧹 Cleaning up all services...${NC}"
    
    # Stop Flask app if running (this script can't stop it if running separately)
    echo -e "${CYAN}  Note: If Flask app is running, please stop it with Ctrl+C${NC}"
    
    # Cleanup agents
    if [ -f "$SCRIPT_DIR/scripts/setup-agents.sh" ]; then
        cd "$SCRIPT_DIR"
        ./scripts/setup-agents.sh cleanup
    fi
    
    # Cleanup database
    if [ -f "$SCRIPT_DIR/scripts/setup-database.sh" ]; then
        cd "$SCRIPT_DIR"
        ./scripts/setup-database.sh cleanup
    fi
    
    echo -e "${GREEN}✅ Cleanup completed${NC}"
}

# Show help
show_help() {
    echo -e "${BLUE}Classification Document System - Startup Script${NC}"
    echo ""
    echo -e "${YELLOW}USAGE:${NC}"
    echo -e "${CYAN}  ./start.sh [COMMAND]${NC}"
    echo ""
    echo -e "${YELLOW}COMMANDS:${NC}"
    echo -e "${CYAN}  (none)    Full startup - recommended for first run${NC}"
    echo -e "${CYAN}  quick     Start Flask app only (requires existing setup)${NC}"
    echo -e "${CYAN}  database  Setup PostgreSQL database only${NC}"
    echo -e "${CYAN}  agents    Setup Identus agents only${NC}"
    echo -e "${CYAN}  status    Show current system status${NC}"
    echo -e "${CYAN}  cleanup   Stop and remove all services${NC}"
    echo -e "${CYAN}  help      Show this help message${NC}"
    echo ""
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo -e "${CYAN}  ./start.sh              # Complete setup and start${NC}"
    echo -e "${CYAN}  ./start.sh quick        # Start Flask app only${NC}"
    echo -e "${CYAN}  ./start.sh status       # Check what's running${NC}"
    echo -e "${CYAN}  ./start.sh cleanup      # Stop everything${NC}"
    echo ""
    echo -e "${YELLOW}FIRST TIME SETUP:${NC}"
    echo -e "${CYAN}  1. Run: ./start.sh      # This will do everything${NC}"
    echo -e "${CYAN}  2. Wait for completion  # Takes 2-3 minutes${NC}"
    echo -e "${CYAN}  3. Access: http://localhost:5000${NC}"
    echo ""
    echo -e "${YELLOW}SUBSEQUENT RUNS:${NC}"
    echo -e "${CYAN}  ./start.sh quick        # Faster startup${NC}"
    echo ""
    echo -e "${YELLOW}LOGIN CREDENTIALS:${NC}"
    echo -e "${CYAN}  Admin: admin@company.com / admin123${NC}"
    echo -e "${CYAN}  User:  john.doe@company.com / john123${NC}"
    echo ""
    echo -e "${YELLOW}PORTS USED:${NC}"
    echo -e "${CYAN}  5000  - Flask Application${NC}"
    echo -e "${CYAN}  5432  - PostgreSQL Database${NC}"
    echo -e "${CYAN}  8080  - Issuer Agent${NC}"
    echo -e "${CYAN}  7000  - Holder Agent${NC}"
    echo -e "${CYAN}  9000  - Verifier Agent${NC}"
    echo -e "${CYAN}  8200  - Issuer Vault${NC}"
    echo -e "${CYAN}  7200  - Holder Vault${NC}"
    echo -e "${CYAN}  9200  - Verifier Vault${NC}"
}

# Main function
main() {
    local command=${1:-"full"}
    
    case $command in
        "help"|"-h"|"--help")
            show_help
            ;;
        "status")
            show_banner
            check_status
            ;;
        "cleanup")
            show_banner
            cleanup_all
            ;;
        "quick")
            show_banner
            echo -e "${CYAN}🚀 Quick start - Flask app only${NC}"
            echo ""
            check_prerequisites
            setup_python_env
            setup_env_file
            start_flask
            ;;
        "database")
            show_banner
            echo -e "${CYAN}🗄️  Database setup only${NC}"
            echo ""
            check_prerequisites
            setup_database
            echo -e "${GREEN}✅ Database setup completed${NC}"
            ;;
        "agents")
            show_banner
            echo -e "${CYAN}🚀 Agents setup only${NC}"
            echo ""
            check_prerequisites
            setup_agents
            echo -e "${GREEN}✅ Agents setup completed${NC}"
            ;;
        "full"|*)
            show_banner
            echo -e "${CYAN}🚀 Complete system startup${NC}"
            echo ""
            
            echo -e "${BLUE}Step 1: Prerequisites${NC}"
            check_prerequisites
            echo ""
            
            echo -e "${BLUE}Step 2: Python Environment${NC}"
            setup_python_env
            echo ""
            
            echo -e "${BLUE}Step 3: Environment Configuration${NC}"
            setup_env_file
            echo ""
            
            echo -e "${BLUE}Step 4: Database Setup${NC}"
            setup_database
            echo ""
            
            echo -e "${BLUE}Step 5: Identus Agents Setup${NC}"
            setup_agents
            echo ""
            
            echo -e "${BLUE}Step 6: System Status Check${NC}"
            check_status
            echo ""
            
            echo -e "${BLUE}Step 7: Starting Flask Application${NC}"
            start_flask
            ;;
    esac
}

# Run main function with all arguments
main "$@"