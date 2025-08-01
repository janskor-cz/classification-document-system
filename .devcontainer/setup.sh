#!/bin/bash

echo "🚀 Setting up Classification Document System in GitHub Codespaces..."
echo "This will take 3-5 minutes - please wait..."

# Update system packages
echo "📦 Updating system packages..."
sudo apt-get update -qq

# Install essential tools
echo "🔧 Installing development tools..."
sudo apt-get install -y -qq \
    curl \
    wget \
    htop \
    net-tools \
    postgresql-client \
    redis-tools \
    jq \
    tree

# Setup Python virtual environment
echo "🐍 Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Create requirements.txt with all necessary packages
echo "📋 Creating requirements.txt..."
cat > requirements.txt << 'EOF'
Flask==2.3.3
Flask-CORS==4.0.0
requests==2.31.0
qrcode[pil]==7.4.2
Pillow==10.0.1
python-dotenv==1.0.0
gunicorn==21.2.0
psycopg2-binary==2.9.7
redis==4.6.0
pytest==7.4.2
python-multipart==0.0.6
Werkzeug==2.3.7
markupsafe==2.1.3
cryptography==41.0.7
EOF

# Install Python dependencies
echo "🔽 Installing Python dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

# Create project directory structure
echo "📁 Creating project structure..."
mkdir -p {static,templates,scripts,tests,docs,config,data/uploads,logs,certs}
touch data/uploads/.gitkeep
touch logs/.gitkeep
touch certs/.gitkeep

# Create environment configuration
echo "⚙️ Creating environment configuration..."
cat > .env << 'EOF'
# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=codespaces-dev-secret-key-change-in-production

# Database Configuration
DATABASE_URL=postgresql://identus_user:identus_pass@localhost:5432/identus_db
REDIS_URL=redis://localhost:6379

# Identus Agent URLs (Codespaces auto-detects and uses port forwarding)
IDENTUS_ISSUER_URL=http://localhost:8000/cloud-agent
IDENTUS_HOLDER_URL=http://localhost:7000/cloud-agent
IDENTUS_VERIFIER_URL=http://localhost:9000/cloud-agent

# Application Configuration
UPLOAD_FOLDER=data/uploads
MAX_CONTENT_LENGTH=16777216
ALLOWED_EXTENSIONS=pdf,txt,doc,docx

# Codespaces Configuration
CODESPACES=true
HOST=0.0.0.0
PORT=5000
EOF

# Create development commands script
echo "🛠️ Creating development commands..."
cat > dev-commands.sh << 'EOF'
#!/bin/bash

case "$1" in
    "start")
        echo "🚀 Starting all services..."
        source venv/bin/activate
        docker-compose up -d
        echo "⏳ Waiting for services to initialize..."
        sleep 30
        python app.py &
        echo "✅ All services started!"
        echo "📊 Dashboard: Check Ports tab for URL"
        ;;
    "stop")
        echo "🛑 Stopping all services..."
        docker-compose down
        pkill -f "python app.py" 2>/dev/null || true
        echo "✅ All services stopped"
        ;;
    "restart")
        echo "🔄 Restarting services..."
        $0 stop
        sleep 3
        $0 start
        ;;
    "status")
        echo "📊 Service Status:"
        docker-compose ps
        echo ""
        echo "🔍 Health Checks:"
        curl -s http://localhost:8000/_system/health >/dev/null && echo "✅ Issuer Agent: OK" || echo "❌ Issuer Agent: Failed"
        curl -s http://localhost:7000/_system/health >/dev/null && echo "✅ Holder Agent: OK" || echo "❌ Holder Agent: Failed"
        curl -s http://localhost:9000/_system/health >/dev/null && echo "✅ Verifier Agent: OK" || echo "❌ Verifier Agent: Failed"
        ;;
    "logs")
        echo "📋 Recent service logs:"
        docker-compose logs --tail=50
        ;;
    "test")
        echo "🧪 Running system tests..."
        source venv/bin/activate
        python -c "
from identus_wrapper import IdentusDashboardClient
client = IdentusDashboardClient()
print('Testing Identus integration...')
if client.check_agents_health():
    print('✅ All systems operational!')
else:
    print('❌ Some services not responding')
"
        ;;
    *)
        echo "🎛️ Available commands:"
        echo "  start   - Start all services"
        echo "  stop    - Stop all services"
        echo "  restart - Restart all services"
        echo "  status  - Check service status"
        echo "  logs    - Show service logs"
        echo "  test    - Run system tests"
        echo ""
        echo "Usage: ./dev-commands.sh [command]"
        ;;
esac
EOF

chmod +x dev-commands.sh

# Create helpful aliases
echo "🔗 Setting up aliases..."
echo "alias start-system='./dev-commands.sh start'" >> ~/.bashrc
echo "alias stop-system='./dev-commands.sh stop'" >> ~/.bashrc
echo "alias system-status='./dev-commands.sh status'" >> ~/.bashrc

echo ""
echo "✅ Setup completed successfully!"
echo "🎯 Classification Document System is ready for development"
echo ""
echo "📝 Next steps:"
echo "  1. Services will start automatically"
echo "  2. Check the 'Ports' tab for your dashboard URL"
echo "  3. Use './dev-commands.sh status' to check services"
echo "  4. Happy coding! 🚀"
EOF

chmod +x .devcontainer/setup.sh
