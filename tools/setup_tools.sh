#!/bin/bash
# tools/setup_tools.sh
# Setup script for cybersecurity tools and dependencies

echo "╔══════════════════════════════════════════════════╗"
echo "║     Cybersecurity Tools Setup Script             ║"
echo "║         FOR EDUCATIONAL USE ONLY                 ║"
echo "╚══════════════════════════════════════════════════╝"

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo "⚠️  Warning: Running as root. Be careful!"
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo ""
echo "[*] Checking system requirements..."

# Check Python version
if command_exists python3; then
    python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    echo "✓ Python $python_version detected"
    
    # Check if Python version is >= 3.8
    if python3 -c "import sys; exit(0 if sys.version_info >= (3,8) else 1)"; then
        echo "  ✓ Python version is compatible"
    else
        echo "  ✗ Python 3.8+ required. Found $python_version"
        exit 1
    fi
else
    echo "✗ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Check pip
if command_exists pip3; then
    echo "✓ pip3 detected"
else
    echo "✗ pip3 not found. Installing..."
    python3 -m ensurepip --upgrade
fi

echo ""
echo "[*] Creating virtual environment..."

# Create virtual environment
if [ -d "venv" ]; then
    echo "  ✓ Virtual environment already exists"
else
    python3 -m venv venv
    echo "  ✓ Virtual environment created"
fi

# Activate virtual environment
source venv/bin/activate

echo ""
echo "[*] Upgrading pip..."
pip install --upgrade pip

echo ""
echo "[*] Installing requirements..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    echo "  ✓ Requirements installed"
else
    echo "  ✗ requirements.txt not found"
    exit 1
fi

echo ""
echo "[*] Checking optional system dependencies..."

# Check for tcpdump (useful for network analysis)
if command_exists tcpdump; then
    echo "✓ tcpdump detected"
else
    echo "⚠️  tcpdump not found. Install with: sudo apt-get install tcpdump (Linux) or brew install tcpdump (Mac)"
fi

# Check for nmap
if command_exists nmap; then
    echo "✓ nmap detected"
else
    echo "⚠️  nmap not found. Install with: sudo apt-get install nmap (Linux) or brew install nmap (Mac)"
fi

# Check for wireshark
if command_exists wireshark; then
    echo "✓ wireshark detected"
else
    echo "⚠️  wireshark not found. Install for packet analysis"
fi

echo ""
echo "[*] Creating necessary directories..."

# Create directories if they don't exist
mkdir -p logs
mkdir -p reports
mkdir -p samples/malware
mkdir -p config

echo "  ✓ Directories created"

echo ""
echo "[*] Setting up configuration..."

# Create default config file if it doesn't exist
if [ ! -f "config/default.conf" ]; then
    cat > config/default.conf << EOF
# Default configuration for cybersecurity tools
# Modify as needed

[network]
interface = eth0
timeout = 5
max_packets = 1000

[scanning]
threads = 10
timeout = 30
user_agent = Mozilla/5.0 (Security Scanner - Educational Purpose)

[logging]
log_level = INFO
log_file = logs/security_tools.log
max_log_size = 10485760
backup_count = 5

[reporting]
output_format = json
save_reports = true
report_directory = reports

[database]
type = sqlite
name = security_tools.db
host = localhost
port = 3306

[alerts]
email_enabled = false
smtp_server = localhost
smtp_port = 25
alert_email = admin@localhost
EOF
    echo "  ✓ Default configuration created"
fi

echo ""
echo "[*] Running post-installation checks..."

# Test imports
python3 -c "
import sys
required_modules = ['scapy', 'requests', 'cryptography', 'yara', 'pefile']
missing_modules = []

for module in required_modules:
    try:
        __import__(module)
        print(f'  ✓ {module} imported successfully')
    except ImportError as e:
        missing_modules.append(module)
        print(f'  ✗ {module} import failed: {e}')

if missing_modules:
    print(f'\n⚠️  Warning: Some modules failed to import: {missing_modules}')
    sys.exit(1)
else:
    print('\n  ✓ All modules imported successfully!')
"

if [ $? -eq 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║     Setup completed successfully!                ║"
    echo "║                                                  ║"
    echo "║  Next steps:                                     ║"
    echo "║  1. Activate the virtual environment:            ║"
    echo "║     source venv/bin/activate                     ║"
    echo "║                                                  ║"
    echo "║  2. Start exploring the tools:                   ║"
    echo "║     cd ..                                        ║"
    echo "║     python scripts/network_monitor.py --help     ║"
    echo "║                                                  ║"
    echo "║  3. Check configuration:                         ║"
    echo "║     cat config/default.conf                      ║"
    echo "║                                                  ║"
    echo "║  Remember: Use these tools responsibly and       ║"
    echo "║           only on systems you own or have        ║"
    echo "║           permission to test!                    ║"
    echo "╚══════════════════════════════════════════════════╝"
else
    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║     Setup completed with warnings!               ║"
    echo "║     Some modules may not work properly.          ║"
    echo "╚══════════════════════════════════════════════════╝"
fi

echo ""
echo "Setup completed at $(date)"
