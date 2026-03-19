#!/bin/bash
#
# setup_nexus.sh - Script to set up the NEXUS Core environment.
#
# This script performs the following actions:
# 1. Checks for Python 3.11 or higher.
# 2. Creates a Python virtual environment named 'venv'.
# 3. Activates the virtual environment.
# 4. Installs required packages from requirements.txt.
# 5. Creates a default .env file from .env.example if it doesn't exist.
# 6. Verifies that the main application file (main.py) exists.
#

set -e # Exit immediately if a command exits with a non-zero status.

# --- Functions ---

# Function to print a formatted message
function log() {
    echo "--- $1 ---"
}

# Function to check Python version
function check_python_version() {
    log "Checking Python version..."
    
    if ! command -v python3 &> /dev/null; then
        echo "❌ ERROR: python3 command not found. Please install Python 3.11 or higher."
        exit 1
    fi

    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    MIN_VERSION="3.11"

    if ! printf '%s
' "$MIN_VERSION" "$PYTHON_VERSION" | sort -V -C; then
        echo "❌ ERROR: Python version $PYTHON_VERSION is not supported."
        echo "Please install Python $MIN_VERSION or higher."
        exit 1
    fi
    
    echo "✅ Python version $PYTHON_VERSION is compatible."
}

# --- Main Script ---

log "Starting NEXUS Core setup..."

# 1. Verify Python version
check_python_version

# 2. Create virtual environment
if [ -d "venv" ]; then
    log "Virtual environment 'venv' already exists. Skipping creation."
else
    log "Creating Python virtual environment..."
    python3 -m venv venv
fi

# 3. Activate virtual environment
log "Activating virtual environment..."
source venv/bin/activate

# 4. Install dependencies
log "Installing dependencies from requirements.txt..."
pip install --upgrade pip > /dev/null
pip install -r requirements.txt
log "Dependencies installed successfully."

# 5. Copy .env.example to .env if .env does not exist
if [ -f ".env" ]; then
    log ".env file already exists. Skipping creation."
else
    log "Creating .env file from .env.example..."
    cp .env.example .env
    log "✅ .env file created. Please edit it to add your API keys."
fi

# 6. Verify main.py exists
if [ ! -f "main.py" ]; then
    echo "⚠️ WARNING: main.py not found. The application may not run."
else
    log "main.py found."
fi

# 7. Success message
echo ""
echo "======================================================"
echo "✅ NEXUS setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit the .env file with your API keys."
echo "   nano .env"
echo ""
echo "2. Run the application:"
echo "   bash run_nexus.sh"
echo "======================================================"

exit 0
