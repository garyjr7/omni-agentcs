#!/bin/bash
#
# run_nexus.sh - Script to run the NEXUS Core application.
#
# This script performs the following actions:
# 1. Checks for the existence of the virtual environment.
# 2. Checks for the existence of the .env file.
# 3. Activates the virtual environment.
# 4. Exports environment variables from .env.
# 5. Runs the main Python application.
#

set -e # Exit immediately if a command exits with a non-zero status.

# --- Cleanup function for Ctrl+C ---
function cleanup() {
    echo ""
    echo "🔌 Shutting down NEXUS Core..."
    # Add any specific cleanup commands here if needed
    exit 0
}

# Trap Ctrl+C and call the cleanup function
trap cleanup INT

# --- Main Script ---

# 1. Verify venv exists
if [ ! -d "venv" ]; then
    echo "❌ ERROR: Virtual environment 'venv' not found."
    echo "Please run the setup script first: bash setup_nexus.sh"
    exit 1
fi

# 2. Verify .env exists
if [ ! -f ".env" ]; then
    echo "❌ ERROR: .env file not found."
    echo "Please run 'bash setup_nexus.sh' or create it from .env.example."
    exit 1
fi

# 3. Activate virtual environment
source venv/bin/activate

# 4. Export environment variables from .env
echo "📦 Loading environment variables from .env..."
export $(cat .env | grep -v '^#' | xargs)

# 5. Run the main application
echo "🚀 Starting NEXUS Core... (Press Ctrl+C to stop)"
PYTHONPATH=".." python main.py

# The script will exit via the cleanup trap on Ctrl+C
