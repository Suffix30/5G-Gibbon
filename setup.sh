#!/bin/bash
#
# 5G-Gibbon Setup Script
# Author: NET - Gaspberry
#
# Usage: chmod +x setup.sh && ./setup.sh
#

echo "=================================="
echo "5G-Gibbon Setup (5G + 4G/LTE)"
echo "=================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Warning: Not running as root. Some features require sudo."
    echo ""
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Please install Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[+] Python version: $PYTHON_VERSION"

# Create virtual environment
echo "[+] Creating virtual environment..."
python3 -m venv venv

# Activate and install using venv's pip directly
echo "[+] Installing dependencies..."
./venv/bin/pip install --upgrade pip > /dev/null 2>&1
./venv/bin/pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo ""
    echo "=================================="
    echo "Setup Complete!"
    echo "=================================="
    echo ""
    echo "To use 5G-Gibbon:"
    echo ""
    echo "  1. Activate environment:"
    echo "     source venv/bin/activate"
    echo ""
    echo "  2. Run the toolkit:"
    echo "     python run.py              # Interactive menu"
    echo "     sudo python run.py         # With full permissions"
    echo ""
    echo "  3. Quick commands:"
    echo "     python run.py discover     # Scan for 5G/4G components"
    echo "     python run.py audit        # Security audit"
    echo "     python run.py ultra-red    # Red team attack"
    echo "     python run.py lte assessment  # 4G/LTE assessment"
    echo ""
else
    echo "[!] Setup failed. Check errors above."
    exit 1
fi

