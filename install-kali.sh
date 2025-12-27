#!/bin/bash

# ReconMaster Installation Script
# Compatible with Kali Linux and Termux

echo "================================================"
echo "  ReconMaster - Installation Script"
echo "================================================"
echo ""

# Detect platform
if [[ "$OSTYPE" == "linux-android"* ]] || [[ -d "/data/data/com.termux" ]]; then
    PLATFORM="termux"
    echo "[*] Detected: Termux"
else
    PLATFORM="linux"
    echo "[*] Detected: Linux (Kali/Ubuntu/Debian)"
fi

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Installing..."
    
    if [ "$PLATFORM" == "termux" ]; then
        pkg update -y
        pkg install python -y
    else
        sudo apt-get update
        sudo apt-get install python3 python3-pip -y
    fi
else
    echo "[+] Python3 is already installed"
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    echo "[!] pip not found. Installing..."
    
    if [ "$PLATFORM" == "termux" ]; then
        pkg install python-pip -y
    else
        sudo apt-get install python3-pip -y
    fi
else
    echo "[+] pip is already installed"
fi

# Install required Python packages
echo ""
echo "[*] Installing Python dependencies..."

if [ "$PLATFORM" == "termux" ]; then
    pip install -r requirements.txt
else
    pip3 install -r requirements.txt
fi

# Make the main script executable
chmod +x recon_master.py

echo ""
echo "================================================"
echo "[+] Installation completed successfully!"
echo "================================================"
echo ""
echo "Next steps:"
echo "1. Run setup wizard: python3 recon_master.py --setup"
echo "2. Start scanning: python3 recon_master.py -t example.com"
echo ""
echo "For help: python3 recon_master.py -h"
echo ""
