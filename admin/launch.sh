#!/bin/bash
set -e

# Update system and install required dependencies
echo "Updating system and installing dependencies..."
sudo apt update
sudo apt install -y python3 python3-dev python3-venv libaugeas-dev gcc nginx build-essential



sudo pkill -f litellm