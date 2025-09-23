#!/bin/bash

set -e  # Exit on any error

echo "Changing to the target directory..."
cd ../../../ || { echo "Failed to change directory"; exit 1; }

echo "Activating virtual environment..."
source .venv/bin/activate || { echo "Failed to activate virtual environment"; exit 1; }

echo "Generating key pair..."
python3 admin/create_key_pair.py || { echo "Failed to generate key pair"; exit 1; }

echo "Starting LiteLLM Proxy Server..."
litellm --config config.yaml --port 4000