#!/bin/bash
set -e

if [ -d ".venv" ]; then
    echo ".venv already exists, skipping creation."
else
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -r requirements.txt

export CLOUDFLARE_ACCESS_TOKEN="enqkaxaX37bnV-gWy3-mvT4V8OFCkCZVtCW6F4JG"
export CLOUDFLARE_ZONE_ID="7e2ab196e7128c33e1da145715bbe947"
export APP_SUBDOMAIN_NAME="gateway-test1"
export PUBLIC_SERVER_IP=$(curl -s -4 ifconfig.me)
python3 admin/a_record.py