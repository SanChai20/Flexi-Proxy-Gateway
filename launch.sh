#!/bin/bash
set -e

echo "Checking if virtual environment already exists..."
if [ -d ".venv" ]; then
    echo ".venv already exists, skipping creation."
else
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Installing dependencies..."
pip install -r requirements-linux.txt

echo "Setting environment variables..."

# Use a temporary file to store the output
TEMP_FILE=$(mktemp)
python3 <<EOF > "$TEMP_FILE"
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode("ascii"))
EOF

# Read the generated Fernet key
export FP_PROXY_SERVER_FERNET_KEY=$(cat "$TEMP_FILE")
rm "$TEMP_FILE"

# Critical security validation
if [ -z "$FP_PROXY_SERVER_FERNET_KEY" ]; then
    echo "ERROR: Fernet key generation failed." >&2
    echo "This is critical for token encryption - see [redhat.com](https://docs.redhat.com/en/documentation/red_hat_openstack_platform/10/html/deploy_fernet_on_the_overcloud/rotate_the_fernet_keys) for security implications" >&2
    exit 1
fi

SERVER_NAME=$(grep -A 20 "ssl_certificate" /etc/nginx/sites-enabled/* | grep "server_name" | awk '{print $2}' | tr -d ';' | head -n 1)

# Critical validation check
if [ -z "$SERVER_NAME" ]; then
    echo "ERROR: Could not detect server_name from nginx configuration." >&2
    echo "Please verify your nginx config has a valid 'server_name' directive." >&2
    echo "See nginx documentation: [nginx.org](https://nginx.org/en/docs/http/server_names.html)"
    exit 1
fi

# Validate and extract server ID from SERVER_NAME
if [[ "$SERVER_NAME" =~ ^flexiproxy-([a-zA-Z0-9-]+)\.flexiproxy\.com$ ]]; then
    export FP_PROXY_SERVER_ID="${BASH_REMATCH[1]}"
else
    read -p "[FP_PROXY_SERVER_ID] Customized proxy server id: " FP_PROXY_SERVER_ID
    export FP_PROXY_SERVER_ID
fi

read -p "[FP_APP_TOKEN_PASS] Issued by flexi-proxy admin/token-issuance.ts: " FP_APP_TOKEN_PASS
export FP_APP_TOKEN_PASS

read -p "[FP_PROXY_SERVER_KEYPAIR_PWD] Customized key pair password: " FP_PROXY_SERVER_KEYPAIR_PWD
export FP_PROXY_SERVER_KEYPAIR_PWD

read -p "[FP_PROXY_SERVER_ADVANCED] Advanced Proxy Server? (0 or 1): " FP_PROXY_SERVER_ADVANCED
export FP_PROXY_SERVER_ADVANCED

# Ensure HTTPS prefix (critical for SSL termination)
if [[ ! "$SERVER_NAME" =~ ^https?:// ]]; then
    SERVER_NAME="https://$SERVER_NAME"
    echo "Added 'https://' prefix to SERVER_NAME: $SERVER_NAME"
fi

export FP_PROXY_SERVER_URL=$SERVER_NAME
export LITELLM_MODE=PRODUCTION
export FP_APP_BASE_URL=https://www.flexiproxy.com
export FP_PROXY_SERVER_KEYPAIR_DIR=../key
export FP_LRU_MAX_CACHE_SIZE=400
export FP_HTTP_CONNECT_TIMEOUT_LIMIT=8
export FP_HTTP_READ_TIMEOUT_LIMIT=240
export FP_HTTP_MAX_RETRY_COUNT=5
export FP_HTTP_MAX_POOL_CONNECTIONS_COUNT=10
export FP_HTTP_POOL_MAX_SIZE=30
export FP_HTTP_RETRY_BACKOFF=0.5

echo "Generating key pair..."
python3 admin/create_key_pair.py

echo "Starting LiteLLM Proxy Server..."
nohup litellm --config config.yaml --port 4000 &