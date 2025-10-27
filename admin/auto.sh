#!/bin/bash
set -e

# Ensure running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

# Validate required environment variables
validate_env() {
    local required_vars=(
        "ADMIN_EMAIL"
        "APP_DOMAIN"
        "APP_SUBDOMAIN_NAME"
        "CF_Token"
        "CF_Zone_ID"
        "FP_PROXY_SERVER_KEYPAIR_PWD"
        "FP_APP_TOKEN_PASS"
        "FP_PROXY_SERVER_ADVANCED"
    )
    
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -gt 0 ]; then
        echo "ERROR: Missing required environment variables:" >&2
        printf '  - %s\n' "${missing_vars[@]}" >&2
        exit 1
    fi
}

echo "========================================="
echo "  Flexi-Proxy Full Deployment"
echo "========================================="
echo ""

# Validate environment variables
echo "Validating environment variables..."
validate_env
echo "✓ All required environment variables are set"
echo ""

# Set default values for optional variables
export LITELLM_SERVER_PORT=${LITELLM_SERVER_PORT:-4000}
export FP_PROXY_SERVER_KEYPAIR_DIR=${FP_PROXY_SERVER_KEYPAIR_DIR:-../key}
export FP_LRU_MAX_CACHE_SIZE=${FP_LRU_MAX_CACHE_SIZE:-1000}
export FP_HTTP_CONNECT_TIMEOUT_LIMIT=${FP_HTTP_CONNECT_TIMEOUT_LIMIT:-5}
export FP_HTTP_READ_TIMEOUT_LIMIT=${FP_HTTP_READ_TIMEOUT_LIMIT:-120}
export FP_HTTP_MAX_RETRY_COUNT=${FP_HTTP_MAX_RETRY_COUNT:-2}
export FP_HTTP_MAX_POOL_CONNECTIONS_COUNT=${FP_HTTP_MAX_POOL_CONNECTIONS_COUNT:-100}
export FP_HTTP_POOL_MAX_SIZE=${FP_HTTP_POOL_MAX_SIZE:-200}
export FP_HTTP_RETRY_BACKOFF=${FP_HTTP_RETRY_BACKOFF:-0.1}
export FP_TOKEN_REFRESH_INTERVAL=${FP_TOKEN_REFRESH_INTERVAL:-300}
export FP_TOKEN_REFRESH_BUFFER=${FP_TOKEN_REFRESH_BUFFER:-1500}
export LITELLM_NUM_WORKERS=${LITELLM_NUM_WORKERS:-4}
export LITELLM_SET_VERBOSE=${LITELLM_SET_VERBOSE:-False}
export LITELLM_DROP_PARAMS=${LITELLM_DROP_PARAMS:-True}
export LITELLM_MODE=${LITELLM_MODE:-PRODUCTION}
export NO_DOCS=${NO_DOCS:-True}
export NO_REDOC=${NO_REDOC:-True}

# ========================================
# Step 1: Install Dependencies
# ========================================
echo "========================================="
echo "Step 1: Installing Dependencies"
echo "========================================="
echo ""

sudo apt update
sudo apt install python3 python3-dev python3-venv libaugeas-dev gcc nginx build-essential socat -y

if [ -d ".venv" ]; then
    echo ".venv already exists, skipping creation."
else
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -r requirements.txt

echo ""
echo "✓ Dependencies installed successfully"
echo ""

# ========================================
# Step 2: Install acme.sh
# ========================================
echo "========================================="
echo "Step 2: Installing acme.sh"
echo "========================================="
echo ""

if [ -d "$HOME/.acme.sh" ] && [ -f "$HOME/.acme.sh/acme.sh" ]; then
    echo "acme.sh is already installed, skipping installation..."
    export ACME_SH="$HOME/.acme.sh/acme.sh"
else
    if [ -d "acme.sh" ]; then
        echo "Removing incomplete acme.sh directory..."
        rm -rf acme.sh
    fi
    
    git clone https://github.com/acmesh-official/acme.sh.git
    cd acme.sh
    ./acme.sh --install -m "$ADMIN_EMAIL"
    cd ..
    
    export ACME_SH="$HOME/.acme.sh/acme.sh"
fi

echo ""
echo "✓ acme.sh installed successfully"
echo ""

# ========================================
# Step 3: Configure DNS
# ========================================
echo "========================================="
echo "Step 3: Configuring DNS"
echo "========================================="
echo ""

export PUBLIC_SERVER_IP=$(curl -s -4 ifconfig.me)
echo "Server IP: $PUBLIC_SERVER_IP"
echo "Domain: $APP_SUBDOMAIN_NAME"

python3 admin/a_record_create.py

echo ""
echo "✓ DNS configured successfully"
echo ""

# ========================================
# Step 4: Issue SSL Certificate
# ========================================
echo "========================================="
echo "Step 4: Issuing SSL Certificate"
echo "========================================="
echo ""

echo "Issuing certificate for:"
echo "  - $APP_DOMAIN"
echo "  - $APP_SUBDOMAIN_NAME"
echo ""

$ACME_SH --issue --dns dns_cf -d "$APP_DOMAIN" -d "$APP_SUBDOMAIN_NAME"

echo ""
echo "✓ SSL certificate issued successfully"
echo ""

# ========================================
# Step 5: Install Certificate on Nginx
# ========================================
echo "========================================="
echo "Step 5: Installing Certificate on Nginx"
echo "========================================="
echo ""

CERT_DIR="/etc/nginx/ssl/$APP_SUBDOMAIN_NAME"
sudo mkdir -p "$CERT_DIR"

$ACME_SH --install-cert -d "$APP_DOMAIN" \
    --key-file       "$CERT_DIR/key.pem" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --reloadcmd      "service nginx force-reload"

echo ""
echo "✓ Certificate installed on Nginx"
echo ""

# ========================================
# Step 6: Configure Nginx
# ========================================
echo "========================================="
echo "Step 6: Configuring Nginx"
echo "========================================="
echo ""

NGINX_CONF="/etc/nginx/sites-available/$APP_SUBDOMAIN_NAME"

sudo tee "$NGINX_CONF" > /dev/null <<EOF
server {
    if (\$host = $APP_SUBDOMAIN_NAME) {
        return 301 https://\$host\$request_uri;
    }
    listen 80;
    server_name $APP_SUBDOMAIN_NAME;
    return 404;
}

server {
    root /var/www/html;

    listen 443 ssl http2;
    server_name $APP_SUBDOMAIN_NAME;

    ssl_certificate $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/key.pem;
    
    # SSL security settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    
    location / {
        proxy_pass http://127.0.0.1:$LITELLM_SERVER_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 120s;
    }
}
EOF

# Enable the configuration
sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/

# Test and reload Nginx
echo "Testing Nginx configuration..."
sudo nginx -t

echo "Reloading Nginx..."
sudo systemctl reload nginx

echo ""
echo "✓ Nginx configured successfully"
echo ""

# ========================================
# Step 7: Generate Key Pair
# ========================================
echo "========================================="
echo "Step 7: Generating Key Pair"
echo "========================================="
echo ""

python3 admin/create_key_pair.py

chmod 600 "$FP_PROXY_SERVER_KEYPAIR_DIR/key.pem"
chmod 600 "$FP_PROXY_SERVER_KEYPAIR_DIR/public.pem"

echo ""
echo "✓ Key pair generated successfully"
echo ""

# ========================================
# Step 8: Generate Fernet Key
# ========================================
echo "========================================="
echo "Step 8: Generating Fernet Encryption Key"
echo "========================================="
echo ""

TEMP_FILE=$(mktemp)
python3 <<EOF > "$TEMP_FILE"
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode("ascii"))
EOF

export FP_PROXY_SERVER_FERNET_KEY=$(cat "$TEMP_FILE")
rm "$TEMP_FILE"

if [ -z "$FP_PROXY_SERVER_FERNET_KEY" ]; then
    echo "ERROR: Fernet key generation failed." >&2
    echo "This is critical for token encryption." >&2
    exit 1
fi

echo "✓ Fernet key generated successfully"
echo ""

# ========================================
# Step 9: Set Runtime Environment Variables
# ========================================
echo "========================================="
echo "Step 9: Setting Runtime Environment"
echo "========================================="
echo ""

export FP_PROXY_SERVER_URL="https://$APP_SUBDOMAIN_NAME"
export FP_PROXY_SERVER_ID=$(expr match "$APP_SUBDOMAIN_NAME" '\([^\.]*\)\..*')
export FP_APP_BASE_URL="https://www.$APP_DOMAIN"

echo "Server Configuration:"
echo "  URL: $FP_PROXY_SERVER_URL"
echo "  ID: $FP_PROXY_SERVER_ID"
echo "  Port: $LITELLM_SERVER_PORT"
echo "  Workers: $LITELLM_NUM_WORKERS"
echo "  Mode: $LITELLM_MODE"
echo ""

# ========================================
# Step 10: Launch Server
# ========================================
echo "========================================="
echo "Step 10: Launching Litellm Server"
echo "========================================="
echo ""

# Stop any existing instances
echo "Stopping existing server instances..."
sudo pkill -f litellm || true
sleep 2

echo "Starting Litellm server..."
nohup litellm --config config.yaml --port "$LITELLM_SERVER_PORT" > litellm.log 2>&1 &

# Wait and verify
sleep 3
if pgrep -f "litellm.*$LITELLM_SERVER_PORT" > /dev/null; then
    SERVER_PID=$(pgrep -f "litellm.*$LITELLM_SERVER_PORT")
    echo ""
    echo "✓ Server launched successfully!"
    echo "  Log: litellm.log"
else
    echo ""
    echo "ERROR: Server failed to start" >&2
    echo "Last 20 lines of log:" >&2
    tail -n 20 litellm.log >&2
    exit 1
fi

echo ""
echo "========================================="
echo "  ✓ DEPLOYMENT COMPLETED SUCCESSFULLY"
echo "========================================="
echo ""
echo "Server Details:"
echo "  • URL: $FP_PROXY_SERVER_URL"
echo "  • ID: $FP_PROXY_SERVER_ID"
echo "  • Port: $LITELLM_SERVER_PORT"
echo ""
echo "SSL Certificate:"
echo "  • Auto-renewal: Enabled (60 days before expiry)"
echo "  • Location: $CERT_DIR"
echo ""
echo "Logs:"
echo "  • Application: ./litellm.log"
echo "  • Nginx: /var/log/nginx/"
echo ""
echo "Next Steps:"
echo "  • Verify server: curl https://$APP_SUBDOMAIN_NAME/health/liveness"
echo ""
echo "========================================="