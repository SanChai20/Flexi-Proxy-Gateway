#!/bin/bash
set -e

# ========================================
# Logging Configuration
# ========================================
LOG_LEVEL=${LOG_LEVEL:-INFO}

# Logging function with structured format
log() {
    local level=$1
    local component=$2
    local message=$3
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Format: [TIMESTAMP] [LEVEL] [COMPONENT] MESSAGE
    echo "[${timestamp}] [${level}] [${component}] ${message}"
}

log_info() {
    log "INFO" "$1" "$2"
}

log_success() {
    log "SUCCESS" "$1" "$2"
}

log_error() {
    log "ERROR" "$1" "$2" >&2
}

log_warning() {
    log "WARNING" "$1" "$2"
}

log_debug() {
    if [ "$LOG_LEVEL" = "DEBUG" ]; then
        log "DEBUG" "$1" "$2"
    fi
}

sync_progress() {
    local step=$1
    local total=$2
    local status=$3  # success, error, running
    local message=$4
    
    if [ -z "$APP_DOMAIN" ]; then
        log_debug "SYNC" "Progress sync URL not configured, skipping sync"
        return 0
    fi
    
    local payload=$(cat <<EOF
{
    "domain": "$APP_SUBDOMAIN_NAME",
    "step": $step,
    "total_steps": $total,
    "status": "$status",
    "message": "$message",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)
    curl -X POST "https://www.$APP_DOMAIN/api/auth/deployment/progress" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $FP_APP_TOKEN_PASS" \
        -d "$payload" \
        --max-time 5 \
        --silent \
        --show-error \
        > /dev/null 2>&1 || log_warning "SYNC" "Failed to sync progress to server"
}

# Progress indicator
log_progress() {
    local step=$1
    local total=$2
    local message=$3
    log "PROGRESS" "DEPLOYMENT" "Step ${step}/${total}: ${message}"
    sync_progress "$step" "$total" "running" "$message"
}

log_step_success() {
    local component=$1
    local step=$2
    local total=$3
    local message=$4
    log_success "$component" "$message"
    sync_progress "$step" "$total" "success" "$message"
}

log_step_error() {
    local component=$1
    local step=$2
    local total=$3
    local message=$4
    log_error "$component" "$message"
    sync_progress "$step" "$total" "error" "$message"
}

# ========================================
# Validation
# ========================================

# Ensure running as root
if [ "$EUID" -ne 0 ]; then 
    log_error "ROOT_CHECK" "This script must be run as root"
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
        "FP_APP_TOKEN_PASS"
        "FP_PROXY_SERVER_OWNER"
        "OPENROUTER_KEY"
    )
    
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -gt 0 ]; then
        log_error "ENV_VALIDATION" "Missing required environment variables: ${missing_vars[*]}"
        exit 1
    fi
}

log_info "DEPLOYMENT" "========================================="
log_info "DEPLOYMENT" "  Flexi-Proxy Full Deployment"
log_info "DEPLOYMENT" "========================================="

# Validate environment variables
log_progress "0" "9" "Validating environment variables"
validate_env
log_step_success "ENV_VALIDATION" "0" "9" "All required environment variables are set"

# Set default values for optional variables
export LITELLM_SERVER_PORT=${LITELLM_SERVER_PORT:-4000}
export FP_LRU_MAX_CACHE_SIZE=${FP_LRU_MAX_CACHE_SIZE:-1000}
export FP_HTTP_CONNECT_TIMEOUT_LIMIT=${FP_HTTP_CONNECT_TIMEOUT_LIMIT:-5}
export FP_HTTP_READ_TIMEOUT_LIMIT=${FP_HTTP_READ_TIMEOUT_LIMIT:-120}
export FP_HTTP_MAX_RETRY_COUNT=${FP_HTTP_MAX_RETRY_COUNT:-2}
export FP_HTTP_MAX_POOL_CONNECTIONS_COUNT=${FP_HTTP_MAX_POOL_CONNECTIONS_COUNT:-100}
export FP_HTTP_POOL_MAX_SIZE=${FP_HTTP_POOL_MAX_SIZE:-200}
export FP_HTTP_RETRY_BACKOFF=${FP_HTTP_RETRY_BACKOFF:-0.1}
export FP_TOKEN_REFRESH_INTERVAL=${FP_TOKEN_REFRESH_INTERVAL:-300}
export FP_TOKEN_REFRESH_BUFFER=${FP_TOKEN_REFRESH_BUFFER:-1500}
export FP_QUEUE_MAX_CONCURRENT=${FP_QUEUE_MAX_CONCURRENT:-50}
export FP_QUEUE_TIMEOUT=${FP_QUEUE_TIMEOUT:-30}
export FP_QUEUE_ENABLED=${FP_QUEUE_ENABLED:-true}
export LITELLM_NUM_WORKERS=${LITELLM_NUM_WORKERS:-4}
export LITELLM_SET_VERBOSE=${LITELLM_SET_VERBOSE:-False}
export LITELLM_DROP_PARAMS=${LITELLM_DROP_PARAMS:-True}
export LITELLM_MODE=${LITELLM_MODE:-PRODUCTION}
export LITELLM_PROVIDER_PREFIX=${LITELLM_PROVIDER_PREFIX:-openrouter}
export NO_DOCS=${NO_DOCS:-True}
export NO_REDOC=${NO_REDOC:-True}


log_debug "CONFIG" "Configuration loaded successfully"

# ========================================
# Step 1: Install Dependencies
# ========================================
log_progress "1" "9" "Installing Dependencies"

log_info "DEPENDENCIES" "Updating package lists"
sudo apt update > /dev/null 2>&1

log_info "DEPENDENCIES" "Installing system packages"
sudo apt install python3 python3-dev python3-venv libaugeas-dev gcc nginx build-essential socat -y > /dev/null 2>&1

if [ -d ".venv" ]; then
    log_info "DEPENDENCIES" "Virtual environment already exists"
else
    log_info "DEPENDENCIES" "Creating Python virtual environment"
    python3 -m venv .venv
fi

source .venv/bin/activate
log_info "DEPENDENCIES" "Installing Python packages from requirements.txt"
pip install -r requirements.txt > /dev/null 2>&1

log_step_success "DEPENDENCIES" "1" "9" "Dependencies installed successfully"

# ========================================
# Step 2: Install acme.sh
# ========================================
log_progress "2" "9" "Installing acme.sh"

if [ -d "$HOME/.acme.sh" ] && [ -f "$HOME/.acme.sh/acme.sh" ]; then
    log_info "ACME" "acme.sh is already installed"
    export ACME_SH="$HOME/.acme.sh/acme.sh"
else
    if [ -d "acme.sh" ]; then
        log_warning "ACME" "Removing incomplete acme.sh directory"
        rm -rf acme.sh
    fi
    
    log_info "ACME" "Cloning acme.sh repository"
    git clone https://github.com/acmesh-official/acme.sh.git > /dev/null 2>&1
    
    cd acme.sh
    log_info "ACME" "Installing acme.sh"
    ./acme.sh --install -m "$ADMIN_EMAIL" > /dev/null 2>&1
    cd ..
    
    export ACME_SH="$HOME/.acme.sh/acme.sh"
fi

log_step_success "ACME" "2" "9" "acme.sh installed successfully"

# ========================================
# Step 3: Configure DNS
# ========================================
log_progress "3" "9" "Configuring DNS"

export PUBLIC_SERVER_IP=$(curl -s -4 ifconfig.me)
log_info "DNS" "Retrieving server public IP"

log_info "DNS" "Creating DNS A record"
python3 admin/a_record_create.py

if [ $? -eq 0 ]; then
    log_step_success "DNS" "3" "9" "DNS A record configured successfully"
else
    log_step_error "DNS" "3" "9" "Failed to configure DNS record"
    exit 1
fi

# ========================================
# Step 4: Issue SSL Certificate
# ========================================
log_progress "4" "9" "Issuing SSL Certificate"

log_info "SSL" "Requesting SSL certificate via Cloudflare DNS"

if $ACME_SH --issue --dns dns_cf -d "$APP_DOMAIN" -d "$APP_SUBDOMAIN_NAME" > /dev/null 2>&1; then
    log_step_success "SSL" "4" "9" "SSL certificate issued successfully"
else
    log_step_error "SSL" "4" "9" "Failed to issue SSL certificate"
    exit 1
fi

# ========================================
# Step 5: Install Certificate on Nginx
# ========================================
log_progress "5" "9" "Installing Certificate on Nginx"

CERT_DIR="/etc/nginx/ssl/$APP_SUBDOMAIN_NAME"
log_info "SSL" "Preparing certificate directory"
sudo mkdir -p "$CERT_DIR"

log_info "SSL" "Installing certificate to Nginx"
$ACME_SH --install-cert -d "$APP_DOMAIN" \
    --key-file       "$CERT_DIR/key.pem" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --reloadcmd      "service nginx force-reload" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    log_step_success "SSL" "5" "9" "Certificate installed successfully"
else
    log_step_error "SSL" "5" "9" "Failed to install certificate to Nginx"
    exit 1
fi

# ========================================
# Step 6: Configure Nginx
# ========================================
log_progress "6" "9" "Configuring Nginx"

NGINX_CONF="/etc/nginx/sites-available/$APP_SUBDOMAIN_NAME"
log_info "NGINX" "Creating Nginx site configuration"

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
log_info "NGINX" "Enabling site configuration"
sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/

# Test and reload Nginx
log_info "NGINX" "Testing Nginx configuration"
if sudo nginx -t > /dev/null 2>&1; then
    log_step_success "NGINX" "6" "9" "Nginx configuration test passed"
else
    log_step_error "NGINX" "6" "9" "Nginx configuration test failed"
    exit 1
fi

log_info "NGINX" "Reloading Nginx service"
sudo systemctl reload nginx
log_step_success "NGINX" "6" "9" "Nginx configured and reloaded successfully"

# ========================================
# Step 7: Generate Fernet Key
# ========================================
log_progress "7" "9" "Generating Fernet Encryption Key"

TEMP_FILE=$(mktemp)

python3 <<EOF > "$TEMP_FILE"
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode("ascii"))
EOF

export FP_PROXY_SERVER_FERNET_KEY=$(cat "$TEMP_FILE")
rm "$TEMP_FILE"

if [ -z "$FP_PROXY_SERVER_FERNET_KEY" ]; then
    log_step_error "FERNET" "7" "9" "Failed to generate Fernet encryption key"
    exit 1
fi

log_step_success "FERNET" "7" "9" "Fernet encryption key generated successfully"

# ========================================
# Step 8: Set Runtime Environment Variables
# ========================================
log_progress "8" "9" "Setting Runtime Environment"

export FP_PROXY_SERVER_URL="$APP_SUBDOMAIN_NAME"
export FP_PROXY_SERVER_ID=$(expr match "$APP_SUBDOMAIN_NAME" '\([^\.]*\)\..*')
export FP_APP_BASE_URL="https://www.$APP_DOMAIN"

log_info "CONFIG" "Runtime environment variables configured"
log_step_success "CONFIG" "8" "9" "Server configuration completed"

# ========================================
# Step 9: Launch Server
# ========================================
log_progress "9" "9" "Launching Litellm Server"

# Stop any existing instances
log_info "SERVER" "Stopping existing server instances"
sudo pkill -f litellm || true
sleep 2

log_info "SERVER" "Starting Litellm server"
nohup litellm --config config.yaml --port "$LITELLM_SERVER_PORT" > litellm.log 2>&1 &

# Wait and verify
sleep 3
if pgrep -f "litellm.*$LITELLM_SERVER_PORT" > /dev/null; then
    log_step_success "SERVER" "9" "9" "Server launched successfully"
else
    log_step_error "SERVER" "9" "9" "Server failed to start - check litellm.log for details"
    exit 1
fi

# ========================================
# Deployment Summary
# ========================================
log_info "SUMMARY" "SSL certificate installed and configured"
log_info "SUMMARY" "SSL auto-renewal enabled (60 days before expiry)"
log_info "SUMMARY" "Nginx reverse proxy configured"
log_info "SUMMARY" "Application server started"
log_info "SUMMARY" "Application logs: ./litellm.log"
log_info "SUMMARY" "Nginx logs: /var/log/nginx/"
log_info "NEXT_STEPS" "Verify deployment by checking server health endpoint"
log_info "DEPLOYMENT" "========================================="