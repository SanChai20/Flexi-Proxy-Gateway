#!/bin/bash
set -e

# Function to display menu
show_menu() {
    echo ""
    echo "=== Flexi-Proxy Deployment Script ==="
    echo "1. Full Setup (First Time Deployment)"
    echo "2. Deploy SSL Certificate Only"
    echo "3. Launch Server Only"
    echo "4. Exit"
    echo ""
}

# Function to install dependencies
install_dependencies() {
    echo "Installing dependencies..."
    sudo apt update
    sudo apt install python3 python3-dev python3-venv libaugeas-dev gcc nginx build-essential -y

    if [ -d ".venv" ]; then
        echo ".venv already exists, skipping creation."
    else
        echo "Creating Python virtual environment..."
        python3 -m venv .venv
    fi

    source .venv/bin/activate
    pip install -r requirements.txt
}

# Function to get domain parameters
get_domain_params() {
    if [ -z "$ADMIN_EMAIL" ]; then
        read -p "[ADMIN_EMAIL] Your email address: " ADMIN_EMAIL
        export ADMIN_EMAIL
    fi
    
    if [ -z "$APP_DOMAIN" ]; then
        read -p "[APP_DOMAIN] Domain (e.g. example.com): " APP_DOMAIN
        export APP_DOMAIN
    fi
    
    if [ -z "$APP_SUBDOMAIN_NAME" ]; then
        read -p "[APP_SUBDOMAIN_NAME] Subdomain (e.g. api.example.com): " APP_SUBDOMAIN_NAME
        export APP_SUBDOMAIN_NAME
    fi

    export LITELLM_SERVER_PORT=4000
}

# Function to install acme.sh
install_acme() {
    if [ -d "acme.sh" ] && [ -f "acme.sh/acme.sh" ]; then
        echo "acme.sh is already installed, skipping installation..."
        ACME_SH="acme.sh/acme.sh"
    else
        echo "Installing acme.sh..."
        if [ -d "acme.sh" ]; then
            echo "Removing incomplete acme.sh directory..."
            rm -rf acme.sh
        fi
        
        git clone https://github.com/acmesh-official/acme.sh.git
        ACME_SH="acme.sh/acme.sh"
        $ACME_SH --install -m "$ADMIN_EMAIL"
    fi
}

# Function to deploy SSL certificate
deploy_certificate() {
    echo ""
    echo "=== SSL Certificate Deployment ==="
    echo "Note: This only needs to be done once during initial setup."
    echo ""
    
    get_domain_params
    install_acme

    echo ""
    echo "=== Cloudflare DNS Validation ==="
    echo "Get your Cloudflare API Token: https://dash.cloudflare.com/profile/api-tokens"
    echo "Required permissions: Zone - DNS - Edit"
    echo ""
    
    if [ -z "$CF_Token" ]; then
        read -p "[CF_Token] Cloudflare API Token: " CF_Token
        export CF_Token
    fi

    echo ""
    echo "Get your Cloudflare Zone ID: https://dash.cloudflare.com/"
    echo ""
    
    if [ -z "$CF_Zone_ID" ]; then
        read -p "[CF_Zone_ID] Cloudflare Zone ID: " CF_Zone_ID
        export CF_Zone_ID
    fi

    # Add A record for APP_SUBDOMAIN_NAME
    echo ""
    echo "Adding DNS A record..."
    export PUBLIC_SERVER_IP=$(curl -s -4 ifconfig.me)
    echo "Your server IP: $PUBLIC_SERVER_IP"
    python3 admin/a_record.py

    # Issue certificate
    echo ""
    echo "Issuing SSL certificate..."
    $ACME_SH --issue --dns dns_cf -d $APP_DOMAIN -d $APP_SUBDOMAIN_NAME

    # Install certificate on nginx
    CERT_DIR="/etc/nginx/ssl/$APP_SUBDOMAIN_NAME"
    sudo mkdir -p "$CERT_DIR"
    echo ""
    echo "Installing certificate on Nginx..."
    $ACME_SH --install-cert -d $APP_DOMAIN \
    --key-file       $CERT_DIR/key.pem \
    --fullchain-file $CERT_DIR/fullchain.pem \
    --reloadcmd "service nginx force-reload"

    # Create Nginx SSL configuration
    echo ""
    echo "Creating Nginx SSL configuration..."
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
    
    location / {
        proxy_pass http://127.0.0.1:$LITELLM_SERVER_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    # Enable the configuration
    sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/

    # Test and reload Nginx
    echo ""
    echo "Testing Nginx configuration..."
    sudo nginx -t
    echo ""
    echo "Reloading Nginx..."
    sudo systemctl reload nginx
    
    echo ""
    echo "✓ SSL Certificate deployed successfully!"
    echo "✓ Certificates will auto-renew 60 days before expiration"
}

# Function to launch server
launch_server() {
    echo ""
    echo "=== Launching Litellm Proxy Server ==="
    echo ""
    
    get_domain_params

    # Kill old process
    echo "Stopping existing server instances..."
    sudo pkill -f litellm || true

    # Generate key pair
    echo ""
    echo "Generating key pair..."
    if [ -z "$FP_PROXY_SERVER_KEYPAIR_PWD" ]; then
        read -p "[FP_PROXY_SERVER_KEYPAIR_PWD] Customized key pair password: " FP_PROXY_SERVER_KEYPAIR_PWD
        export FP_PROXY_SERVER_KEYPAIR_PWD
    fi
    
    export FP_PROXY_SERVER_KEYPAIR_DIR=../key
    python3 admin/create_key_pair.py

    chmod 600 ../key/key.pem
    chmod 600 ../key/public.pem

    # Set environment variables
    export FP_PROXY_SERVER_URL="https://$APP_SUBDOMAIN_NAME"
    export FP_PROXY_SERVER_ID=$(expr match "$APP_SUBDOMAIN_NAME" '\([^\.]*\)\..*')
    export FP_APP_BASE_URL="https://www.$APP_DOMAIN"
    export FP_LRU_MAX_CACHE_SIZE=1000
    export FP_HTTP_CONNECT_TIMEOUT_LIMIT=5
    export FP_HTTP_READ_TIMEOUT_LIMIT=120
    export FP_HTTP_MAX_RETRY_COUNT=2
    export FP_HTTP_MAX_POOL_CONNECTIONS_COUNT=100
    export FP_HTTP_POOL_MAX_SIZE=200
    export FP_HTTP_RETRY_BACKOFF=0.1
    export FP_TOKEN_REFRESH_INTERVAL=300
    export FP_TOKEN_REFRESH_BUFFER=1500
    export LITELLM_NUM_WORKERS=4
    export LITELLM_SET_VERBOSE=False
    export LITELLM_DROP_PARAMS=True
    export LITELLM_MODE=PRODUCTION
    export NO_DOCS=True
    export NO_REDOC=True

    if [ -z "$FP_APP_TOKEN_PASS" ]; then
        read -p "[FP_APP_TOKEN_PASS] Issued by flexi-proxy admin/token-issuance.ts: " FP_APP_TOKEN_PASS
        export FP_APP_TOKEN_PASS
    fi

    if [ -z "$FP_PROXY_SERVER_ADVANCED" ]; then
        read -p "[FP_PROXY_SERVER_ADVANCED] Advanced Proxy Server? (0 or 1): " FP_PROXY_SERVER_ADVANCED
        export FP_PROXY_SERVER_ADVANCED
    fi

    # Generate Fernet key
    TEMP_FILE=$(mktemp)
    python3 <<EOF > "$TEMP_FILE"
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode("ascii"))
EOF

    export FP_PROXY_SERVER_FERNET_KEY=$(cat "$TEMP_FILE")
    rm "$TEMP_FILE"

    # Critical security validation
    if [ -z "$FP_PROXY_SERVER_FERNET_KEY" ]; then
        echo "ERROR: Fernet key generation failed." >&2
        echo "This is critical for token encryption." >&2
        exit 1
    fi

    if [ -z "$FP_PROXY_SERVER_URL" ]; then
        echo "ERROR: Could not detect server_name." >&2
        echo "Please verify your nginx config has a valid 'server_name' directive." >&2
        exit 1
    fi

    echo ""
    echo "Starting Litellm server..."
    nohup litellm --config config.yaml --port $LITELLM_SERVER_PORT > litellm.log 2>&1 &
    
    echo ""
    echo "✓ Server launched successfully!"
    echo "✓ Server URL: $FP_PROXY_SERVER_URL"
    echo "✓ Server ID: $FP_PROXY_SERVER_ID"
    echo "✓ Log file: litellm.log"
}

# Main script execution
main() {
    # Activate virtual environment if exists
    if [ -d ".venv" ]; then
        source .venv/bin/activate
    fi

    while true; do
        show_menu
        read -p "Select an option (1-4): " choice
        
        case $choice in
            1)
                echo "Starting full setup..."
                install_dependencies
                deploy_certificate
                launch_server
                echo ""
                echo "========================================="
                echo "✓ Full setup completed successfully!"
                echo "========================================="
                break
                ;;
            2)
                install_dependencies
                deploy_certificate
                echo ""
                echo "You can now run this script again and select option 3 to launch the server."
                break
                ;;
            3)
                if [ ! -d ".venv" ]; then
                    echo "ERROR: Virtual environment not found. Please run option 1 or 2 first."
                    continue
                fi
                source .venv/bin/activate
                launch_server
                break
                ;;
            4)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo "Invalid option. Please select 1-4."
                ;;
        esac
    done
}

# Run main function
main