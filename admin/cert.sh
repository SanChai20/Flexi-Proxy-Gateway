#!/bin/bash
set -e

sudo apt update
sudo apt install python3 python3-dev python3-venv libaugeas-dev gcc nginx build-essential

read -p "[ADMIN_EMAIL] Your email address: " ADMIN_EMAIL
export ADMIN_EMAIL
read -p "[YOUR_DOMAIN] Domain (e.g. example.com): " YOUR_DOMAIN
export YOUR_DOMAIN
read -p "[YOUR_SUBDOMAIN] Subdomain (e.g. api.example.com): " YOUR_SUBDOMAIN
export YOUR_SUBDOMAIN

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

read -p "Do you want to deploy cert? (y/n): " DEPLOY_CERT

if [[ "$DEPLOY_CERT" == "y" || "$DEPLOY_CERT" == "Y" ]]; then

    read -p "[CF_Token] Cloudflare user token (https://dash.cloudflare.com/profile/api-tokens): " CF_Token
    export CF_Token

    read -p "[CF_Zone_ID] Cloudflare zone id (https://dash.cloudflare.com/): " CF_Zone_ID
    export CF_Zone_ID

    echo "Issuing cert..."
    $ACME_SH --issue --dns dns_cf -d $YOUR_DOMAIN -d $YOUR_SUBDOMAIN

fi

CERT_DIR="/etc/nginx/ssl"
sudo mkdir -p "$CERT_DIR"
echo ""
echo "Installing cert on nginx..."
$ACME_SH --install-cert -d $YOUR_DOMAIN \
--key-file       $CERT_DIR/key.pem \
--fullchain-file $CERT_DIR/fullchain.pem \
--reloadcmd "service nginx force-reload"

# Create Nginx SSL configuration
echo ""
echo "Creating Nginx SSL configuration..."
NGINX_CONF="/etc/nginx/sites-available/$YOUR_SUBDOMAIN"

sudo tee "$NGINX_CONF" > /dev/null <<EOF
server {
    listen 80;
    server_name $YOUR_SUBDOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $YOUR_SUBDOMAIN;

    ssl_certificate $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/key.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    location / {
        root /var/www/html;
        index index.html;
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