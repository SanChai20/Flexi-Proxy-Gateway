#!/bin/bash
set -e

# Update system and install required dependencies
echo "Updating system and installing dependencies..."
sudo apt update
sudo apt install -y nginx

# Ask if SSL certificate deployment is needed
read -p "Do you want to deploy SSL certificate? (y/n): " DEPLOY_CERT
if [[ "$DEPLOY_CERT" != "y" && "$DEPLOY_CERT" != "Y" ]]; then
    echo "Skipping certificate deployment. Installation complete."
    exit 0
fi

# Get administrator email
while true; do
    read -p "Enter your email address: " ADMIN_EMAIL
    if [[ "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        export ADMIN_EMAIL
        break
    else
        echo "Invalid email format. Please try again."
    fi
done

# Check and install acme.sh
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
    
    # Install and configure acme.sh
    echo "Configuring acme.sh..."
    $ACME_SH --install -m "$ADMIN_EMAIL"
fi

# Get Cloudflare API Token
echo ""
echo "Visit https://dash.cloudflare.com/profile/api-tokens to create an API Token"
echo "Required permissions: Zone - DNS - Edit"
read -p "Enter Cloudflare API Token: " CF_Token
export CF_Token

# Get Cloudflare Zone ID
echo ""
echo "Visit https://dash.cloudflare.com/ and select your domain to find the Zone ID"
read -p "Enter Cloudflare Zone ID: " CF_Zone_ID
export CF_Zone_ID

# Get primary domain
echo ""
read -p "Enter primary domain (e.g., example.com): " YOUR_DOMAIN
export YOUR_DOMAIN

# Get subdomain (optional)
read -p "Enter subdomain (e.g., api.example.com, leave empty for primary domain only): " YOUR_SUBDOMAIN
export YOUR_SUBDOMAIN

# Issue certificate
echo ""
echo "Requesting certificate..."
if [ -z "$YOUR_SUBDOMAIN" ]; then
    $ACME_SH --issue --dns dns_cf -d "$YOUR_DOMAIN"
else
    $ACME_SH --issue --dns dns_cf -d "$YOUR_DOMAIN" -d "$YOUR_SUBDOMAIN"
fi

# Install certificate to Nginx
echo ""
echo "Installing certificate to Nginx..."

$ACME_SH --install-cert -d "$YOUR_DOMAIN" \
    --reloadcmd "service nginx force-reload"