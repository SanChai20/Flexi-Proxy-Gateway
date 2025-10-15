#!/bin/bash
set -e

# Manage Cert by CertBot & Nginx [My HTTP website is running Nginx on Linux(pip)]

cd "$(dirname "$0")" || exit 1
echo "Change to sh dir"

export PROXY_SERVER_LISTEN_PORT=4000
read -p "[CUSTOMIZE_SUBDOMAIN_NAME] Customized Subdomain (in format of *.flexiproxy.com): " CUSTOMIZE_SUBDOMAIN_NAME
export CUSTOMIZE_SUBDOMAIN_NAME
read -p "Do you want to deploy Certbot SSL? (y/n): " DEPLOY_CERTBOT

if [[ "$DEPLOY_CERTBOT" == "y" || "$DEPLOY_CERTBOT" == "Y" ]]; then
echo "=============Install system dependencies BEGIN============="
sudo apt update
sudo apt install python3 python3-dev python3-venv libaugeas-dev gcc nginx build-essential
echo "=============Install system dependencies END============="

echo "=============Remove certbot-auto and any Certbot OS packages BEGIN============="
sudo apt-get remove certbot
echo "=============Remove certbot-auto and any Certbot OS packages END============="

echo "=============Set up a Python virtual environment BEGIN============="
sudo python3 -m venv /opt/certbot/
sudo /opt/certbot/bin/pip install --upgrade pip
echo "=============Set up a Python virtual environment END============="

echo "=============Install Certbot BEGIN============="
sudo /opt/certbot/bin/pip install certbot certbot-nginx
echo "=============Install Certbot END============="

echo "=============Prepare the Certbot command BEGIN============="
if [ -f /usr/bin/certbot ]; then
    echo "Removing existing /usr/bin/certbot..."
    sudo rm /usr/bin/certbot
fi
sudo ln -s /opt/certbot/bin/certbot /usr/bin/certbot
echo "=============Prepare the Certbot command END============="

echo "=============Give *.sh files permissions BEGIN============="
chmod u+x ./_authenticator.sh
chmod u+x ./_cleanup.sh
echo "=============Give *.sh files permissions END============="

echo "=============Configure BEGIN============="
read -p "[VERCEL_ACCESS_TOKEN] Vercel's access token (https://vercel.com/account/settings/tokens): " VERCEL_ACCESS_TOKEN
export VERCEL_ACCESS_TOKEN
read -p "[VERCEL_TEAM_ID] Vercel team's id (https://vercel.com/account): " VERCEL_TEAM_ID
export VERCEL_TEAM_ID
echo "=============Configure END============="

echo "=============Run Certbot - Get and install your certificates BEGIN============="
certbot -i nginx --manual --preferred-challenges=dns \
    --manual-auth-hook ./_authenticator.sh \
    --manual-cleanup-hook ./_cleanup.sh -d $CUSTOMIZE_SUBDOMAIN_NAME
echo "=============Run Certbot - Get and install your certificates END============="

echo "=============Auto renew BEGIN============="
grep -q '/opt/certbot/bin/python -c .*certbot renew -q' /etc/crontab || \
echo "0 0,12 * * * root /opt/certbot/bin/python -c 'import random; import time; time.sleep(random.random() * 3600)' && sudo certbot renew -q" | sudo tee -a /etc/crontab
echo "=============Auto renew END============="

echo "=============Replace Template BEGIN============="
envsubst '$CUSTOMIZE_SUBDOMAIN_NAME $PROXY_SERVER_LISTEN_PORT' \
  < ./sites-template.conf \
  | sudo tee /etc/nginx/sites-enabled/default > /dev/null
echo "=============Replace Template END============="

echo "=============Reload Nginx BEGIN============="
sudo nginx -t
sudo systemctl reload nginx
echo "=============Reload Nginx END============="
else
echo "Skipping Certbot deployment..."
fi

read -p "Do you want to launch Litellm Proxy Server? (y/n): " LAUNCH_SERVER

if [[ "$LAUNCH_SERVER" == "y" || "$LAUNCH_SERVER" == "Y" ]]; then

cd ../
echo "Change to project dir"

echo "=============Launch - Generate Key Pair BEGIN============="
echo "Generating key pair..."
read -p "[FP_PROXY_SERVER_KEYPAIR_PWD] Customized key pair password: " FP_PROXY_SERVER_KEYPAIR_PWD
export FP_PROXY_SERVER_KEYPAIR_PWD
export FP_PROXY_SERVER_KEYPAIR_DIR=../key
python3 ./admin/create_key_pair.py
echo "=============Launch - Generate Key Pair END============="

echo "=============Launch - Authorized *.pem BEGIN============="
chmod 600 ../key/key.pem
chmod 600 ../key/public.pem
echo "=============Launch - Authorized *.pem END============="

echo "=============Launch - Check virtual environments BEGIN============="
echo "Checking if virtual environment already exists..."
if [ -d ".venv" ]; then
    echo ".venv already exists, skipping creation."
else
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi
echo "=============Launch - Check virtual environments END============="

echo "=============Launch - Activating virtual environment BEGIN============="
source .venv/bin/activate
echo "=============Launch - Activating virtual environment END============="

echo "=============Launch - Installing dependencies BEGIN============="
pip install -r requirements.txt
echo "=============Launch - Installing dependencies END============="

echo "=============Launch - Settings environment variables BEGIN============="

export FP_PROXY_SERVER_URL="https://$CUSTOMIZE_SUBDOMAIN_NAME"
export FP_PROXY_SERVER_ID=$(expr match "$CUSTOMIZE_SUBDOMAIN_NAME" '\([^\.]*\)\..*')
export FP_APP_BASE_URL=https://www.flexiproxy.com
export FP_LRU_MAX_CACHE_SIZE=2000
export FP_HTTP_CONNECT_TIMEOUT_LIMIT=5
export FP_HTTP_READ_TIMEOUT_LIMIT=120
export FP_HTTP_MAX_RETRY_COUNT=3
export FP_HTTP_MAX_POOL_CONNECTIONS_COUNT=50
export FP_HTTP_POOL_MAX_SIZE=200
export FP_HTTP_RETRY_BACKOFF=0.3
export LITELLM_NUM_WORKERS=4
export LITELLM_SET_VERBOSE=False
export LITELLM_DROP_PARAMS=True
export LITELLM_MODE=PRODUCTION
export NO_DOCS=True
export NO_REDOC=True

read -p "[FP_APP_TOKEN_PASS] Issued by flexi-proxy admin/token-issuance.ts: " FP_APP_TOKEN_PASS
export FP_APP_TOKEN_PASS

read -p "[FP_PROXY_SERVER_ADVANCED] Advanced Proxy Server? (0 or 1): " FP_PROXY_SERVER_ADVANCED
export FP_PROXY_SERVER_ADVANCED

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
    echo "This is critical for token encryption." >&2
    exit 1
fi

# Critical validation check
if [ -z "$CUSTOMIZE_SUBDOMAIN_NAME" ]; then
    echo "ERROR: Could not detect server_name." >&2
    echo "Please verify your nginx config has a valid 'server_name' directive." >&2
    exit 1
fi

echo "=============Launch - Settings environment variables END============="

echo "=============Launch - Starting LiteLLM Proxy Server BEGIN============="
nohup litellm --config config.yaml --port $PROXY_SERVER_LISTEN_PORT &
echo "=============Launch - Starting LiteLLM Proxy Server END============="

else
echo "Skipping launching..."
fi