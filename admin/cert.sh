#!/bin/bash
set -e

# Manage Cert by CertBot & Nginx [My HTTP website is running Nginx on Linux(pip)]

cd "$(dirname "$0")" || exit 1
echo "Change to sh dir"

echo "=============Install system dependencies BEGIN============="
sudo apt update
sudo apt install python3 python3-dev python3-venv libaugeas-dev gcc
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
sudo rm /usr/bin/certbot
sudo ln -s /opt/certbot/bin/certbot /usr/bin/certbot
echo "=============Prepare the Certbot command END============="

echo "=============Give *.sh files permissions BEGIN============="
chmod u+x ./_authenticator.sh
chmod u+x ./_cleanup.sh
echo "=============Give *.sh files permissions END============="

echo "=============Configure BEGIN============="
read -p "[DOMAIN_NAME] Please enter your domain's url: " DOMAIN_NAME
read -p "[VERCEL_ACCESS_TOKEN] Please enter your domain's url: " VERCEL_ACCESS_TOKEN
export VERCEL_ACCESS_TOKEN
read -p "[VERCEL_TEAM_ID] Please enter your domain's url: " VERCEL_TEAM_ID
export VERCEL_TEAM_ID
echo "=============Configure END============="

echo "=============Run Certbot - Get and install your certificates BEGIN============="
certbot -i nginx --manual --preferred-challenges=dns --manual-auth-hook ./_authenticator.sh --manual-cleanup-hook ./_cleanup.sh -d $DOMAIN_NAME
echo "=============Run Certbot - Get and install your certificates END============="

echo "=============Auto renew BEGIN============="
grep -q '/opt/certbot/bin/python -c .*certbot renew -q' /etc/crontab || \
echo "0 0,12 * * * root /opt/certbot/bin/python -c 'import random; import time; time.sleep(random.random() * 3600)' && sudo certbot renew -q" | sudo tee -a /etc/crontab
echo "=============Auto renew END============="