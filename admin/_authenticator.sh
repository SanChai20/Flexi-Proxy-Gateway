#!/bin/bash

cd "$(dirname "$0")" || exit 1
# Strip only the top domain to get the zone id
DOMAIN=$(expr match "$CERTBOT_DOMAIN" '.*\.\(.*\..*\)')
EXTRA_QUERY_PARAMS="teamId=$VERCEL_TEAM_ID"

# List records
# RECORDS=$(curl s -X GET "https://api.vercel.com/v4/domains/$DOMAIN/records?$EXTRA_QUERY_PARAMS" \
#   -H "Authorization: Bearer $VERCEL_ACCESS_TOKEN" \
#   | python -c "import sys,json;print(json.load(sys.stdin))")


# Create A record
PUBLIC_IP=$(curl -s ifconfig.me)
curl -s -X POST "https://api.vercel.com/v2/domains/$DOMAIN/records?$EXTRA_QUERY_PARAMS" \
     -H     "Authorization: Bearer $VERCEL_ACCESS_TOKEN" \
     -H     "Content-Type: application/json" \
     --data '{"type":"A","name":"'"$CERTBOT_DOMAIN"'","value":"'"$PUBLIC_IP"'","ttl":120,"comment":"'"registry"'"}'

# Create TXT record
CREATE_DOMAIN="_acme-challenge.$CERTBOT_DOMAIN"
TXTRECORD_ID=$(curl -s -X POST "https://api.vercel.com/v2/domains/$DOMAIN/records?$EXTRA_QUERY_PARAMS" \
     -H     "Authorization: Bearer $VERCEL_ACCESS_TOKEN" \
     -H     "Content-Type: application/json" \
     --data '{"type":"TXT","name":"'"$CREATE_DOMAIN"'","value":"'"$CERTBOT_VALIDATION"'","ttl":120,"comment":"'"temp"'"}' \
             | python -c "import sys,json;print(json.load(sys.stdin)['uid'])")
# Save info for cleanup
if [ ! -d /tmp/CERTBOT_$CERTBOT_DOMAIN ];then
        mkdir -m 0700 /tmp/CERTBOT_$CERTBOT_DOMAIN
fi
echo $TXTRECORD_ID > /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID

# Sleep to make sure the change has time to propagate over to DNS
sleep 25