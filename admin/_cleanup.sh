#!/bin/bash

cd "$(dirname "$0")" || exit 1
# Strip only the top domain to get the zone id
DOMAIN=$(expr match "$CERTBOT_DOMAIN" '.*\.\(.*\..*\)')

if [ -f /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID ]; then
        RECORD_ID=$(cat /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID)
        rm -f /tmp/CERTBOT_$CERTBOT_DOMAIN/RECORD_ID
fi

# Remove the challenge TXT record
if [ -n "${RECORD_ID}" ]; then
    curl -s -X DELETE "https://api.vercel.com/v2/domains/$DOMAIN/records/$RECORD_ID" \
            -H "Authorization: Bearer $VERCEL_ACCESS_TOKEN"
fi