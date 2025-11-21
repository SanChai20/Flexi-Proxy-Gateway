#!/usr/bin/env python3
import os
import sys

from cloudflare import Cloudflare

CF_Token = os.getenv("CF_Token", None)
CF_Zone_ID = os.getenv("CF_Zone_ID", None)
APP_SUBDOMAIN_NAME = os.getenv("APP_SUBDOMAIN_NAME", None)
PUBLIC_SERVER_IP = os.getenv("PUBLIC_SERVER_IP", None)


def update_a_record():

    if CF_Token is None:
        print("ERROR: CF_Token is not set.", file=sys.stderr)
        return 1
    if CF_Zone_ID is None:
        print("ERROR: CF_Zone_ID is not set.", file=sys.stderr)
        return 1
    if APP_SUBDOMAIN_NAME is None:
        print("ERROR: APP_SUBDOMAIN_NAME is not set.", file=sys.stderr)
        return 1
    if PUBLIC_SERVER_IP is None:
        print("ERROR: PUBLIC_SERVER_IP is not set.", file=sys.stderr)
        return 1

    try:
        client: Cloudflare = Cloudflare(api_token=CF_Token)

        record_response = client.dns.records.create(
            zone_id=CF_Zone_ID,
            name=APP_SUBDOMAIN_NAME,
            ttl=1,
            type="A",
            content=PUBLIC_SERVER_IP,
        )

        print(f"Record Response: {record_response}")
        return 0

    except Exception as e:
        error_msg = str(e)

        if "already exists" in error_msg.lower() or "81053" in error_msg:
            print(f"INFO: DNS record already exists for {APP_SUBDOMAIN_NAME}")
            print("INFO: This is expected if rerunning the deployment")
            return 0

        print(f"ERROR: Failed to create DNS record - {error_msg}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit_code = update_a_record()
    sys.exit(exit_code)
