import os
import socket

import psutil
from cloudflare import Cloudflare

CLOUDFLARE_ACCESS_TOKEN = os.getenv("CLOUDFLARE_ACCESS_TOKEN", None)
CLOUDFLARE_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID", "")
APP_SUBDOMAIN_NAME = os.getenv("APP_SUBDOMAIN_NAME", "")
PUBLIC_SERVER_IP = os.getenv("PUBLIC_SERVER_IP", None)


def update_a_record():

    client = Cloudflare(api_token=CLOUDFLARE_ACCESS_TOKEN)
    all_a_records = []
    for record in client.dns.records.list(
        zone_id=CLOUDFLARE_ZONE_ID, type="A", name={"contains": APP_SUBDOMAIN_NAME}
    ):
        all_a_records.append(record)  # type: ignore
        print(
            f"Name: {record.name}, Content: {record.content}, Proxied: {record.proxied}"
        )

    if len(all_a_records) > 0:
        # Update

        pass
    else:
        # Create
        record_response = client.dns.records.create(
            zone_id=CLOUDFLARE_ZONE_ID,
            name=APP_SUBDOMAIN_NAME,
            ttl=1,
            type="A",
            content=PUBLIC_SERVER_IP,
        )
        print(record_response)

    print(f"\n总共找到 {len(all_a_records)} 条 A 记录")

    return


if __name__ == "__main__":
    update_a_record()
