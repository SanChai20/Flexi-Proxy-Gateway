import os

from cloudflare import Cloudflare

CF_Token = os.getenv("CF_Token", None)
CF_Zone_ID = os.getenv("CF_Zone_ID", None)
APP_SUBDOMAIN_NAME = os.getenv("APP_SUBDOMAIN_NAME", None)
PUBLIC_SERVER_IP = os.getenv("PUBLIC_SERVER_IP", None)


def update_a_record():

    if CF_Token is None:
        print("Make sure CF_Token is set.")
        return
    if CF_Zone_ID is None:
        print("Make sure CF_Zone_ID is set.")
        return
    if APP_SUBDOMAIN_NAME is None:
        print("Make sure APP_SUBDOMAIN_NAME is set.")
        return
    if PUBLIC_SERVER_IP is None:
        print("Public ip is none.")
        return

    client = Cloudflare(api_token=CF_Token)
    # Create
    record_response = client.dns.records.create(
        zone_id=CF_Zone_ID,
        name=APP_SUBDOMAIN_NAME,
        ttl=1,
        type="A",
        content=PUBLIC_SERVER_IP,
    )
    print(record_response)


if __name__ == "__main__":
    update_a_record()
