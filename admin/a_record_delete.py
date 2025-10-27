import os

from cloudflare import Cloudflare
from cloudflare.types.dns.record_response import ARecord

CF_Token = os.getenv("CF_Token", None)
CF_Zone_ID = os.getenv("CF_Zone_ID", None)
APP_SUBDOMAIN_NAME = os.getenv("APP_SUBDOMAIN_NAME", None)


def delete_a_record():

    if CF_Token is None:
        print("Make sure CF_Token is set.")
        return
    if CF_Zone_ID is None:
        print("Make sure CF_Zone_ID is set.")
        return
    if APP_SUBDOMAIN_NAME is None:
        print("Make sure APP_SUBDOMAIN_NAME is set.")
        return

    client = Cloudflare(api_token=CF_Token)
    all_a_records = []
    for record in client.dns.records.list(
        zone_id=CF_Zone_ID, type="A", name={"exact": APP_SUBDOMAIN_NAME}
    ):
        if isinstance(record, ARecord):
            all_a_records.append(record)  # type: ignore
            print(
                f"Name: {record.name}, Content: {record.content}, Proxied: {record.proxied}"
            )

    if len(all_a_records) > 0:
        # Update
        record_response = client.dns.records.delete(
            dns_record_id=all_a_records[0].id, zone_id=CF_Zone_ID  # type: ignore
        )
        print(record_response)


if __name__ == "__main__":
    delete_a_record()
