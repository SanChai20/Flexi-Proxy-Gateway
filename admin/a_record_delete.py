#!/usr/bin/env python3
import os
import sys

from cloudflare import Cloudflare
from cloudflare.types.dns.record_response import ARecord

CF_Token = os.getenv("CF_Token", None)
CF_Zone_ID = os.getenv("CF_Zone_ID", None)
APP_SUBDOMAIN_NAME = os.getenv("APP_SUBDOMAIN_NAME", None)


def delete_a_record():

    if CF_Token is None:
        print("ERROR: CF_Token is not set.", file=sys.stderr)
        return 1
    if CF_Zone_ID is None:
        print("ERROR: CF_Zone_ID is not set.", file=sys.stderr)
        return 1
    if APP_SUBDOMAIN_NAME is None:
        print("ERROR: APP_SUBDOMAIN_NAME is not set.", file=sys.stderr)
        return 1

    try:
        client = Cloudflare(api_token=CF_Token)

        all_a_records = []
        for record in client.dns.records.list(
            zone_id=CF_Zone_ID, type="A", name={"exact": APP_SUBDOMAIN_NAME}
        ):
            if isinstance(record, ARecord):
                all_a_records.append(record)  # type: ignore
                print(
                    f"Found: Name={record.name}, Content={record.content}, Proxied={record.proxied}"
                )

        if len(all_a_records) > 0:
            deleted_count = 0
            for record in all_a_records:
                try:
                    client.dns.records.delete(
                        dns_record_id=record.id, zone_id=CF_Zone_ID  # type: ignore
                    )
                    print(f"SUCCESS: Deleted DNS A record {record.name} (ID: {record.id})")  # type: ignore
                    deleted_count += 1
                except Exception as e:
                    print(f"WARNING: Failed to delete record {record.id}: {str(e)}", file=sys.stderr)  # type: ignore

            if deleted_count > 0:
                print(
                    f"SUCCESS: Deleted {deleted_count} DNS A record(s) for {APP_SUBDOMAIN_NAME}"
                )
                return 0
            else:
                print("ERROR: Failed to delete any DNS records", file=sys.stderr)
                return 1
        else:
            print(f"INFO: No DNS A records found for {APP_SUBDOMAIN_NAME}")
            print("INFO: This is expected if records were already deleted")
            return 0

    except Exception as e:
        print(f"ERROR: Failed to delete DNS record - {str(e)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit_code = delete_a_record()
    sys.exit(exit_code)
