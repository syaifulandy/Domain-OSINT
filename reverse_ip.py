#!/usr/bin/env python3

import os
import csv
import json
import time
import socket
import requests

from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

TIMEOUT = 30
CACHE_DIR = "cache"

os.makedirs(CACHE_DIR, exist_ok=True)


def get_cache_file(ip):
    return os.path.join(
        CACHE_DIR,
        f"{ip}.json"
    )


def load_cache(ip):

    cache_file = get_cache_file(ip)

    if os.path.exists(cache_file):

        try:

            with open(
                cache_file,
                "r"
            ) as f:

                return json.load(f)

        except:
            pass

    return None


def save_cache(ip, results):

    cache_file = get_cache_file(ip)

    with open(
        cache_file,
        "w"
    ) as f:

        json.dump(
            {
                "ip": ip,
                "results": results
            },
            f,
            indent=2
        )


def safe_request(url, headers=None):

    for attempt in range(3):

        try:

            time.sleep(3)

            r = requests.get(
                url,
                headers=headers,
                timeout=TIMEOUT
            )

            return r

        except Exception as e:

            print(
                f"[RETRY {attempt+1}/3]"
            )

            print(e)

            time.sleep(5)

    return None


#################################################
# VIRUSTOTAL
#################################################

def vt_lookup(ip):

    results = []
    seen = set()

    url = (
        "https://www.virustotal.com/api/v3/"
        f"ip_addresses/{ip}/resolutions"
    )

    headers = {
        "x-apikey": VT_API_KEY
    }

    while url:

        r = safe_request(
            url,
            headers
        )

        if not r:
            break

        if r.status_code == 429:

            print(
                f"[VT] {ip} Rate Limited"
            )

            break

        if r.status_code != 200:

            print(
                f"[VT] {ip} "
                f"HTTP {r.status_code}"
            )

            break

        data = r.json()

        for item in data.get(
            "data",
            []
        ):

            host = (
                item.get(
                    "attributes",
                    {}
                ).get(
                    "host_name"
                )
            )

            if (
                host
                and host not in seen
            ):

                seen.add(host)

                results.append(
                    {
                        "domain": host,
                        "source": "VirusTotal"
                    }
                )

        url = (
            data.get(
                "links",
                {}
            ).get(
                "next"
            )
        )

    return results

#################################################
# URLSCAN
#################################################

def urlscan_lookup(ip):

    results = []

    url = (
        "https://urlscan.io/api/v1/search/"
        f"?q=ip:{ip}"
    )

    r = safe_request(url)

    if not r:
        return results

    if r.status_code != 200:

        print(
            f"[URLSCAN] {ip} "
            f"HTTP {r.status_code}"
        )

        return results

    try:

        data = r.json()

        seen = set()

        for item in data.get(
            "results",
            []
        ):

            page = item.get(
                "page",
                {}
            )

            if page.get("ip") != ip:
                continue

            candidates = []

            page_domain = page.get(
                "domain"
            )

            if page_domain:
                candidates.append(
                    page_domain
                )

            task_domain = (
                item.get(
                    "task",
                    {}
                ).get("domain")
            )

            if task_domain:
                candidates.append(
                    task_domain
                )

            ptr = page.get("ptr")

            if ptr:
                candidates.append(
                    ptr
                )

            for domain in candidates:

                domain = (
                    domain
                    .strip()
                    .lower()
                )

                if (
                    domain
                    and domain not in seen
                ):

                    seen.add(domain)

                    results.append(
                        {
                            "domain":
                                domain,
                            "source":
                                "URLScan"
                        }
                    )

    except Exception as e:

        print(
            f"[URLSCAN ERROR] "
            f"{ip}: {e}"
        )

    return results


#################################################
# VERIFY
#################################################

def verify_domain(
    domain,
    target_ip
):

    try:

        resolved = (
            socket.gethostbyname(
                domain
            )
        )

        return (
            resolved == target_ip
        )

    except:
        return False


#################################################
# PROCESS
#################################################

def process_ip(ip):

    cached = load_cache(ip)

    if cached:

        print(
            f"[CACHE] {ip}"
        )

        return cached[
            "results"
        ]

    print(
        f"[*] Processing {ip}"
    )

    domain_map = {}

    #################################
    # VT
    #################################

    for item in vt_lookup(ip):

        domain = item["domain"]

        if domain not in domain_map:

            domain_map[
                domain
            ] = item["source"]

        else:

            if (
                item["source"]
                not in
                domain_map[domain]
            ):

                domain_map[
                    domain
                ] += (
                    "|" +
                    item["source"]
                )

    #################################
    # URLSCAN
    #################################

    for item in urlscan_lookup(ip):

        domain = item["domain"]

        if domain not in domain_map:

            domain_map[
                domain
            ] = item["source"]

        else:

            if (
                item["source"]
                not in
                domain_map[domain]
            ):

                domain_map[
                    domain
                ] += (
                    "|" +
                    item["source"]
                )

    #################################
    # VERIFY
    #################################

    results = []

    for (
        domain,
        source
    ) in domain_map.items():

        live = verify_domain(
            domain,
            ip
        )

        results.append(
            {
                "ip": ip,
                "domain": domain,
                "source": source,
                "live_match": live
            }
        )

    save_cache(
        ip,
        results
    )

    print(
        f"[+] {ip} -> "
        f"{len(results)} domains"
    )

    return results


#################################################
# MAIN
#################################################

def main():

    if not VT_API_KEY:

        print(
            "VT_API_KEY not set"
        )

        return

    with open(
        "ips.txt"
    ) as f:

        ips = [

            x.strip()

            for x in f

            if x.strip()
        ]

    all_rows = []

    total = len(ips)

    for idx, ip in enumerate(
        ips,
        start=1
    ):

        print(
            f"\n[{idx}/{total}] "
            f"{ip}"
        )

        try:

            rows = process_ip(ip)

            all_rows.extend(
                rows
            )

        except Exception as e:

            print(
                f"[ERROR] {ip}"
            )

            print(e)

    with open(
        "output.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ip",
                "domain",
                "source",
                "live_match"
            ]
        )

        writer.writeheader()

        writer.writerows(
            all_rows
        )

    with open(
        "live_domains.txt",
        "w"
    ) as f:

        written = set()

        for row in all_rows:

            if (
                row["live_match"]
                and
                row["domain"]
                not in written
            ):

                written.add(
                    row["domain"]
                )

                f.write(
                    row["domain"]
                    + "\n"
                )

    print(
        "\n========== DONE =========="
    )

    print(
        f"IPs     : {len(ips)}"
    )

    print(
        f"Records : {len(all_rows)}"
    )

    print(
        "CSV     : output.csv"
    )

    print(
        "Live    : live_domains.txt"
    )


if __name__ == "__main__":
    main()
