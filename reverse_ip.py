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
ST_API_KEY = os.getenv("ST_API_KEY")

TIMEOUT = 30
CACHE_DIR = "cache"

os.makedirs(CACHE_DIR, exist_ok=True)


def get_cache_file(ip):
    return os.path.join(CACHE_DIR, f"{ip}.json")


def load_cache(ip):

    cache_file = get_cache_file(ip)

    if os.path.exists(cache_file):

        try:
            with open(cache_file, "r") as f:
                return json.load(f)

        except Exception:
            pass

    return None


def save_cache(ip, results):

    cache_file = get_cache_file(ip)

    with open(cache_file, "w") as f:

        json.dump(
            {
                "ip": ip,
                "results": results
            },
            f,
            indent=2
        )


def safe_request(method, url, headers=None):

    for attempt in range(3):

        try:

            time.sleep(2)

            if method == "GET":

                r = requests.get(
                    url,
                    headers=headers,
                    timeout=TIMEOUT
                )

            else:

                r = requests.post(
                    url,
                    headers=headers,
                    timeout=TIMEOUT
                )

            return r

        except Exception as e:

            print(
                f"[RETRY {attempt+1}/3] "
                f"{url}"
            )

            print(e)

            time.sleep(5)

    return None


def vt_lookup(ip):

    results = []

    url = (
        f"https://www.virustotal.com/api/v3/"
        f"ip_addresses/{ip}/resolutions"
    )

    headers = {
        "x-apikey": VT_API_KEY
    }

    r = safe_request(
        "GET",
        url,
        headers
    )

    if not r:
        return results

    if r.status_code == 200:

        data = r.json()

        for item in data.get("data", []):

            hostname = (
                item.get("attributes", {})
                .get("host_name")
            )

            if hostname:

                results.append({
                    "domain": hostname,
                    "source": "VirusTotal"
                })

    elif r.status_code == 429:

        print(f"[VT] {ip} Rate Limited")

    else:

        print(
            f"[VT] {ip} HTTP {r.status_code}"
        )

    return results


def st_lookup(ip):

    results = []

    url = (
        f"https://api.securitytrails.com/v1/ips/{ip}"
    )

    headers = {
        "APIKEY": ST_API_KEY
    }

    r = safe_request(
        "GET",
        url,
        headers
    )

    if not r:
        return results

    if r.status_code == 200:

        data = r.json()

        hostname = data.get("hostname")

        if isinstance(hostname, str):

            results.append({
                "domain": hostname,
                "source": "SecurityTrails"
            })

        hostnames = data.get("hostnames")

        if isinstance(hostnames, list):

            for h in hostnames:

                results.append({
                    "domain": h,
                    "source": "SecurityTrails"
                })

    elif r.status_code == 429:

        print(f"[ST] {ip} Rate Limited")

    else:

        print(
            f"[ST] {ip} HTTP {r.status_code}"
        )

    return results


def verify_domain(domain, target_ip):

    try:

        resolved = socket.gethostbyname(domain)

        if resolved == target_ip:
            return True

        return False

    except Exception:

        return False


def process_ip(ip):

    cached = load_cache(ip)

    if cached:

        print(f"[CACHE] {ip}")

        return cached["results"]

    print(f"[*] Processing {ip}")

    domain_map = {}

    #################################################
    # VIRUSTOTAL
    #################################################

    for item in vt_lookup(ip):

        domain = item["domain"]

        if domain not in domain_map:

            domain_map[domain] = {
                "source": item["source"]
            }

        else:

            if item["source"] not in domain_map[domain]["source"]:

                domain_map[domain]["source"] += (
                    "|" + item["source"]
                )

    #################################################
    # SECURITYTRAILS
    #################################################

    for item in st_lookup(ip):

        domain = item["domain"]

        if domain not in domain_map:

            domain_map[domain] = {
                "source": item["source"]
            }

        else:

            if item["source"] not in domain_map[domain]["source"]:

                domain_map[domain]["source"] += (
                    "|" + item["source"]
                )

    #################################################
    # VERIFY
    #################################################

    results = []

    for domain, meta in domain_map.items():

        live = verify_domain(
            domain,
            ip
        )

        results.append({
            "ip": ip,
            "domain": domain,
            "source": meta["source"],
            "live_match": live
        })

    save_cache(
        ip,
        results
    )

    print(
        f"[+] {ip} -> {len(results)} domain(s)"
    )

    return results


def main():

    if not VT_API_KEY:
        print("VT_API_KEY not set")
        return

    if not ST_API_KEY:
        print("ST_API_KEY not set")
        return

    with open("ips.txt") as f:

        ips = [
            x.strip()
            for x in f
            if x.strip()
        ]

    all_rows = []

    total = len(ips)

    for idx, ip in enumerate(ips, start=1):

        print(
            f"\n[{idx}/{total}] {ip}"
        )

        try:

            rows = process_ip(ip)

            all_rows.extend(rows)

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
        writer.writerows(all_rows)

    with open(
        "live_domains.txt",
        "w"
    ) as f:

        for row in all_rows:

            if row["live_match"]:

                f.write(
                    row["domain"] + "\n"
                )

    print("\n========== DONE ==========")
    print(f"IPs      : {len(ips)}")
    print(f"Records  : {len(all_rows)}")
    print("CSV      : output.csv")
    print("Live TXT : live_domains.txt")
    print("Cache    : cache/")


if __name__ == "__main__":
    main()
