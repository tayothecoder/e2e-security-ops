#!/usr/bin/env python3
"""recon.py - basic reconnaissance against a target web app"""

import argparse
import json
import socket
import sys
import time

import requests
from colorama import Fore, Style, init

init(autoreset=True)

# common ports to check
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
                995, 1433, 1521, 3306, 3389, 5000, 5432, 5900, 6379, 8000,
                8080, 8443, 8888, 9090, 27017]


def banner():
    print(f"{Fore.CYAN}{'='*60}")
    print(f"  recon.py - target reconnaissance")
    print(f"{'='*60}{Style.RESET_ALL}\n")


def scan_ports(host, ports=None):
    """socket-based port scan"""
    if ports is None:
        ports = COMMON_PORTS
    open_ports = []
    print(f"{Fore.YELLOW}[*] scanning {len(ports)} ports on {host}...")
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"{Fore.RED}  [+] port {port} is open")
                open_ports.append(port)
            sock.close()
        except socket.error:
            pass
    if not open_ports:
        print(f"{Fore.GREEN}  [-] no open ports found in common list")
    return open_ports


def analyze_headers(base_url):
    """grab http headers and look for interesting stuff"""
    print(f"\n{Fore.YELLOW}[*] analyzing HTTP headers...")
    findings = {}
    try:
        resp = requests.get(base_url, timeout=5, allow_redirects=False)
        headers = dict(resp.headers)
        findings["status_code"] = resp.status_code
        findings["headers"] = headers

        security_headers = [
            "X-Content-Type-Options", "X-Frame-Options",
            "Content-Security-Policy", "Strict-Transport-Security",
            "X-XSS-Protection", "Referrer-Policy"
        ]
        headers_lower = {k.lower(): v for k, v in headers.items()}
        missing = [h for h in security_headers if h.lower() not in headers_lower]
        findings["missing_security_headers"] = missing

        if missing:
            print(f"{Fore.RED}  [+] missing security headers: {', '.join(missing)}")
        else:
            print(f"{Fore.GREEN}  [-] all common security headers present")

        server = headers.get("Server", "")
        if server:
            print(f"{Fore.RED}  [+] server header exposed: {server}")
            findings["server"] = server

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            print(f"{Fore.RED}  [+] X-Powered-By: {powered_by}")
            findings["powered_by"] = powered_by

    except requests.ConnectionError:
        print(f"{Fore.RED}  [!] connection failed to {base_url}")
        findings["error"] = "connection failed"
    return findings


def fingerprint(base_url):
    """try to figure out what tech stack is running"""
    print(f"\n{Fore.YELLOW}[*] fingerprinting technology stack...")
    tech = []
    try:
        resp = requests.get(base_url, timeout=5)
        body = resp.text.lower()
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

        checks = {
            "Flask": "werkzeug" in headers_lower.get("server", ""),
            "Django": "csrfmiddlewaretoken" in body,
            "WordPress": "wp-content" in body,
            "jQuery": "jquery" in body,
            "Bootstrap": "bootstrap" in body,
            "React": "react" in body or "_reactroot" in body,
        }
        for name, detected in checks.items():
            if detected:
                print(f"{Fore.RED}  [+] detected: {name}")
                tech.append(name)

        if resp.cookies:
            cookie_names = list(resp.cookies.keys())
            print(f"{Fore.YELLOW}  [*] cookies: {', '.join(cookie_names)}")
            if "session" in cookie_names:
                tech.append("server-side sessions")

    except requests.ConnectionError:
        print(f"{Fore.RED}  [!] connection failed")
    return tech


def dir_bruteforce(base_url, wordlist_path=None):
    """try common directories to find hidden endpoints"""
    print(f"\n{Fore.YELLOW}[*] bruteforcing directories...")
    found = []

    # make sure base_url doesn't have trailing slash
    base_url = base_url.rstrip("/")

    if wordlist_path:
        try:
            with open(wordlist_path) as f:
                dirs = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}  [!] wordlist not found: {wordlist_path}")
            dirs = []
    else:
        dirs = ["admin", "login", "dashboard", "api", "uploads", "upload",
                "static", "backup", "config", "debug", "test", ".git",
                ".env", "robots.txt", "console", "search", "profile",
                "register", "logout", "reset", "docs", "swagger",
                "download", "reviews"]

    for d in dirs:
        target = f"{base_url}/{d}"
        try:
            resp = requests.get(target, timeout=3, allow_redirects=False)
            if resp.status_code not in [404]:
                status = resp.status_code
                color = Fore.RED if status == 200 else Fore.YELLOW
                print(f"{color}  [+] /{d} -> {status}")
                found.append({"path": f"/{d}", "status": status})
        except requests.ConnectionError:
            pass
        except requests.Timeout:
            pass

    if not found:
        print(f"{Fore.GREEN}  [-] no interesting directories found")
    return found


def run_recon(target_url, host=None, wordlist=None):
    """main recon routine, returns all findings as dict"""
    banner()
    if host is None:
        host = target_url.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]

    results = {"target": target_url, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
    results["open_ports"] = scan_ports(host)
    results["headers"] = analyze_headers(target_url)
    results["technologies"] = fingerprint(target_url)
    results["directories"] = dir_bruteforce(target_url, wordlist)

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  recon complete")
    print(f"  open ports: {len(results['open_ports'])}")
    print(f"  technologies: {', '.join(results['technologies']) or 'none identified'}")
    print(f"  directories found: {len(results['directories'])}")
    print(f"{'='*60}{Style.RESET_ALL}")

    return results


def main():
    parser = argparse.ArgumentParser(description="recon.py - target reconnaissance")
    parser.add_argument("-t", "--target", default="http://127.0.0.1:5000",
                        help="target URL (default: http://127.0.0.1:5000)")
    parser.add_argument("-w", "--wordlist", default=None,
                        help="path to directory wordlist")
    parser.add_argument("-o", "--output", default="recon_report.json",
                        help="output file path")
    args = parser.parse_args()

    results = run_recon(args.target, wordlist=args.wordlist)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n{Fore.GREEN}[+] results saved to {args.output}")


if __name__ == "__main__":
    main()
