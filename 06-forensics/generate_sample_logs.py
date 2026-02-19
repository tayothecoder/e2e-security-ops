#!/usr/bin/env python3
"""generate realistic sample logs from attack activity for forensic analysis.
creates suricata eve.json and apache-style access logs that the forensics
tools can parse without needing a live IDS/web server stack."""

import json
import os
import random
import time
from datetime import datetime, timedelta

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "sample_logs")


def generate_suricata_eve(start_time, num_alerts=150):
    """generate suricata eve.json alerts matching our attack patterns."""
    alerts = []
    attack_sigs = [
        {"sid": 2100001, "msg": "SQL Injection attempt detected",
         "category": "Web Application Attack", "severity": 1},
        {"sid": 2100002, "msg": "UNION SELECT statement in HTTP request",
         "category": "Web Application Attack", "severity": 1},
        {"sid": 2100003, "msg": "XSS script tag in request parameter",
         "category": "Web Application Attack", "severity": 2},
        {"sid": 2100004, "msg": "XSS event handler in request",
         "category": "Web Application Attack", "severity": 2},
        {"sid": 2100005, "msg": "Brute force login attempt",
         "category": "Attempted Information Leak", "severity": 2},
        {"sid": 2100006, "msg": "Directory traversal attempt via path",
         "category": "Web Application Attack", "severity": 1},
        {"sid": 2100007, "msg": "Suspicious file upload detected",
         "category": "Web Application Attack", "severity": 1},
        {"sid": 2100008, "msg": "IDOR sequential ID enumeration",
         "category": "Attempted Information Leak", "severity": 3},
        {"sid": 2100009, "msg": "PHP/Python shell upload attempt",
         "category": "Web Application Attack", "severity": 1},
        {"sid": 2100010, "msg": "HTTP response code bruteforce pattern",
         "category": "Potentially Bad Traffic", "severity": 3},
    ]

    src_ips = ["10.0.1.50", "10.0.1.51", "192.168.1.100"]
    dest_ip = "10.0.2.10"
    t = start_time

    for i in range(num_alerts):
        sig = random.choice(attack_sigs)
        t += timedelta(seconds=random.uniform(0.5, 8.0))

        alert = {
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
            "flow_id": random.randint(100000000, 999999999),
            "in_iface": "eth0",
            "event_type": "alert",
            "src_ip": random.choice(src_ips),
            "src_port": random.randint(40000, 65000),
            "dest_ip": dest_ip,
            "dest_port": 5000,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": sig["sid"],
                "rev": 1,
                "signature": sig["msg"],
                "category": sig["category"],
                "severity": sig["severity"],
            },
            "http": {
                "hostname": "travelbird.local",
                "http_method": random.choice(["GET", "POST"]),
                "protocol": "HTTP/1.1",
                "status": random.choice([200, 302, 403, 500]),
                "length": random.randint(200, 5000),
            },
            "app_proto": "http",
        }
        alerts.append(alert)

    return alerts


def generate_access_log(start_time, num_entries=300):
    """generate apache/nginx-style access log entries."""
    lines = []
    paths = [
        ('GET', '/login', 200),
        ('POST', '/login', 302),
        ('POST', '/login', 200),
        ('GET', '/search?q=test', 200),
        ('GET', "/search?q=' OR 1=1 --", 200),
        ('GET', "/search?q=<script>alert(1)</script>", 200),
        ('GET', '/admin', 302),
        ('GET', '/profile/1', 200),
        ('GET', '/profile/2', 200),
        ('GET', '/profile/3', 200),
        ('GET', '/profile/4', 200),
        ('GET', '/profile/5', 200),
        ('GET', '/profile/6', 200),
        ('POST', '/upload', 302),
        ('GET', '/download?file=shell.php', 200),
        ('GET', '/download?file=../../app.py', 200),
        ('GET', '/console', 200),
        ('GET', '/', 200),
        ('GET', '/packages', 200),
        ('GET', '/booking/1', 200),
    ]

    ips = ["10.0.1.50", "10.0.1.51", "192.168.1.100", "10.0.1.20"]
    t = start_time

    for i in range(num_entries):
        method, path, status = random.choice(paths)
        ip = random.choice(ips)
        t += timedelta(seconds=random.uniform(0.2, 5.0))
        size = random.randint(200, 15000)
        ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        line = f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size}'
        lines.append(line)

    return lines


def generate_auth_log(start_time, num_entries=50):
    """generate auth.log style entries with ssh brute force attempts."""
    lines = []
    users = ["root", "admin", "ubuntu", "test", "user", "pi", "oracle"]
    ips = ["10.0.1.50", "203.0.113.42", "198.51.100.17"]
    t = start_time

    for i in range(num_entries):
        t += timedelta(seconds=random.uniform(1, 30))
        user = random.choice(users)
        ip = random.choice(ips)
        ts = t.strftime("%b %d %H:%M:%S")

        if random.random() < 0.7:
            line = f"{ts} travelbird sshd[{random.randint(10000,99999)}]: Failed password for {'invalid user ' if random.random() < 0.5 else ''}{user} from {ip} port {random.randint(40000,65000)} ssh2"
        else:
            line = f"{ts} travelbird sshd[{random.randint(10000,99999)}]: Accepted password for ubuntu from {ip} port {random.randint(40000,65000)} ssh2"
        lines.append(line)

    return lines


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    start = datetime.now() - timedelta(hours=1)

    # suricata eve.json
    alerts = generate_suricata_eve(start)
    eve_path = os.path.join(OUTPUT_DIR, "eve.json")
    with open(eve_path, "w") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")
    print(f"[+] wrote {len(alerts)} alerts to sample_logs/eve.json")

    # access log
    access_lines = generate_access_log(start)
    access_path = os.path.join(OUTPUT_DIR, "access.log")
    with open(access_path, "w") as f:
        f.write("\n".join(access_lines) + "\n")
    print(f"[+] wrote {len(access_lines)} entries to sample_logs/access.log")

    # auth log
    auth_lines = generate_auth_log(start)
    auth_path = os.path.join(OUTPUT_DIR, "auth.log")
    with open(auth_path, "w") as f:
        f.write("\n".join(auth_lines) + "\n")
    print(f"[+] wrote {len(auth_lines)} entries to sample_logs/auth.log")

    print(f"[+] sample logs generated in sample_logs/")


if __name__ == "__main__":
    main()
