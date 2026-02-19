#!/usr/bin/env python3
"""generate sample datasets for training and testing the ids model"""

import csv
import os
import random

random.seed(42)


def generate_benign(count=200):
    """generate normal-looking network traffic features"""
    rows = []
    protocols = ['tcp', 'udp', 'tcp', 'tcp']  # weighted toward tcp
    services = ['http', 'https', 'dns', 'ssh', 'smtp', 'ftp', 'http', 'https']
    flags = ['SF', 'SF', 'SF', 'S0', 'SF']  # mostly normal established connections

    for _ in range(count):
        protocol = random.choice(protocols)
        service = random.choice(services)
        flag = random.choice(flags)

        # normal traffic characteristics
        duration = round(random.uniform(0.01, 30.0), 4)
        src_bytes = random.randint(40, 15000)
        dst_bytes = random.randint(40, 50000)
        count_val = random.randint(1, 20)
        srv_count = random.randint(1, 15)

        rows.append({
            'duration': duration,
            'protocol': protocol,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'flag': flag,
            'service': service,
            'count': count_val,
            'srv_count': srv_count,
            'label': 'benign'
        })

    return rows


def generate_attack(count=100):
    """generate attack-like network traffic features"""
    rows = []

    attack_profiles = [
        # port scan - many short connections, small bytes, S0 flags
        lambda: {
            'duration': round(random.uniform(0.0, 0.5), 4),
            'protocol': 'tcp',
            'src_bytes': random.randint(40, 60),
            'dst_bytes': random.randint(0, 40),
            'flag': random.choice(['S0', 'S0', 'REJ', 'RSTO']),
            'service': random.choice(['other', 'http', 'ssh', 'ftp']),
            'count': random.randint(50, 500),
            'srv_count': random.randint(1, 5),
            'label': 'attack'
        },
        # dos - high connection count, repeated service
        lambda: {
            'duration': round(random.uniform(0.0, 2.0), 4),
            'protocol': 'tcp',
            'src_bytes': random.randint(100, 500),
            'dst_bytes': random.randint(0, 100),
            'flag': random.choice(['S0', 'SF', 'REJ']),
            'service': 'http',
            'count': random.randint(100, 1000),
            'srv_count': random.randint(50, 500),
            'label': 'attack'
        },
        # data exfiltration - long duration, high src_bytes
        lambda: {
            'duration': round(random.uniform(30.0, 300.0), 4),
            'protocol': random.choice(['tcp', 'udp']),
            'src_bytes': random.randint(50000, 500000),
            'dst_bytes': random.randint(100, 2000),
            'flag': 'SF',
            'service': random.choice(['other', 'ftp', 'http']),
            'count': random.randint(1, 10),
            'srv_count': random.randint(1, 5),
            'label': 'attack'
        },
        # brute force - many connections to same service
        lambda: {
            'duration': round(random.uniform(0.1, 5.0), 4),
            'protocol': 'tcp',
            'src_bytes': random.randint(100, 1000),
            'dst_bytes': random.randint(100, 500),
            'flag': random.choice(['SF', 'RSTO', 'S0']),
            'service': random.choice(['ssh', 'ftp', 'smtp']),
            'count': random.randint(30, 200),
            'srv_count': random.randint(20, 150),
            'label': 'attack'
        },
    ]

    for _ in range(count):
        profile = random.choice(attack_profiles)
        rows.append(profile())

    return rows


def write_dataset(rows, filepath):
    """write rows to csv"""
    fieldnames = ['duration', 'protocol', 'src_bytes', 'dst_bytes', 'flag', 'service', 'count', 'srv_count', 'label']

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[*] wrote {len(rows)} rows to {filepath}")


def main():
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

    benign = generate_benign(200)
    attack = generate_attack(100)

    write_dataset(benign, os.path.join(data_dir, 'sample_benign.csv'))
    write_dataset(attack, os.path.join(data_dir, 'sample_attack.csv'))

    print("[*] sample datasets generated")


if __name__ == '__main__':
    main()
