#!/usr/bin/env python3
"""extract indicators of compromise from log files and output in stix-like json format"""

import re
import sys
import os
import json
import hashlib
from datetime import datetime, timezone
from collections import defaultdict


# patterns for extracting different ioc types
PATTERNS = {
    'ipv4': re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'),
    'domain': re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk|ml|ga|cf)\b', re.IGNORECASE),
    'url': re.compile(r'https?://[^\s<>"\']+'),
    'md5': re.compile(r'\b[a-f0-9]{32}\b'),
    'sha1': re.compile(r'\b[a-f0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-f0-9]{64}\b'),
    'email': re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
}

# private/internal ip ranges to filter out
PRIVATE_RANGES = [
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^127\.'),
    re.compile(r'^0\.'),
]


def is_private_ip(ip):
    """check if an ip is in a private range"""
    return any(p.match(ip) for p in PRIVATE_RANGES)


def extract_iocs(text, include_private=False):
    """extract all ioc types from a block of text"""
    iocs = defaultdict(set)

    for ioc_type, pattern in PATTERNS.items():
        matches = pattern.findall(text)
        for match in matches:
            # filter private ips unless explicitly included
            if ioc_type == 'ipv4' and not include_private and is_private_ip(match):
                continue
            # skip common false positive domains
            if ioc_type == 'domain' and match.lower() in ('localhost.com', 'example.com'):
                continue
            iocs[ioc_type].add(match)

    return iocs


def process_file(filepath, include_private=False):
    """read a file and extract iocs from it"""
    if not os.path.exists(filepath):
        print(f"  [skip] {filepath} not found")
        return defaultdict(set)

    print(f"  [+] processing {filepath}")
    with open(filepath, 'r', errors='replace') as f:
        content = f.read()

    return extract_iocs(content, include_private)


def merge_iocs(ioc_sets):
    """merge multiple ioc dictionaries together"""
    merged = defaultdict(set)
    for ioc_dict in ioc_sets:
        for ioc_type, values in ioc_dict.items():
            merged[ioc_type].update(values)
    return merged


def to_stix_bundle(iocs):
    """convert iocs to a simplified stix 2.1 bundle format"""
    objects = []
    bundle_id = f"bundle--{hashlib.md5(datetime.now().isoformat().encode()).hexdigest()}"

    # mapping of our types to stix indicator patterns
    type_mapping = {
        'ipv4': ('ipv4-addr', lambda v: f"[ipv4-addr:value = '{v}']"),
        'domain': ('domain-name', lambda v: f"[domain-name:value = '{v}']"),
        'url': ('url', lambda v: f"[url:value = '{v}']"),
        'md5': ('file', lambda v: f"[file:hashes.'MD5' = '{v}']"),
        'sha1': ('file', lambda v: f"[file:hashes.'SHA-1' = '{v}']"),
        'sha256': ('file', lambda v: f"[file:hashes.'SHA-256' = '{v}']"),
        'email': ('email-addr', lambda v: f"[email-addr:value = '{v}']"),
    }

    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')

    for ioc_type, values in iocs.items():
        if ioc_type not in type_mapping:
            continue

        stix_type, pattern_fn = type_mapping[ioc_type]

        for value in sorted(values):
            indicator_id = f"indicator--{hashlib.md5(f'{ioc_type}:{value}'.encode()).hexdigest()}"
            indicator = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': indicator_id,
                'created': now,
                'modified': now,
                'name': f"{ioc_type}: {value}",
                'description': f"extracted {ioc_type} indicator",
                'indicator_types': ['malicious-activity'],
                'pattern': pattern_fn(value),
                'pattern_type': 'stix',
                'valid_from': now,
                'labels': [ioc_type, stix_type]
            }
            objects.append(indicator)

    bundle = {
        'type': 'bundle',
        'id': bundle_id,
        'objects': objects
    }

    return bundle


def print_summary(iocs):
    """print a summary of extracted iocs"""
    print("\n[*] ioc summary:")
    total = 0
    for ioc_type in sorted(iocs.keys()):
        count = len(iocs[ioc_type])
        total += count
        print(f"    {ioc_type}: {count}")
    print(f"    total unique indicators: {total}")


def main():
    if len(sys.argv) < 3:
        print("usage: ioc_extractor.py <output_dir> <logfile1> [logfile2] ...")
        print("")
        print("extracts indicators of compromise from log files")
        print("and outputs them in stix 2.1 format.")
        print("")
        print("options:")
        print("  --include-private    include private/internal ip addresses")
        sys.exit(1)

    output_dir = sys.argv[1]
    include_private = '--include-private' in sys.argv
    log_files = [f for f in sys.argv[2:] if not f.startswith('--')]

    os.makedirs(output_dir, exist_ok=True)

    print("[*] extracting indicators of compromise")
    all_iocs = []
    for filepath in log_files:
        iocs = process_file(filepath, include_private)
        all_iocs.append(iocs)

    merged = merge_iocs(all_iocs)

    if not any(merged.values()):
        print("[!] no indicators found")
        sys.exit(0)

    print_summary(merged)

    # write stix bundle
    stix_path = os.path.join(output_dir, 'iocs_stix.json')
    bundle = to_stix_bundle(merged)
    with open(stix_path, 'w') as f:
        json.dump(bundle, f, indent=2)
    print(f"\n[*] stix bundle written to {stix_path} ({len(bundle['objects'])} indicators)")

    # also write a simple flat json for quick reference
    flat_path = os.path.join(output_dir, 'iocs_flat.json')
    flat = {k: sorted(list(v)) for k, v in merged.items()}
    with open(flat_path, 'w') as f:
        json.dump(flat, f, indent=2)
    print(f"[*] flat ioc list written to {flat_path}")


if __name__ == '__main__':
    main()
