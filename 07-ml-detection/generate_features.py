#!/usr/bin/env python3
"""extract flow-level features from pcap files for ml classification"""

import sys
import os
import csv
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    print("error: scapy is required. install with: pip install scapy")
    sys.exit(1)


def extract_flows(packets):
    """group packets into bidirectional flows based on 5-tuple"""
    flows = defaultdict(lambda: {
        'packets': [],
        'start_time': None,
        'end_time': None,
        'src_bytes': 0,
        'dst_bytes': 0,
        'src_packets': 0,
        'dst_packets': 0,
        'protocol': 'other',
        'flags': set(),
        'service': 'other'
    })

    # common port to service mapping
    port_services = {
        80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp',
        25: 'smtp', 53: 'dns', 110: 'pop3', 143: 'imap',
        3306: 'mysql', 5432: 'postgres', 8080: 'http_alt'
    }

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = 'other'
        sport = 0
        dport = 0

        if pkt.haslayer(TCP):
            proto = 'tcp'
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
        elif pkt.haslayer(UDP):
            proto = 'udp'
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            flags = 0
        else:
            flags = 0

        # create a canonical flow key (sorted so both directions map to same flow)
        endpoints = tuple(sorted([(src, sport), (dst, dport)]))
        flow_key = (endpoints[0][0], endpoints[0][1], endpoints[1][0], endpoints[1][1], proto)

        flow = flows[flow_key]
        ts = float(pkt.time)

        if flow['start_time'] is None or ts < flow['start_time']:
            flow['start_time'] = ts
        if flow['end_time'] is None or ts > flow['end_time']:
            flow['end_time'] = ts

        flow['protocol'] = proto
        flow['packets'].append(pkt)

        # determine direction (original src -> dst or reply)
        if ip.src == flow_key[0]:
            flow['src_bytes'] += len(pkt)
            flow['src_packets'] += 1
        else:
            flow['dst_bytes'] += len(pkt)
            flow['dst_packets'] += 1

        # capture tcp flags
        if proto == 'tcp' and flags:
            flag_str = str(flags)
            for f in flag_str:
                flow['flags'].add(f)

        # determine service from destination port
        service = port_services.get(dport, port_services.get(sport, 'other'))
        flow['service'] = service

    return flows


def compute_features(flows):
    """compute flow-level features suitable for ml classification"""
    feature_rows = []

    # track connection counts for count-based features
    src_counts = defaultdict(int)
    srv_counts = defaultdict(int)

    # first pass: count connections per source and service
    for flow_key, flow in flows.items():
        src_ip = flow_key[0]
        service = flow['service']
        src_counts[src_ip] += 1
        srv_counts[service] += 1

    # second pass: compute features for each flow
    for flow_key, flow in flows.items():
        duration = 0.0
        if flow['start_time'] and flow['end_time']:
            duration = flow['end_time'] - flow['start_time']

        # map tcp flags to a simple categorical
        flags = flow['flags']
        if 'S' in flags and 'A' not in flags:
            flag_cat = 'S0'  # syn only, no reply
        elif 'S' in flags and 'A' in flags and 'F' in flags:
            flag_cat = 'SF'  # normal established and finished
        elif 'S' in flags and 'R' in flags:
            flag_cat = 'REJ'  # rejected
        elif 'R' in flags:
            flag_cat = 'RSTO'  # reset
        elif flags:
            flag_cat = 'OTH'
        else:
            flag_cat = 'SF'  # default for udp etc

        src_ip = flow_key[0]
        service = flow['service']

        row = {
            'duration': round(duration, 4),
            'protocol': flow['protocol'],
            'src_bytes': flow['src_bytes'],
            'dst_bytes': flow['dst_bytes'],
            'flag': flag_cat,
            'service': service,
            'count': src_counts[src_ip],
            'srv_count': srv_counts[service]
        }
        feature_rows.append(row)

    return feature_rows


def write_csv(features, output_path):
    """write features to csv file"""
    if not features:
        print("[!] no features to write")
        return

    fieldnames = ['duration', 'protocol', 'src_bytes', 'dst_bytes', 'flag', 'service', 'count', 'srv_count']

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(features)

    print(f"[*] wrote {len(features)} flow features to {output_path}")


def main():
    if len(sys.argv) < 2:
        print("usage: generate_features.py <capture.pcap> [output.csv]")
        print("")
        print("extracts flow-level features from a pcap file,")
        print("outputs csv compatible with the trained ml model.")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else 'features.csv'

    if not os.path.exists(pcap_path):
        print(f"error: {pcap_path} not found")
        sys.exit(1)

    print(f"[*] reading {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"[*] loaded {len(packets)} packets")

    print("[*] extracting flows")
    flows = extract_flows(packets)
    print(f"[*] identified {len(flows)} flows")

    print("[*] computing features")
    features = compute_features(flows)

    write_csv(features, output_path)
    print("[*] done")


if __name__ == '__main__':
    main()
