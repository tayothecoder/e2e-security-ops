#!/usr/bin/env python3
"""network forensics tool - analyses pcap files for suspicious activity and extracts artefacts"""

import sys
import os
import json
import hashlib
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("error: scapy is required. install with: pip install scapy")
    sys.exit(1)


def extract_http_requests(packets):
    """pull out http requests and responses from packet capture"""
    requests = []
    for pkt in packets:
        if pkt.haslayer(HTTPRequest):
            http = pkt[HTTPRequest]
            entry = {
                'timestamp': float(pkt.time),
                'src_ip': pkt[IP].src if pkt.haslayer(IP) else '?',
                'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else '?',
                'method': http.Method.decode(errors='replace') if http.Method else '?',
                'host': http.Host.decode(errors='replace') if http.Host else '?',
                'path': http.Path.decode(errors='replace') if http.Path else '/',
                'user_agent': http.User_Agent.decode(errors='replace') if hasattr(http, 'User_Agent') and http.User_Agent else 'unknown'
            }
            requests.append(entry)
    return requests


def extract_dns_queries(packets):
    """extract dns queries from the capture"""
    queries = []
    for pkt in packets:
        if pkt.haslayer(DNSQR) and pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0:  # query, not response
                qname = dns.qd.qname.decode(errors='replace').rstrip('.')
                queries.append({
                    'timestamp': float(pkt.time),
                    'src_ip': pkt[IP].src if pkt.haslayer(IP) else '?',
                    'query': qname,
                    'type': dns.qd.qtype
                })
    return queries


def analyse_traffic_patterns(packets):
    """look for suspicious patterns in the traffic"""
    findings = []
    connection_counts = Counter()
    port_scan_tracker = defaultdict(set)
    data_volumes = defaultdict(int)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        size = len(pkt)

        connection_counts[(src, dst)] += 1
        data_volumes[src] += size

        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
            port_scan_tracker[src].add((dst, dst_port))

    # check for port scanning - many different ports from one source
    for src, targets in port_scan_tracker.items():
        unique_ports = len(set(p for _, p in targets))
        if unique_ports > 20:
            findings.append({
                'type': 'port_scan',
                'severity': 'high',
                'source': src,
                'detail': f"{src} connected to {unique_ports} unique ports across {len(set(d for d, _ in targets))} hosts"
            })

    # check for high-volume connections (potential data exfiltration)
    for src, volume in data_volumes.items():
        if volume > 10_000_000:  # more than 10mb from a single source
            findings.append({
                'type': 'high_volume',
                'severity': 'medium',
                'source': src,
                'detail': f"{src} sent {volume / 1_000_000:.1f} MB of data"
            })

    # check for connections to unusual ports
    unusual_ports = {4444, 5555, 6666, 1234, 31337, 8888, 9999, 12345}
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            dport = pkt[TCP].dport
            if dport in unusual_ports:
                findings.append({
                    'type': 'suspicious_port',
                    'severity': 'medium',
                    'source': pkt[IP].src,
                    'detail': f"connection to suspicious port {dport} on {pkt[IP].dst}"
                })

    # deduplicate findings by type+source
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f['type'], f['source'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


def extract_transferred_files(packets, output_dir):
    """attempt to extract files from http traffic based on content-type headers"""
    extracted = []
    os.makedirs(output_dir, exist_ok=True)

    # reassemble tcp streams with payload data
    payload_data = b''
    file_count = 0

    for pkt in packets:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            payload = bytes(pkt[Raw].load)

            # look for http response headers indicating file content
            if b'Content-Type:' in payload and b'200 OK' in payload:
                # try to find the body after double newline
                header_end = payload.find(b'\r\n\r\n')
                if header_end > 0:
                    body = payload[header_end + 4:]
                    if len(body) > 100:  # skip tiny fragments
                        file_count += 1
                        filename = f"extracted_{file_count}.bin"
                        filepath = os.path.join(output_dir, filename)
                        with open(filepath, 'wb') as f:
                            f.write(body)

                        file_hash = hashlib.sha256(body).hexdigest()
                        extracted.append({
                            'filename': filename,
                            'size': len(body),
                            'sha256': file_hash,
                            'source_ip': pkt[IP].src if pkt.haslayer(IP) else '?',
                            'dest_ip': pkt[IP].dst if pkt.haslayer(IP) else '?'
                        })

    return extracted


def generate_report(pcap_path, packets, http_requests, dns_queries, findings, extracted_files, output_path):
    """write the analysis report"""
    report = {
        'metadata': {
            'pcap_file': pcap_path,
            'analysis_time': datetime.now().isoformat(),
            'total_packets': len(packets),
        },
        'summary': {
            'http_requests': len(http_requests),
            'dns_queries': len(dns_queries),
            'suspicious_findings': len(findings),
            'extracted_files': len(extracted_files)
        },
        'http_requests': http_requests[:50],  # cap at 50 for readability
        'dns_queries': dns_queries[:50],
        'findings': findings,
        'extracted_files': extracted_files
    }

    # write json report
    json_path = output_path + '.json'
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    # write markdown report
    md_path = output_path + '.md'
    with open(md_path, 'w') as f:
        f.write(f"# pcap analysis report\n\n")
        f.write(f"**file:** {pcap_path}\n\n")
        f.write(f"**analysed:** {datetime.now().isoformat()}\n\n")
        f.write(f"**total packets:** {len(packets)}\n\n")

        f.write("## summary\n\n")
        f.write(f"- http requests captured: {len(http_requests)}\n")
        f.write(f"- dns queries captured: {len(dns_queries)}\n")
        f.write(f"- suspicious findings: {len(findings)}\n")
        f.write(f"- files extracted: {len(extracted_files)}\n\n")

        if findings:
            f.write("## suspicious findings\n\n")
            for finding in findings:
                f.write(f"- **[{finding['severity'].upper()}]** {finding['type']}: {finding['detail']}\n")
            f.write("\n")

        if http_requests:
            f.write("## http requests (first 20)\n\n")
            f.write("| source | method | host | path |\n")
            f.write("|--------|--------|------|------|\n")
            for req in http_requests[:20]:
                f.write(f"| {req['src_ip']} | {req['method']} | {req['host']} | {req['path']} |\n")
            f.write("\n")

        if dns_queries:
            f.write("## dns queries (first 20)\n\n")
            f.write("| source | query |\n")
            f.write("|--------|-------|\n")
            for q in dns_queries[:20]:
                f.write(f"| {q['src_ip']} | {q['query']} |\n")
            f.write("\n")

        if extracted_files:
            f.write("## extracted files\n\n")
            for ef in extracted_files:
                f.write(f"- {ef['filename']} ({ef['size']} bytes) sha256: {ef['sha256'][:16]}...\n")

    print(f"[*] report written to {json_path} and {md_path}")
    return report


def main():
    if len(sys.argv) < 2:
        print("usage: pcap_analyser.py <capture.pcap> [output_dir]")
        print("")
        print("analyses a pcap file for http requests, dns queries,")
        print("suspicious patterns, and extracts transferred files.")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else './pcap_analysis'
    os.makedirs(output_dir, exist_ok=True)

    if not os.path.exists(pcap_path):
        print(f"error: {pcap_path} not found")
        sys.exit(1)

    print(f"[*] loading {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"[*] loaded {len(packets)} packets")

    print("[*] extracting http requests")
    http_requests = extract_http_requests(packets)

    print("[*] extracting dns queries")
    dns_queries = extract_dns_queries(packets)

    print("[*] analysing traffic patterns")
    findings = analyse_traffic_patterns(packets)

    print("[*] extracting transferred files")
    extracted_dir = os.path.join(output_dir, 'extracted_files')
    extracted_files = extract_transferred_files(packets, extracted_dir)

    print("[*] generating report")
    report_path = os.path.join(output_dir, 'pcap_report')
    generate_report(pcap_path, packets, http_requests, dns_queries, findings, extracted_files, report_path)

    print(f"\n[*] analysis complete")
    if findings:
        print(f"    {len(findings)} suspicious findings detected")


if __name__ == '__main__':
    main()
