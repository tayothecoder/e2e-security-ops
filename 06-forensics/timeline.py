#!/usr/bin/env python3
"""timeline builder - merges multiple log sources into a unified chronological timeline"""

import json
import re
import sys
import os
from datetime import datetime
from dateutil import parser as dateparser


def parse_eve_json(filepath):
    """parse suricata eve.json and extract alert events"""
    events = []
    if not os.path.exists(filepath):
        print(f"  [skip] {filepath} not found")
        return events

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            timestamp = record.get('timestamp', '')
            event_type = record.get('event_type', 'unknown')

            # build a useful description based on event type
            if event_type == 'alert':
                alert = record.get('alert', {})
                desc = f"suricata alert: {alert.get('signature', 'unknown')} " \
                       f"[severity {alert.get('severity', '?')}]"
                src = record.get('src_ip', '?')
                dst = record.get('dest_ip', '?')
                desc += f" | {src} -> {dst}"
            elif event_type == 'dns':
                dns = record.get('dns', {})
                desc = f"dns query: {dns.get('rrname', '?')} ({dns.get('rrtype', '?')})"
            elif event_type == 'http':
                http = record.get('http', {})
                desc = f"http: {http.get('http_method', '?')} {http.get('hostname', '')}{http.get('url', '/')}"
            else:
                desc = f"suricata {event_type}"

            try:
                ts = dateparser.parse(timestamp)
            except (ValueError, TypeError):
                continue

            events.append({
                'timestamp': ts.isoformat(),
                'source': 'suricata',
                'type': event_type,
                'description': desc,
                'raw': record
            })

    print(f"  [+] parsed {len(events)} events from eve.json")
    return events


def parse_access_log(filepath):
    """parse apache/nginx combined log format"""
    events = []
    if not os.path.exists(filepath):
        print(f"  [skip] {filepath} not found")
        return events

    # combined log format pattern
    pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) (?P<size>\S+)'
    )

    with open(filepath, 'r') as f:
        for line in f:
            m = pattern.match(line.strip())
            if not m:
                continue

            try:
                ts = datetime.strptime(m.group('time'), '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                # try without timezone
                try:
                    time_part = m.group('time').split(' ')[0]
                    ts = datetime.strptime(time_part, '%d/%b/%Y:%H:%M:%S')
                except ValueError:
                    continue

            status = m.group('status')
            desc = f"web: {m.group('method')} {m.group('url')} [{status}] from {m.group('ip')}"

            events.append({
                'timestamp': ts.isoformat(),
                'source': 'webserver',
                'type': 'http_access',
                'description': desc,
                'status_code': int(status),
                'client_ip': m.group('ip')
            })

    print(f"  [+] parsed {len(events)} entries from access log")
    return events


def parse_auth_log(filepath):
    """parse linux auth.log for authentication events"""
    events = []
    if not os.path.exists(filepath):
        print(f"  [skip] {filepath} not found")
        return events

    # common auth log patterns
    patterns = {
        'login_success': re.compile(r'Accepted (\w+) for (\S+) from (\S+)'),
        'login_failure': re.compile(r'Failed (\w+) for (\S+) from (\S+)'),
        'sudo': re.compile(r'(\S+) : .* COMMAND=(.*)'),
        'session_open': re.compile(r'session opened for user (\S+)'),
        'session_close': re.compile(r'session closed for user (\S+)'),
    }

    # auth log timestamp format (no year, need to assume current year)
    current_year = datetime.now().year

    try:
        f = open(filepath, 'r')
    except PermissionError:
        print(f"  [skip] {filepath} permission denied")
        return events

    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # extract timestamp from start of line (e.g. "Feb 14 10:23:45")
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue

            time_str = f"{parts[0]} {parts[1]} {parts[2]}"
            try:
                ts = datetime.strptime(f"{current_year} {time_str}", '%Y %b %d %H:%M:%S')
            except ValueError:
                continue

            message = parts[3] if len(parts) > 3 else ''

            # match against known patterns
            for event_name, pattern in patterns.items():
                m = pattern.search(message)
                if m:
                    if event_name == 'login_success':
                        desc = f"auth: successful {m.group(1)} login for {m.group(2)} from {m.group(3)}"
                    elif event_name == 'login_failure':
                        desc = f"auth: failed {m.group(1)} login for {m.group(2)} from {m.group(3)}"
                    elif event_name == 'sudo':
                        desc = f"auth: sudo by {m.group(1)} - {m.group(2)}"
                    elif event_name == 'session_open':
                        desc = f"auth: session opened for {m.group(1)}"
                    elif event_name == 'session_close':
                        desc = f"auth: session closed for {m.group(1)}"
                    else:
                        desc = f"auth: {event_name}"

                    events.append({
                        'timestamp': ts.isoformat(),
                        'source': 'auth',
                        'type': event_name,
                        'description': desc
                    })
                    break

    print(f"  [+] parsed {len(events)} entries from auth log")
    return events


def build_timeline(events):
    """sort all events chronologically"""
    return sorted(events, key=lambda e: e['timestamp'])


def write_json(timeline, output_path):
    """write timeline as json"""
    # strip raw suricata data for the json output to keep it manageable
    clean = []
    for event in timeline:
        entry = {k: v for k, v in event.items() if k != 'raw'}
        clean.append(entry)

    with open(output_path, 'w') as f:
        json.dump(clean, f, indent=2, default=str)
    print(f"[*] wrote {output_path} ({len(clean)} events)")


def write_markdown(timeline, output_path):
    """write a human-readable markdown timeline"""
    with open(output_path, 'w') as f:
        f.write("# incident timeline\n\n")
        f.write(f"generated: {datetime.now().isoformat()}\n\n")
        f.write(f"total events: {len(timeline)}\n\n")
        f.write("| time | source | type | description |\n")
        f.write("|------|--------|------|-------------|\n")

        for event in timeline:
            ts = event['timestamp']
            src = event.get('source', '?')
            etype = event.get('type', '?')
            desc = event.get('description', '').replace('|', '\\|')
            f.write(f"| {ts} | {src} | {etype} | {desc} |\n")

    print(f"[*] wrote {output_path}")


def main():
    import argparse
    ap = argparse.ArgumentParser(description='build unified timeline from multiple log sources')
    ap.add_argument('output_dir', nargs='?', default=None,
                    help='output directory (positional, legacy)')
    ap.add_argument('--suricata', default='/var/log/suricata/eve.json',
                    help='path to suricata eve.json')
    ap.add_argument('--access-log', default='/var/log/apache2/access.log',
                    help='path to apache access log')
    ap.add_argument('--auth-log', default='/var/log/auth.log',
                    help='path to auth log')
    ap.add_argument('--output', default=None,
                    help='output file path for markdown report')
    args = ap.parse_args()

    # figure out where to write
    if args.output:
        output_dir = os.path.dirname(args.output) or '.'
        output_md = args.output
    elif args.output_dir:
        output_dir = args.output_dir
        output_md = os.path.join(output_dir, 'timeline.md')
    else:
        print("error: provide --output <file> or a positional output directory")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    eve_path = args.suricata
    access_path = args.access_log
    auth_path = args.auth_log

    print("[*] building incident timeline")
    print(f"    eve.json:   {eve_path}")
    print(f"    access.log: {access_path}")
    print(f"    auth.log:   {auth_path}")
    print("")

    all_events = []
    all_events.extend(parse_eve_json(eve_path))
    all_events.extend(parse_access_log(access_path))
    all_events.extend(parse_auth_log(auth_path))

    if not all_events:
        print("[!] no events found in any log source")
        sys.exit(0)

    timeline = build_timeline(all_events)
    print(f"\n[*] total events in timeline: {len(timeline)}")

    write_json(timeline, os.path.join(output_dir, 'timeline.json'))
    write_markdown(timeline, output_md)

    print("[*] done")


if __name__ == '__main__':
    main()
