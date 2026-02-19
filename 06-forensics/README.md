# forensics toolkit

tools and templates for digital forensic investigation as part of the e2e security operations project.

## tools

### capture.sh
evidence collection script that captures volatile system data (processes, network connections, arp cache), copies relevant logs, generates sha256 hashes of all evidence, and packages everything into a timestamped tar.gz archive.

```bash
chmod +x capture.sh
sudo ./capture.sh CASE_2024_001
```

### timeline.py
builds a unified chronological timeline from multiple log sources (suricata eve.json, web server access logs, auth logs). outputs both json and human-readable markdown.

```bash
python3 timeline.py ./output /var/log/suricata/eve.json /var/log/apache2/access.log /var/log/auth.log
```

### pcap_analyser.py
network forensics tool that reads pcap files and extracts http requests, dns queries, identifies suspicious traffic patterns (port scanning, data exfiltration), and recovers transferred files.

```bash
python3 pcap_analyser.py capture.pcap ./analysis_output
```

### ioc_extractor.py
extracts indicators of compromise (ips, domains, urls, file hashes, emails) from log files. outputs in stix 2.1 format and a flat json for quick reference.

```bash
python3 ioc_extractor.py ./output /var/log/suricata/eve.json /var/log/auth.log
```

## templates

- **report_template.md** - expert testimony style forensic report template with sections for executive summary, scope, methodology, findings, timeline, conclusions, and recommendations
- **chain_of_custody.md** - evidence tracking template for maintaining chain of custody records

## setup

```bash
pip install -r requirements.txt
```

## dependencies

- python 3.8+
- scapy (for pcap analysis)
- python-dateutil (for timestamp parsing)
- standard linux tools (ps, ss, netstat, sha256sum) for capture.sh
