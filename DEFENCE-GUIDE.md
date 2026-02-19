# E2E Security Operations — Defence Prep Guide

This is your cheat sheet for defending this project in front of lecturers, interviewers, or anyone who asks. Read it until you can explain everything without looking at it.


## 1. What is this project?

A full-cycle cybersecurity lab that simulates a real-world attack scenario from start to finish. You built a deliberately vulnerable web application, deployed defensive security controls around it, attacked it with custom tools, detected the attacks using both signature-based and ML-based methods, then forensically investigated the breach.

**If asked "why?":** Real SOCs don't operate in silos. Red team, blue team, and DFIR need to understand each other. This project demonstrates that full spectrum.


## 2. The Target App (TravelBird)

**Stack:** Python Flask, SQLite, Jinja2 templates

**Why Flask + SQLite?** Lightweight, easy to deploy, and SQLite lets you demonstrate SQLi without needing a full MySQL/Postgres setup. In a real scenario these vulns appear in any stack — the principles are language-agnostic.

### The 7 vulnerabilities and WHY they exist:

**SQL Injection (login + search)**
- The code uses Python string formatting directly in SQL queries: `"SELECT * FROM users WHERE username = '%s'" % (user_input)`
- This means user input goes straight into the query with no sanitisation
- The fix: parameterised queries using `?` placeholders — the database driver handles escaping
- If asked: "SQLi has been around since the late 90s and it's still in the OWASP Top 10 because developers keep using string concatenation instead of prepared statements"

**Reflected XSS (search page)**
- The search query gets rendered back to the page using Jinja2's `|safe` filter, which disables HTML escaping
- So if you search for `<script>alert(1)</script>`, it executes in the browser
- The fix: remove `|safe`, let Jinja2 auto-escape (which it does by default)
- If asked: "Reflected XSS requires social engineering — the attacker needs to trick the victim into clicking a crafted URL. Stored XSS is more dangerous because it hits every visitor."

**Stored XSS (reviews)**
- Same `|safe` issue, but the payload gets saved to the database via the review form
- Every user who views that review page gets hit
- The fix: sanitise input server-side (strip HTML tags) AND remove `|safe` on output

**Unrestricted File Upload**
- No validation on file type, extension, or content
- You can upload a Python script, PHP shell, anything
- The fix: whitelist allowed extensions, validate MIME type, rename uploaded files, store outside webroot
- If asked: "In a real attack, uploading a web shell gives you remote code execution on the server — game over"

**Directory Traversal**
- The `/download` endpoint takes a `file` parameter and opens it directly: `open(os.path.join('uploads', filename))`
- But there's no check for `../`, so `?file=../../../etc/passwd` reads system files
- The fix: use `os.path.realpath()` and verify the resolved path starts with your uploads directory

**IDOR (Insecure Direct Object Reference)**
- `/profile/1` shows user 1's data, `/profile/2` shows user 2's data
- There's no check that the logged-in user owns that profile
- The fix: compare `session['user_id']` with the requested `user_id`, or only allow users to see their own profile
- If asked: "IDOR is an access control issue, not an injection. It's about broken authorisation — the app authenticates you but doesn't authorise what you can access."

**Weak Authentication**
- Plaintext passwords in the database (no hashing)
- Session tokens generated with MD5 of username + timestamp (predictable)
- No rate limiting on login attempts
- The fix: bcrypt/argon2 for passwords, cryptographically random session tokens, account lockout after N failures


## 3. The Defence Layer

### Suricata IDS

**What it is:** Open-source network intrusion detection system. It inspects network packets in real-time and matches them against rules.

**How it works:** Suricata sits on a network interface (or reads PCAPs) and compares traffic against signatures. When a match occurs, it logs an alert to `eve.json`.

**Our 22 custom rules cover:**
- SQLi patterns: UNION SELECT, OR 1=1, single quote injection, sqlmap user-agent
- XSS payloads: script tags, event handlers (onerror, onload), javascript: URIs
- Directory traversal: `../` sequences in HTTP requests
- Web shell uploads: .php/.py/.jsp in POST requests to upload endpoints
- Brute force: threshold rule — more than 5 failed logins in 60 seconds from same IP
- Recon tools: Nmap, Nikto, Dirb, sqlmap user-agent strings

**If asked "why Suricata over Snort?":** Suricata is multi-threaded (better performance on modern hardware), supports EVE JSON logging natively (easier to parse), and has built-in protocol detection. Snort is single-threaded. Both use compatible rule syntax.

**If asked about false positives:** Signature-based detection always has a false positive/negative trade-off. A rule matching `OR 1=1` could trigger on legitimate content. That's why you tune thresholds and combine with anomaly-based detection (the ML model).

### Cowrie Honeypot

**What it is:** A medium-interaction SSH/Telnet honeypot that logs attacker commands and credentials.

**Purpose:** Deception. Real services run on non-standard ports. Cowrie listens on standard SSH (22) via iptables NAT redirect. Attackers think they've broken in — meanwhile we're recording everything.

**What it captures:** Attempted usernames/passwords, commands executed, files downloaded, session recordings.

**If asked:** "Honeypots provide early warning and threat intelligence. If someone's connecting to a service that no legitimate user should be accessing, you know you have an intruder. It also wastes attacker time."

### ELK Stack

**What it is:** Elasticsearch (stores/indexes logs), Logstash (parses and routes logs), Kibana (visualisation dashboard).

**Our setup:** Filebeat ships Suricata eve.json and Cowrie logs to Logstash, which parses JSON, adds GeoIP data, tags by severity, then stores in Elasticsearch. Kibana dashboard shows alerts over time, top source IPs, attack categories, severity distribution.

**If asked "why ELK?":** Industry standard SIEM stack. Splunk costs money. ELK is open-source and the skills are directly transferable to enterprise SOCs.

### Firewall (iptables)

**Policy:** Default DROP on INPUT and FORWARD. Only allow what's explicitly needed.
- Port 80/443 for the web app
- Port 2200 for SSH (non-standard)
- Rate limiting: max 25 new connections/second per IP
- All dropped packets are logged
- NAT redirect from port 22 to Cowrie on 2222

**If asked:** "Defence in depth. The firewall is your first layer. Even if an attacker finds a vulnerability, the firewall limits what they can reach. Combined with IDS and honeypot, you have detection at multiple points."


## 4. The Attack Toolkit

### Why custom scripts instead of just using existing tools?

"Understanding how attacks work at the code level makes you a better defender. Anyone can run sqlmap. Writing your own injection script means you understand the HTTP requests, the SQL syntax, the response parsing. That's the difference between a script kiddy and a security professional."

### Key attacks to explain:

**UNION-based SQLi extraction:**
The search query has 7 columns (packages table). We inject:
`' UNION SELECT 1,username,password,email,5,6,7 FROM users--`
This appends the users table data to the search results. The app renders column 2 (name) and column 3 (destination), so we put username in position 2 and password in position 3.

**If asked "how did you know 7 columns?":** Trial and error with ORDER BY. `ORDER BY 1` works, `ORDER BY 7` works, `ORDER BY 8` errors. So 7 columns.

**Brute force approach:**
Threaded dictionary attack. We send POST requests to /login and check if the response is a 302 redirect (success) or 200 with "Invalid" flash message (failure). 5 threads, ~180 requests/second.

**If asked about countermeasures:** Account lockout after N failed attempts, CAPTCHA, progressive delays, IP-based rate limiting. Our Suricata rule detects this via threshold (5 attempts in 60 seconds).


## 5. Forensic Investigation

### Methodology: NIST SP 800-86 / ISO 27037

**Four phases:**
1. **Collection** — capture volatile evidence first (RAM > network connections > processes > disk). Our `capture.sh` follows order of volatility.
2. **Examination** — parse logs, extract artifacts. Our `timeline.py` merges multiple log sources.
3. **Analysis** — correlate events, build the attack narrative. The timeline shows exactly when each attack phase occurred.
4. **Reporting** — document findings in expert testimony style. Professional, objective, evidence-based.

**Chain of custody:** Every piece of evidence is SHA256 hashed at collection time. This proves the evidence hasn't been tampered with. If it goes to court, you need to prove integrity.

**If asked about admissibility:** Digital evidence must be: relevant, authentic (hash verified), complete (not cherry-picked), and collected without altering the original. That's why we use write blockers for disk imaging and hash everything.

### Tools:
- **Autopsy** — disk forensics, file carving, timeline analysis
- **Volatility** — RAM analysis (process list, network connections, loaded DLLs)
- **Wireshark** — packet analysis, protocol dissection
- **Scapy** — programmatic packet analysis (our pcap_analyser.py)


## 6. ML-Based Detection

### Why ML for IDS?

Signature-based detection (Suricata) only catches known attack patterns. If an attacker modifies their payload slightly, signatures miss it. ML learns the PATTERNS of malicious traffic, so it can catch zero-day variants.

### Our approach:

**Algorithms:** Random Forest and Gradient Boosting (ensemble methods)

**Why these?**
- Random Forest: robust, handles mixed feature types, resistant to overfitting, fast to train
- Gradient Boosting: often more accurate, builds trees sequentially to correct errors
- Both are interpretable compared to deep learning — you can explain which features matter most

**Features extracted from network flows:**
duration, protocol, src_bytes, dst_bytes, flag, service, count, srv_count

**Results:** RF achieved ~100% F1 on test set, GB ~98%

**If asked "isn't 100% suspicious?":** Yes — on sample/lab data. In production with real network traffic, you'd see more noise. The sample data is clean and well-separated. Real-world deployment would need continuous retraining and would have lower accuracy. This demonstrates the methodology, not production-ready performance.

**If asked "why not deep learning?":** For tabular network flow data, tree-based methods consistently outperform neural networks. Deep learning shines on images, text, sequences. For IDS with structured features, Random Forest is the standard choice in research (see UNSW-NB15, CIC-IDS benchmarks).

### ML vs Signatures comparison:

**Signatures win at:** Known attacks with exact patterns (specific SQLi strings, known malware hashes)
**ML wins at:** Novel variants, polymorphic attacks, anomalous behaviour that doesn't match any known signature
**Best approach:** Both together. Signatures for known threats, ML for the unknown. That's what modern SOCs do.


## 7. Questions They Might Ask

**"How does this relate to real-world SOC operations?"**
A real SOC uses the same toolchain — SIEM (our ELK), IDS/IPS (our Suricata), honeypots (our Cowrie), threat hunting (our ML model). We've compressed the full SOC workflow into a reproducible lab. The only difference is scale and data volume.

**"What would you do differently in production?"**
- PostgreSQL instead of SQLite
- TLS everywhere
- Proper WSGI server (gunicorn) instead of Flask dev server
- Suricata in IPS mode (inline blocking, not just detection)
- Distributed ELK cluster with proper authentication
- Model retraining pipeline with fresh traffic data
- Automated alerting (PagerDuty/email on critical alerts)

**"What frameworks does this align to?"**
- MITRE ATT&CK — each attack maps to specific techniques (T1190 Exploit Public-Facing Application, T1110 Brute Force, etc.)
- NIST CSF — Identify (asset modelling), Protect (firewall, auth), Detect (Suricata, ML), Respond (forensics), Recover
- OWASP Top 10 — our vulns cover Injection, XSS, Broken Access Control, Security Misconfiguration
- Cyber Kill Chain — Recon → Weaponisation → Delivery → Exploitation → Installation → C2 → Actions on Objective

**"What's the most critical vulnerability and why?"**
SQL injection on the login. It gives you unauthenticated access to any account including admin, and with UNION extraction you can dump the entire database. Combined with plaintext passwords, one SQLi = total compromise.

**"How would you prioritise fixing these vulnerabilities?"**
1. SQLi (critical — full database access)
2. File upload (high — remote code execution)
3. Directory traversal (high — arbitrary file read)
4. Stored XSS (high — affects all users)
5. Weak auth (medium — enables brute force)
6. IDOR (medium — data exposure)
7. Reflected XSS (medium — requires social engineering)

This follows CVSS-style severity ranking based on impact and exploitability.


## 8. Key Terms You Must Know

- **UNION SELECT** — SQL operator that appends results from a second query to the first
- **Parameterised queries** — SQL queries where user input is passed as parameters, not concatenated into the string
- **EVE JSON** — Suricata's unified JSON log format for all events
- **Order of volatility** — evidence collection priority: registers > cache > RAM > disk > network > backups
- **Chain of custody** — documented record of who handled evidence, when, and what they did
- **F1 score** — harmonic mean of precision and recall, good metric for imbalanced datasets
- **False positive rate** — legitimate traffic incorrectly flagged as malicious
- **Defence in depth** — multiple layers of security so no single failure compromises the system
- **STIX** — Structured Threat Information Expression, standard format for sharing threat intelligence
- **Ensemble methods** — ML techniques that combine multiple models (Random Forest = many decision trees)
