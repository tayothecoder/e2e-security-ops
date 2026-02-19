# defence & detection layer

this layer provides intrusion detection, honeypot deception, centralised logging,
and network hardening for the target web application.

## components

### suricata ids (`suricata/`)

network-based intrusion detection system watching traffic to/from the web app.
custom rules cover sqli, xss, directory traversal, web shells, brute force,
recon tools, and suspicious downloads.

```bash
cd suricata/
sudo bash setup.sh
# test that rules fire:
bash test_rules.sh http://TARGET_IP
```

eve.json output lands in `/var/log/suricata/eve.json` and gets picked up by filebeat.

### cowrie honeypot (`cowrie/`)

medium-interaction ssh/telnet honeypot. exposes fake credentials on port 2222/2223
to attract and log attacker activity.

```bash
# option a: native install
cd cowrie/
bash setup.sh

# option b: docker
docker build -t cowrie-hp cowrie/
docker run -d -p 2222:2222 -p 2223:2323 cowrie-hp
```

logs go to `/opt/cowrie/var/log/cowrie/cowrie.json`.

### logging & monitoring (`logging/`)

elk stack (elasticsearch + logstash + kibana) with filebeat shipping logs from
suricata and cowrie. logstash parses the json and normalises fields.

```bash
cd logging/
docker compose up -d
# import the kibana dashboard after kibana is up (~60s):
curl -X POST "localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" --form file=@dashboard.ndjson
```

kibana is on port 5601. the dashboard gives an overview of alerts by severity,
top source ips, attack categories, and honeypot activity.

### firewall (`firewall/`)

iptables rules that lock down the host: only allow http/https to the app,
ssh on a non-standard port (2200), rate-limit connections, and log drops.

```bash
cd firewall/
sudo bash iptables-rules.sh
```

`network-diagram.txt` has an ascii diagram of the overall architecture.

## prerequisites

- ubuntu 22.04+
- docker & docker compose
- python3 + pip (for cowrie)
- root/sudo access for suricata and iptables

## order of deployment

1. firewall rules (lock things down first)
2. suricata (start watching traffic)
3. elk stack (have logging ready)
4. cowrie (deploy the honeypot)
5. import kibana dashboard
6. run test_rules.sh to verify detection
