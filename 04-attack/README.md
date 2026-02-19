# attack toolkit

penetration testing tools for the TravelBird vulnerable flask application. built for the e2e-security-ops portfolio project. **educational use only.**

## setup

```bash
pip install -r requirements.txt
```

make sure the target app is running (default: `http://localhost:5000`).

## tools

| script | description |
|--------|-------------|
| `recon.py` | port scanning, header analysis, tech fingerprinting, directory bruteforce |
| `sqli_manual.py` | manual sql injection - auth bypass, union extraction, db enumeration |
| `sqli_auto.sh` | sqlmap wrapper for automated sqli testing |
| `xss_scanner.py` | reflected, stored, and dom-based xss testing |
| `file_upload.py` | file upload exploitation, web shell upload attempts |
| `brute_force.py` | threaded credential brute forcing with dictionary attack |
| `idor_test.py` | insecure direct object reference testing, profile enumeration |
| `full_pentest.py` | runs all modules in sequence, generates combined report |
| `generate_report.py` | converts json results into a markdown pentest report |

## usage

### run everything
```bash
python3 full_pentest.py -t http://localhost:5000
```

### run individual tools
```bash
python3 recon.py -t http://localhost:5000
python3 sqli_manual.py -t http://localhost:5000
python3 xss_scanner.py -t http://localhost:5000
python3 file_upload.py -t http://localhost:5000
python3 brute_force.py -t http://localhost:5000 -u admin
python3 idor_test.py -t http://localhost:5000 --max-id 30
```

### sqlmap automation
```bash
chmod +x sqli_auto.sh
./sqli_auto.sh http://localhost:5000
```

### generate report from existing results
```bash
python3 generate_report.py -i pentest_report.json
# or from individual files:
python3 generate_report.py --recon recon_report.json --sqli sqli_results.json --xss xss_results.json
```

### brute force with custom wordlists
```bash
python3 brute_force.py -t http://localhost:5000 -U usernames.txt -P wordlists/common_passwords.txt --threads 10
```

## output

each tool generates a json results file. `full_pentest.py` combines them all into:
- `pentest_report.json` - raw combined data
- `pentest_report.md` - formatted markdown report

## wordlists

- `wordlists/common_passwords.txt` - top 100 common passwords
- `wordlists/common_dirs.txt` - common web directories for bruteforcing

## disclaimer

these tools are designed for authorized security testing only. do not use against systems you don't own or have permission to test. built as part of an educational portfolio project.
