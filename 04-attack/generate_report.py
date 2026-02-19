#!/usr/bin/env python3
"""generate_report.py - converts json results into a markdown pentest report"""

import argparse
import json
import os
import sys
import time

from colorama import Fore, Style, init

init(autoreset=True)


def load_json(path):
    """load a json file, return empty dict if missing"""
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def severity_badge(level):
    """return a markdown badge for severity"""
    colors = {"critical": "[!]", "high": "[!]", "medium": "[*]", "low": "[-]", "info": "[i]"}
    return colors.get(level, "⚪")


def generate_markdown_report(data, output_path="pentest_report.md"):
    """build the full markdown report from combined results"""
    target = data.get("target", "unknown")
    timestamp = data.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S"))

    lines = []
    lines.append("# penetration test report")
    lines.append("")
    lines.append(f"**target:** {target}")
    lines.append(f"**date:** {timestamp}")
    lines.append(f"**tool:** e2e-security-ops attack toolkit")
    lines.append("")
    lines.append("---")
    lines.append("")

    # executive summary
    lines.append("## executive summary")
    lines.append("")
    vulns = count_vulnerabilities(data)
    lines.append(f"this assessment identified **{vulns['total']}** vulnerabilities:")
    lines.append(f"- {severity_badge('critical')} critical: {vulns.get('critical', 0)}")
    lines.append(f"- {severity_badge('high')} high: {vulns.get('high', 0)}")
    lines.append(f"- {severity_badge('medium')} medium: {vulns.get('medium', 0)}")
    lines.append(f"- {severity_badge('low')} low: {vulns.get('low', 0)}")
    lines.append(f"- {severity_badge('info')} informational: {vulns.get('info', 0)}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # recon findings
    recon = data.get("recon", {})
    if recon:
        lines.append("## 1. reconnaissance")
        lines.append("")
        open_ports = recon.get("open_ports", [])
        if open_ports:
            lines.append(f"### open ports")
            lines.append("")
            lines.append("| port | status |")
            lines.append("|------|--------|")
            for port in open_ports:
                lines.append(f"| {port} | open |")
            lines.append("")

        techs = recon.get("technologies", [])
        if techs:
            lines.append("### technology stack")
            lines.append("")
            for t in techs:
                lines.append(f"- {t}")
            lines.append("")

        headers = recon.get("headers", {})
        missing = headers.get("missing_security_headers", [])
        if missing:
            lines.append(f"### missing security headers")
            lines.append("")
            for h in missing:
                lines.append(f"- {severity_badge('medium')} {h}")
            lines.append("")

        dirs = recon.get("directories", [])
        if dirs:
            lines.append("### discovered directories")
            lines.append("")
            lines.append("| path | status |")
            lines.append("|------|--------|")
            for d in dirs:
                lines.append(f"| {d['path']} | {d['status']} |")
            lines.append("")

    # sqli findings
    sqli = data.get("sqli", {})
    if sqli:
        lines.append("## 2. sql injection")
        lines.append("")

        bypasses = [r for r in sqli.get("auth_bypass", []) if r.get("success")]
        if bypasses:
            lines.append(f"### {severity_badge('critical')} authentication bypass")
            lines.append("")
            lines.append("the following payloads bypassed authentication:")
            lines.append("")
            for b in bypasses:
                lines.append(f"- `{b['payload']['username']}`")
            lines.append("")

        users = sqli.get("extracted_data", {}).get("users", [])
        if users:
            lines.append(f"### {severity_badge('critical')} extracted credentials")
            lines.append("")
            lines.append("| username | password |")
            lines.append("|----------|----------|")
            for u in users:
                lines.append(f"| {u['username']} | {u['password']} |")
            lines.append("")

        db_info = sqli.get("database_info", {})
        if db_info.get("tables"):
            lines.append("### database structure")
            lines.append("")
            lines.append(f"- version: {db_info.get('version', 'unknown')}")
            lines.append(f"- tables: {', '.join(db_info['tables'])}")
            lines.append("")

    # xss findings
    xss = data.get("xss", {})
    if xss:
        lines.append("## 3. cross-site scripting (XSS)")
        lines.append("")

        reflected = [r for r in xss.get("reflected", []) if r.get("reflected")]
        if reflected:
            lines.append(f"### {severity_badge('high')} reflected XSS")
            lines.append("")
            lines.append(f"**{len(reflected)}** payloads were reflected without sanitization:")
            lines.append("")
            for r in reflected[:5]:  # show top 5
                lines.append(f"- `{r['payload']}`")
            lines.append("")

        stored = [r for r in xss.get("stored", []) if r.get("stored")]
        if stored:
            lines.append(f"### {severity_badge('critical')} stored XSS")
            lines.append("")
            lines.append(f"**{len(stored)}** payloads were stored and rendered:")
            lines.append("")
            for s in stored[:5]:
                lines.append(f"- `{s['payload']}`")
            lines.append("")

        dom = [r for r in xss.get("dom", []) if r.get("found")]
        if dom:
            lines.append(f"### {severity_badge('medium')} DOM XSS sinks")
            lines.append("")
            for d in dom:
                lines.append(f"- `{d['sink']}`")
            lines.append("")

    # upload findings
    upload = data.get("upload", {})
    if upload:
        lines.append("## 4. file upload")
        lines.append("")

        shells = [r for r in upload.get("webshell_tests", []) if r.get("uploaded")]
        if shells:
            lines.append(f"### {severity_badge('critical')} web shell upload")
            lines.append("")
            for s in shells:
                lines.append(f"- uploaded: `{s['filename']}`")
            lines.append("")

        accessible = upload.get("accessible_files", [])
        if accessible:
            lines.append(f"### accessible uploaded files")
            lines.append("")
            for a in accessible:
                lines.append(f"- [{a['filename']}]({a['url']})")
            lines.append("")

    # brute force findings
    brute = data.get("brute", {})
    if brute:
        lines.append("## 5. brute force")
        lines.append("")
        creds = brute.get("credentials", [])
        if creds:
            lines.append(f"### {severity_badge('high')} weak credentials")
            lines.append("")
            lines.append("| username | password |")
            lines.append("|----------|----------|")
            for c in creds:
                lines.append(f"| {c['username']} | {c['password']} |")
            lines.append("")
        else:
            lines.append("no weak credentials found via dictionary attack.")
            lines.append("")

    # idor findings
    idor = data.get("idor", {})
    if idor:
        lines.append("## 6. insecure direct object references (IDOR)")
        lines.append("")
        profiles = [p for p in idor.get("profiles", []) if p.get("data")]
        if profiles:
            lines.append(f"### {severity_badge('high')} user data exposure")
            lines.append("")
            lines.append(f"**{len(profiles)}** user profiles accessible without authorization:")
            lines.append("")
            for p in profiles:
                lines.append(f"- id={p['id']}: {json.dumps(p['data'])[:100]}")
            lines.append("")

        api_leaks = idor.get("api_idor", [])
        if api_leaks:
            lines.append(f"### {severity_badge('high')} API data leakage")
            lines.append("")
            for leak in api_leaks:
                lines.append(f"- {leak['endpoint'].format(id=leak['id'])}")
            lines.append("")

    # recommendations
    lines.append("---")
    lines.append("")
    lines.append("## recommendations")
    lines.append("")
    lines.append("1. **input validation** - sanitize all user input, use parameterized queries")
    lines.append("2. **output encoding** - encode output to prevent xss")
    lines.append("3. **file upload controls** - whitelist allowed file types, validate content")
    lines.append("4. **password policy** - enforce strong passwords, implement account lockout")
    lines.append("5. **access controls** - implement proper authorization checks for all resources")
    lines.append("6. **security headers** - add CSP, X-Frame-Options, HSTS headers")
    lines.append("7. **rate limiting** - implement rate limiting on login and sensitive endpoints")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"*report generated by e2e-security-ops attack toolkit on {timestamp}*")

    report = "\n".join(lines)

    with open(output_path, "w") as f:
        f.write(report)

    return report


def count_vulnerabilities(data):
    """count vulns by severity from all scan results"""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}

    # sqli auth bypass = critical
    sqli = data.get("sqli", {})
    bypasses = sum(1 for r in sqli.get("auth_bypass", []) if r.get("success"))
    counts["critical"] += bypasses

    # extracted creds = critical
    users = len(sqli.get("extracted_data", {}).get("users", []))
    if users:
        counts["critical"] += 1

    # xss reflected = high
    xss = data.get("xss", {})
    reflected = sum(1 for r in xss.get("reflected", []) if r.get("reflected"))
    if reflected:
        counts["high"] += 1

    # xss stored = critical
    stored = sum(1 for r in xss.get("stored", []) if r.get("stored"))
    if stored:
        counts["critical"] += 1

    # file upload shells = critical
    upload = data.get("upload", {})
    shells = sum(1 for r in upload.get("webshell_tests", []) if r.get("uploaded"))
    if shells:
        counts["critical"] += 1

    # brute force = high
    brute = data.get("brute", {})
    if brute.get("credentials"):
        counts["high"] += 1

    # idor = high
    idor = data.get("idor", {})
    profiles = sum(1 for p in idor.get("profiles", []) if p.get("data"))
    if profiles:
        counts["high"] += 1

    # missing headers = medium
    recon = data.get("recon", {})
    missing = len(recon.get("headers", {}).get("missing_security_headers", []))
    counts["medium"] += min(missing, 3)  # cap it

    # open ports = info
    open_ports = len(recon.get("open_ports", []))
    if open_ports:
        counts["info"] += 1

    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    return counts


def main():
    parser = argparse.ArgumentParser(description="generate_report.py - report generator")
    parser.add_argument("-i", "--input", default="pentest_report.json",
                        help="combined json results file")
    parser.add_argument("-o", "--output", default="pentest_report.md",
                        help="output markdown report")
    # also accept individual result files
    parser.add_argument("--recon", default=None, help="recon json file")
    parser.add_argument("--sqli", default=None, help="sqli json file")
    parser.add_argument("--xss", default=None, help="xss json file")
    parser.add_argument("--upload", default=None, help="upload json file")
    parser.add_argument("--brute", default=None, help="brute force json file")
    parser.add_argument("--idor", default=None, help="idor json file")
    args = parser.parse_args()

    # either load combined file or individual files
    if any([args.recon, args.sqli, args.xss, args.upload, args.brute, args.idor]):
        data = {}
        if args.recon:
            data["recon"] = load_json(args.recon)
        if args.sqli:
            data["sqli"] = load_json(args.sqli)
        if args.xss:
            data["xss"] = load_json(args.xss)
        if args.upload:
            data["upload"] = load_json(args.upload)
        if args.brute:
            data["brute"] = load_json(args.brute)
        if args.idor:
            data["idor"] = load_json(args.idor)
        # grab target from any available result
        for key in data:
            if "target" in data[key]:
                data["target"] = data[key]["target"]
                break
        data["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    else:
        data = load_json(args.input)

    if not data:
        print(f"{Fore.RED}[!] no data to generate report from")
        sys.exit(1)

    report = generate_markdown_report(data, args.output)
    print(f"{Fore.GREEN}[+] report generated: {args.output}")
    print(f"{Fore.YELLOW}[*] report length: {len(report)} characters")


if __name__ == "__main__":
    main()
