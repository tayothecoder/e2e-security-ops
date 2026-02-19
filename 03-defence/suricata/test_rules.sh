#!/usr/bin/env bash
# send test payloads to verify suricata rules are firing
set -euo pipefail

TARGET="${1:-http://localhost}"
LOG="/var/log/suricata/eve.json"
DELAY=0.5

echo "target: $TARGET"
echo "watching: $LOG"
echo "---"

# grab current line count so we only check new alerts
if [[ -f "$LOG" ]]; then
    BASELINE=$(wc -l < "$LOG")
else
    BASELINE=0
fi

fire() {
    local desc="$1"
    shift
    echo "[test] $desc"
    "$@" -s -o /dev/null -w '%{http_code}' 2>/dev/null || true
    echo ""
    sleep "$DELAY"
}

# sqli tests
fire "union select in uri" \
    curl "$TARGET/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users"

fire "or 1=1 in uri" \
    curl "$TARGET/login?id=1%20OR%201=1"

fire "single quote attack" \
    curl "$TARGET/item?id=1'%20OR%20'1'='1"

fire "sqlmap user agent" \
    curl -A "sqlmap/1.6.12" "$TARGET/"

# xss tests
fire "script tag in uri" \
    curl "$TARGET/search?q=<script>alert(1)</script>"

fire "onerror handler" \
    curl "$TARGET/page?img=x%20onerror=alert(1)"

fire "javascript uri scheme" \
    curl "$TARGET/redirect?url=javascript:alert(document.cookie)"

fire "script tag in post body" \
    curl -X POST -d "comment=<script>alert('xss')</script>" "$TARGET/comment"

# directory traversal
fire "dot dot slash" \
    curl "$TARGET/files?path=../../../../etc/passwd"

fire "encoded traversal" \
    curl "$TARGET/files?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# web shell upload
fire "php file upload" \
    curl -X POST -F "file=@/dev/null;filename=shell.php" "$TARGET/upload"

# brute force (send 12 rapid requests)
echo "[test] brute force - rapid login attempts"
for i in $(seq 1 12); do
    curl -s -o /dev/null -X POST -d "user=admin&pass=attempt$i" "$TARGET/login" 2>/dev/null || true
done
echo ""
sleep "$DELAY"

# recon user agents
fire "nmap user agent" \
    curl -A "Mozilla/5.0 (compatible; Nmap Scripting Engine)" "$TARGET/"

fire "nikto scanner" \
    curl -A "Nikto/2.1.6" "$TARGET/"

fire "dirb scanner" \
    curl -A "DirBuster-1.0-RC1" "$TARGET/admin"

echo "---"
echo "done sending payloads. checking alerts..."
sleep 2

if [[ -f "$LOG" ]]; then
    NEW_ALERTS=$(tail -n +$((BASELINE + 1)) "$LOG" | grep '"event_type":"alert"' | wc -l)
    echo "new alerts generated: $NEW_ALERTS"
    echo ""
    echo "recent alerts:"
    tail -n +$((BASELINE + 1)) "$LOG" | \
        grep '"event_type":"alert"' | \
        python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        a = e.get('alert', {})
        print(f\"  [{a.get('severity','-')}] {a.get('signature','unknown')} (sid:{a.get('signature_id','?')}) src:{e.get('src_ip','?')}\")
    except:
        pass
" 2>/dev/null || echo "  (install python3 to see parsed alerts, or check $LOG manually)"
else
    echo "log file not found at $LOG"
    echo "make sure suricata is running and logging to that path"
fi
