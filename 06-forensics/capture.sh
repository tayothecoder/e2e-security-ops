#!/usr/bin/env bash
# evidence collection script for forensic investigations
# collects volatile system data, logs, and packages with integrity hashes

set -euo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CASE_ID="${1:-CASE_$(date +%Y%m%d)}"
EVIDENCE_DIR="/tmp/evidence_${CASE_ID}_${TIMESTAMP}"
CUSTODY_LOG="${EVIDENCE_DIR}/chain_of_custody.log"

echo "[*] starting evidence collection for case: ${CASE_ID}"
echo "[*] evidence directory: ${EVIDENCE_DIR}"
mkdir -p "${EVIDENCE_DIR}"/{system,network,logs}

# initialise chain of custody log
cat > "${CUSTODY_LOG}" <<EOF
chain of custody log
====================
case id:    ${CASE_ID}
started:    $(date -u '+%Y-%m-%d %H:%M:%S UTC')
collector:  $(whoami)@$(hostname)
system:     $(uname -a)

evidence items:
---------------
EOF

log_item() {
    local desc="$1"
    local file="$2"
    echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') | collected: ${desc} -> ${file}" >> "${CUSTODY_LOG}"
}

# capture running processes
echo "[*] capturing process list"
ps aux > "${EVIDENCE_DIR}/system/processes.txt" 2>&1
log_item "running processes" "system/processes.txt"

# capture open files
echo "[*] capturing open files"
lsof > "${EVIDENCE_DIR}/system/open_files.txt" 2>/dev/null || true
log_item "open files listing" "system/open_files.txt"

# capture network connections with ss
echo "[*] capturing network connections (ss)"
ss -tulnp > "${EVIDENCE_DIR}/network/ss_listening.txt" 2>&1
ss -anp > "${EVIDENCE_DIR}/network/ss_all.txt" 2>&1
log_item "network connections (ss)" "network/ss_listening.txt"
log_item "all socket states (ss)" "network/ss_all.txt"

# capture network connections with netstat if available
if command -v netstat &>/dev/null; then
    echo "[*] capturing network connections (netstat)"
    netstat -tulnp > "${EVIDENCE_DIR}/network/netstat_listening.txt" 2>/dev/null || true
    netstat -an > "${EVIDENCE_DIR}/network/netstat_all.txt" 2>/dev/null || true
    log_item "network connections (netstat)" "network/netstat_listening.txt"
fi

# capture arp cache
echo "[*] capturing ARP cache"
ip neigh show > "${EVIDENCE_DIR}/network/arp_cache.txt" 2>&1 || arp -a > "${EVIDENCE_DIR}/network/arp_cache.txt" 2>&1
log_item "ARP cache" "network/arp_cache.txt"

# capture routing table
echo "[*] capturing routing table"
ip route show > "${EVIDENCE_DIR}/network/routes.txt" 2>&1
log_item "routing table" "network/routes.txt"

# capture dns resolver config
cp /etc/resolv.conf "${EVIDENCE_DIR}/network/resolv.conf" 2>/dev/null || true
log_item "DNS resolver config" "network/resolv.conf"

# collect relevant log files
echo "[*] collecting log files"
for logfile in /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/apache2/access.log /var/log/nginx/access.log /var/log/suricata/eve.json; do
    if [ -f "${logfile}" ]; then
        dest="logs/$(basename ${logfile})"
        cp "${logfile}" "${EVIDENCE_DIR}/${dest}"
        log_item "log file: ${logfile}" "${dest}"
        echo "  [+] copied ${logfile}"
    fi
done

# also grab recent journal entries if available
if command -v journalctl &>/dev/null; then
    echo "[*] capturing systemd journal (last 24h)"
    journalctl --since "24 hours ago" --no-pager > "${EVIDENCE_DIR}/logs/journal_24h.txt" 2>/dev/null || true
    log_item "systemd journal (24h)" "logs/journal_24h.txt"
fi

# generate sha256 hashes of all collected evidence
echo "[*] generating sha256 hashes"
HASH_FILE="${EVIDENCE_DIR}/evidence_hashes.sha256"
find "${EVIDENCE_DIR}" -type f ! -name "evidence_hashes.sha256" -exec sha256sum {} \; > "${HASH_FILE}"
log_item "integrity hashes" "evidence_hashes.sha256"

# finalise custody log
cat >> "${CUSTODY_LOG}" <<EOF

collection completed: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
total files collected: $(find "${EVIDENCE_DIR}" -type f | wc -l)
EOF

# package everything
ARCHIVE="/tmp/evidence_${CASE_ID}_${TIMESTAMP}.tar.gz"
echo "[*] packaging evidence to ${ARCHIVE}"
tar -czf "${ARCHIVE}" -C /tmp "evidence_${CASE_ID}_${TIMESTAMP}"

# hash the archive itself
ARCHIVE_HASH=$(sha256sum "${ARCHIVE}" | awk '{print $1}')
echo "[*] archive sha256: ${ARCHIVE_HASH}"

echo ""
echo "[*] evidence collection complete"
echo "    archive: ${ARCHIVE}"
echo "    sha256:  ${ARCHIVE_HASH}"
echo "    items:   $(find "${EVIDENCE_DIR}" -type f | wc -l) files"
