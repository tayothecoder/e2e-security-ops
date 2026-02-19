#!/usr/bin/env bash
# install and configure suricata on ubuntu
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "run this as root or with sudo"
    exit 1
fi

echo "adding suricata ppa..."
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update

echo "installing suricata..."
apt-get install -y suricata suricata-update

echo "stopping suricata while we configure..."
systemctl stop suricata || true

# figure out the main network interface
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo "detected interface: $IFACE"

# backup original config
cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak

# copy our config and patch the interface name
cp "$SCRIPT_DIR/suricata.yaml" /etc/suricata/suricata.yaml
sed -i "s/interface: eth0/interface: $IFACE/g" /etc/suricata/suricata.yaml

# copy custom rules
mkdir -p /etc/suricata/rules
cp "$SCRIPT_DIR/custom.rules" /etc/suricata/rules/custom.rules

# update the default ruleset
echo "updating suricata rules..."
suricata-update

# make sure log dir exists
mkdir -p /var/log/suricata
chown suricata:suricata /var/log/suricata 2>/dev/null || true

# test the config
echo "testing configuration..."
suricata -T -c /etc/suricata/suricata.yaml

echo "starting suricata..."
systemctl enable suricata
systemctl start suricata

echo "suricata is running on interface $IFACE"
echo "logs: /var/log/suricata/eve.json"
echo "check status: systemctl status suricata"
