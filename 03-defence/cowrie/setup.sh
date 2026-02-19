#!/usr/bin/env bash
# install cowrie honeypot in a virtualenv
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COWRIE_DIR="/opt/cowrie"
COWRIE_USER="cowrie"

if [[ $EUID -ne 0 ]]; then
    echo "run this as root or with sudo"
    exit 1
fi

echo "installing dependencies..."
apt-get update
apt-get install -y \
    git python3 python3-venv python3-dev \
    libssl-dev libffi-dev build-essential \
    authbind

# create cowrie user if it doesn't exist
if ! id "$COWRIE_USER" &>/dev/null; then
    echo "creating cowrie user..."
    adduser --disabled-password --gecos "" "$COWRIE_USER"
fi

# clone cowrie
if [[ ! -d "$COWRIE_DIR" ]]; then
    echo "cloning cowrie..."
    git clone https://github.com/cowrie/cowrie.git "$COWRIE_DIR"
    chown -R "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_DIR"
fi

cd "$COWRIE_DIR"

# set up virtualenv
echo "setting up virtualenv..."
sudo -u "$COWRIE_USER" python3 -m venv cowrie-env
sudo -u "$COWRIE_USER" "$COWRIE_DIR/cowrie-env/bin/pip" install --upgrade pip
sudo -u "$COWRIE_USER" "$COWRIE_DIR/cowrie-env/bin/pip" install -r requirements.txt

# copy our config
echo "copying configuration..."
cp "$SCRIPT_DIR/cowrie.cfg" "$COWRIE_DIR/etc/cowrie.cfg"
cp "$SCRIPT_DIR/userdb.txt" "$COWRIE_DIR/etc/userdb.txt"
chown "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_DIR/etc/cowrie.cfg"
chown "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_DIR/etc/userdb.txt"

# create log directories
mkdir -p "$COWRIE_DIR/var/log/cowrie"
mkdir -p "$COWRIE_DIR/var/lib/cowrie/downloads"
mkdir -p "$COWRIE_DIR/var/lib/cowrie/ttylog"
chown -R "$COWRIE_USER":"$COWRIE_USER" "$COWRIE_DIR/var"

# set up authbind so cowrie can listen on low ports if needed
touch /etc/authbind/byport/22
chown "$COWRIE_USER" /etc/authbind/byport/22
chmod 770 /etc/authbind/byport/22

echo "starting cowrie..."
sudo -u "$COWRIE_USER" "$COWRIE_DIR/bin/cowrie" start

echo "cowrie is running"
echo "ssh honeypot: port 2222"
echo "telnet honeypot: port 2323"
echo "logs: $COWRIE_DIR/var/log/cowrie/"
echo ""
echo "to redirect real port 22 to 2222, run:"
echo "  iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222"
