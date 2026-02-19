#!/usr/bin/env bash
# iptables firewall rules for the security ops lab
# allows http/https to app, ssh on port 2200, drops everything else
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "run this as root or with sudo"
    exit 1
fi

SSH_PORT=2200
RATE_LIMIT="25/minute"
LOG_PREFIX="iptables-dropped: "

echo "flushing existing rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t mangle -F

# default policies - drop everything
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# rate limit new connections globally (syn flood protection)
iptables -A INPUT -p tcp --syn -m limit --limit $RATE_LIMIT --limit-burst 50 -j ACCEPT
# the accept above only passes rate-limited SYNs to subsequent rules via a chain approach
# actually let's do this properly with a separate chain

# remove the above and redo with a chain
iptables -D INPUT -p tcp --syn -m limit --limit $RATE_LIMIT --limit-burst 50 -j ACCEPT 2>/dev/null || true

# rate limiting chain
iptables -N RATE_LIMIT 2>/dev/null || iptables -F RATE_LIMIT
iptables -A RATE_LIMIT -m limit --limit $RATE_LIMIT --limit-burst 50 -j RETURN
iptables -A RATE_LIMIT -j DROP

# apply rate limiting to new tcp connections
iptables -A INPUT -p tcp --syn -j RATE_LIMIT

# allow http (80)
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# allow https (443)
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# allow ssh on non-standard port
iptables -A INPUT -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -j ACCEPT

# allow icmp ping (useful for monitoring, limit to prevent ping flood)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/second --limit-burst 10 -j ACCEPT

# allow cowrie honeypot ports (optional, uncomment if needed)
# iptables -A INPUT -p tcp --dport 2222 -m conntrack --ctstate NEW -j ACCEPT
# iptables -A INPUT -p tcp --dport 2323 -m conntrack --ctstate NEW -j ACCEPT

# redirect port 22 to cowrie on 2222 (nat)
# uncomment to activate the honeypot redirect
# iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# log dropped packets (limit logging to avoid filling disk)
iptables -A INPUT -m limit --limit 10/minute --limit-burst 20 -j LOG --log-prefix "$LOG_PREFIX" --log-level 4

# final drop (implicit from policy, but explicit for clarity)
iptables -A INPUT -j DROP

echo "firewall rules applied"
echo ""
echo "allowed inbound:"
echo "  tcp/80   - http"
echo "  tcp/443  - https"
echo "  tcp/$SSH_PORT - ssh"
echo "  icmp     - ping (rate limited)"
echo ""
echo "everything else is dropped and logged"
echo ""
echo "to persist rules across reboot:"
echo "  apt-get install iptables-persistent"
echo "  netfilter-persistent save"
echo ""
echo "current rules:"
iptables -L -n -v --line-numbers
