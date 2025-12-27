#!/bin/bash

echo "╔════════════════════════════════════════════════════╗"
echo "║         SERVER SECURITY STATUS                     ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

echo "IP Blocking Statistics:"
echo "  Spamhaus blocklist:     $(sudo ipset list malicious_ips 2>/dev/null | grep -c '^[0-9]') IPs"
echo "  Custom attackers:       $(sudo ipset list custom_attackers 2>/dev/null | grep -c '^[0-9]') entries"
echo ""

echo "Fail2ban Status:"
sudo fail2ban-client status | grep "Jail list" | sed 's/.*://g' | tr ',' '\n' | while read jail; do
    if [ -n "$jail" ]; then
        banned=$(sudo fail2ban-client status $jail 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        total=$(sudo fail2ban-client status $jail 2>/dev/null | grep "Total banned" | awk '{print $4}')
        echo "  $jail: $banned currently banned ($total total)"
    fi
done
echo ""

echo "Recent Attacks (last 10):"
sudo tail -10 /var/log/fail2ban.log | grep "Ban " | awk '{print $1, $2, $NF}' | sed 's/Ban /  ⚠️  /'
echo ""

echo "Last Blocklist Update:"
tail -3 /var/log/blocklist-update.log
