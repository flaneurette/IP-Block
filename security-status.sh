#!/bin/bash

# Colors
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

echo -e "${CYAN}╔════════════════════════════════════════════════════╗"
echo -e "║         SERVER SECURITY STATUS                     ║"
echo -e "╚════════════════════════════════════════════════════╝${RESET}"
echo ""

# Function to count IPs safely
count_ipset() {
    local set_name="$1"
    if sudo ipset list "$set_name" &>/dev/null; then
        echo "$(sudo ipset list "$set_name" | grep -c '^[0-9]')"
    else
        echo "0"
    fi
}

# IP Blocking Statistics
malicious_count=$(count_ipset "malicious_ips")
custom_count=$(count_ipset "custom_attackers")

echo -e "${YELLOW}IP Blocking Statistics:${RESET}"
echo -e "  Spamhaus blocklist:     ${malicious_count} IPs"
echo -e "  Custom attackers:       ${custom_count} entries"
echo ""

# Fail2ban Status
echo -e "${YELLOW}Fail2ban Status:${RESET}"
jails=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://g' | tr ',' '\n')

if [ -z "$jails" ]; then
    echo "  No jails found."
else
    for jail in $jails; do
        jail=$(echo "$jail" | xargs)
        if [ -n "$jail" ]; then
            status=$(sudo fail2ban-client status "$jail" 2>/dev/null)
            banned=$(echo "$status" | grep "Currently banned" | awk '{print $4}')
            total=$(echo "$status" | grep "Total banned" | awk '{print $4}')
            # Colorize if too many currently banned
            if [ "$banned" -ge 50 ]; then
                banned_color="$RED$banned$RESET"
            else
                banned_color="$GREEN$banned$RESET"
            fi
            echo -e "  $jail: $banned_color currently banned ($total total)"
        fi
    done
fi
echo ""

# Recent Attacks
echo -e "${YELLOW}Recent Attacks (last 10):${RESET}"
if [ -f /var/log/fail2ban.log ]; then
    sudo tail -10 /var/log/fail2ban.log | grep "Ban " | awk '{print $1, $2, $(NF-1), $NF}' | sed 's/Ban /    /'
else
    echo "  No fail2ban log found."
fi
echo ""

# Last Blocklist Update
echo -e "${YELLOW}Last Blocklist Update:${RESET}"
if [ -f /var/log/blocklist-update.log ]; then
    tail -3 /var/log/blocklist-update.log
else
    echo "  No blocklist update log found."
fi
