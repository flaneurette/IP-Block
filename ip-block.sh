#!/bin/bash
# /etc/cron.daily/update-blocklists
# Advanced version with multiple sources and rotation

BLOCKLIST_NAME="malicious_ips"
TEMP_DIR="/tmp/blocklists"
LOG_FILE="/var/log/blocklist-update.log"
MAX_AGE_DAYS=30  # Remove IPs not seen in lists for 30 days

# Blocklist sources (add/remove as needed)
declare -A SOURCES=(
    ["spamhaus_drop"]="https://www.spamhaus.org/drop/drop.txt"
    ["spamhaus_edrop"]="https://www.spamhaus.org/drop/edrop.txt"
    # Add more sources here if needed
    # ["blocklist_de"]="https://lists.blocklist.de/lists/all.txt"
)

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Setup
mkdir -p "$TEMP_DIR"
COMBINED_LIST="$TEMP_DIR/combined.txt"
> "$COMBINED_LIST"  # Clear file

log "=== Starting blocklist update ==="

# Create ipset if it doesn't exist
if ! ipset list "$BLOCKLIST_NAME" &>/dev/null; then
    ipset create "$BLOCKLIST_NAME" hash:net maxelem 65536 comment timeout 0
    log "Created new ipset: $BLOCKLIST_NAME"
fi

# Download all sources
for source_name in "${!SOURCES[@]}"; do
    url="${SOURCES[$source_name]}"
    temp_file="$TEMP_DIR/${source_name}.txt"
    
    log "Downloading $source_name..."
    if curl -s -f -m 30 -o "$temp_file" "$url"; then
        # Extract IPs/networks (handle different formats)
        grep -E '^[0-9]' "$temp_file" | \
        grep -v '^;' | \
        awk '{print $1}' | \
        grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' >> "$COMBINED_LIST"
        
        count=$(wc -l < "$temp_file")
        log "Downloaded $count entries from $source_name"
    else
        log "Failed to download $source_name"
    fi
done

# Remove duplicates and sort
sort -u "$COMBINED_LIST" -o "$COMBINED_LIST"
TOTAL_ENTRIES=$(wc -l < "$COMBINED_LIST")
log "Total unique entries to process: $TOTAL_ENTRIES"

# Update ipset efficiently
NEW_COUNT=0
EXIST_COUNT=0

while IFS= read -r ip; do
    if [ -n "$ip" ]; then
        if ipset test "$BLOCKLIST_NAME" "$ip" 2>/dev/null; then
            ((EXIST_COUNT++))
        else
            if ipset add "$BLOCKLIST_NAME" "$ip" 2>/dev/null; then
                ((NEW_COUNT++))
            fi
        fi
    fi
done < "$COMBINED_LIST"

log "Results: $NEW_COUNT new IPs added, $EXIST_COUNT already existed"

# Ensure iptables rule exists (only once)
if ! iptables -C INPUT -m set --match-set "$BLOCKLIST_NAME" src -j DROP 2>/dev/null; then
    iptables -I INPUT -m set --match-set "$BLOCKLIST_NAME" src -j DROP
    log "Added iptables rule"
else
    log "iptables rule already exists"
fi

# Make persistent across reboots
# if command -v netfilter-persistent &>/dev/null; then
#    netfilter-persistent save >/dev/null 2>&1
#    log "Saved iptables rules"
# fi

# Cleanup temp files
rm -rf "$TEMP_DIR"

# Final stats
FINAL_COUNT=$(ipset list "$BLOCKLIST_NAME" 2>/dev/null | grep -c '^[0-9]')
log "=== Update complete: $FINAL_COUNT total IPs blocked ==="
log ""
