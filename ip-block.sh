#!/bin/bash
# /etc/cron.daily/update-blocklists
# Advanced version with multiple sources supporting both TXT and JSON formats

BLOCKLIST_NAME="malicious_ips"
BLOCKLIST_NAME_V6="malicious_ips_v6"
TEMP_DIR="/tmp/blocklists"
LOG_FILE="/var/log/blocklist-update.log"

# Blocklist sources with format type
declare -A SOURCES=(
    ["spamhaus_drop_v4"]="https://www.spamhaus.org/drop/drop_v4.json|json|v4"
    ["spamhaus_drop_v6"]="https://www.spamhaus.org/drop/drop_v6.json|json|v6"
    ["spamhaus_asn"]="https://www.spamhaus.org/drop/asndrop.json|json|asn"
)

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Setup
mkdir -p "$TEMP_DIR"
COMBINED_LIST_V4="$TEMP_DIR/combined_v4.txt"
COMBINED_LIST_V6="$TEMP_DIR/combined_v6.txt"
ASN_LIST="$TEMP_DIR/asn_list.txt"
> "$COMBINED_LIST_V4"
> "$COMBINED_LIST_V6"
> "$ASN_LIST"

log "=== Starting blocklist update ==="

# Check for jq (required for JSON parsing)
if ! command -v jq &>/dev/null; then
    log "ERROR: jq is not installed. Install with: apt-get install jq"
    exit 1
fi

# Create ipsets if they don't exist
if ! ipset list "$BLOCKLIST_NAME" &>/dev/null; then
    ipset create "$BLOCKLIST_NAME" hash:net family inet maxelem 65536 comment
    log "Created new ipset: $BLOCKLIST_NAME (IPv4)"
fi

if ! ipset list "$BLOCKLIST_NAME_V6" &>/dev/null; then
    ipset create "$BLOCKLIST_NAME_V6" hash:net family inet6 maxelem 65536 comment
    log "Created new ipset: $BLOCKLIST_NAME_V6 (IPv6)"
fi

# Function to parse NDJSON format (newline-delimited JSON)
parse_json() {
    local file="$1"
    local type="$2"
    
    case "$type" in
        v4|v6)
            # Each line is a separate JSON object with "cidr" field
            jq -r '.cidr' "$file" 2>/dev/null | grep -v '^null$'
            ;;
        asn)
            # Each line is a separate JSON object with "asn" field
            jq -r '.asn' "$file" 2>/dev/null | grep -v '^null$' | sed 's/^AS//'
            ;;
    esac
}

# Function to parse TXT format (legacy)
parse_txt() {
    local file="$1"
    grep -E '^[0-9]' "$file" | \
    grep -v '^;' | \
    awk '{print $1}' | \
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?'
}

# Download all sources
for source_name in "${!SOURCES[@]}"; do
    IFS='|' read -r url format type <<< "${SOURCES[$source_name]}"
    temp_file="$TEMP_DIR/${source_name}.${format}"

    log "Downloading $source_name ($format format)..."
    
    if curl -s -f -m 30 -o "$temp_file" "$url"; then
        # Parse based on format
        if [ "$format" = "json" ]; then
            parsed_output=$(parse_json "$temp_file" "$type")
        else
            parsed_output=$(parse_txt "$temp_file")
        fi
        
        # Route to appropriate list
        if [ "$type" = "v4" ]; then
            echo "$parsed_output" >> "$COMBINED_LIST_V4"
        elif [ "$type" = "v6" ]; then
            echo "$parsed_output" >> "$COMBINED_LIST_V6"
        elif [ "$type" = "asn" ]; then
            echo "$parsed_output" >> "$ASN_LIST"
        fi
        
        count=$(echo "$parsed_output" | grep -c '^')
        log "Downloaded $count entries from $source_name"
    else
        log "Failed to download $source_name from $url"
    fi
done

# Remove duplicates and sort
sort -u "$COMBINED_LIST_V4" -o "$COMBINED_LIST_V4"
sort -u "$COMBINED_LIST_V6" -o "$COMBINED_LIST_V6"

TOTAL_V4=$(wc -l < "$COMBINED_LIST_V4")
TOTAL_V6=$(wc -l < "$COMBINED_LIST_V6")
log "Total unique IPv4 entries to process: $TOTAL_V4"
log "Total unique IPv6 entries to process: $TOTAL_V6"

# Function to update ipset
update_ipset() {
    local ipset_name="$1"
    local list_file="$2"
    local new_count=0
    local exist_count=0
    
    while IFS= read -r ip; do
        if [ -n "$ip" ] && [ "$ip" != "null" ]; then
            if ipset test "$ipset_name" "$ip" 2>/dev/null; then
                ((exist_count++))
            else
                if ipset add "$ipset_name" "$ip" 2>/dev/null; then
                    ((new_count++))
                fi
            fi
        fi
    done < "$list_file"
    
    echo "$new_count|$exist_count"
}

# Update IPv4 ipset
if [ "$TOTAL_V4" -gt 0 ]; then
    log "Updating IPv4 blocklist..."
    RESULT_V4=$(update_ipset "$BLOCKLIST_NAME" "$COMBINED_LIST_V4")
    NEW_V4="${RESULT_V4%|*}"
    EXIST_V4="${RESULT_V4#*|}"
    log "IPv4 Results: $NEW_V4 new IPs added, $EXIST_V4 already existed"
fi

# Update IPv6 ipset
if [ "$TOTAL_V6" -gt 0 ]; then
    log "Updating IPv6 blocklist..."
    RESULT_V6=$(update_ipset "$BLOCKLIST_NAME_V6" "$COMBINED_LIST_V6")
    NEW_V6="${RESULT_V6%|*}"
    EXIST_V6="${RESULT_V6#*|}"
    log "IPv6 Results: $NEW_V6 new IPs added, $EXIST_V6 already existed"
fi

# Log ASN info (for informational purposes - not blocking ASNs directly)
ASN_COUNT=$(wc -l < "$ASN_LIST")
if [ "$ASN_COUNT" -gt 0 ]; then
    log "INFO: $ASN_COUNT ASNs in DROP list (not blocking - requires BGP/AS-level blocking)"
fi

# Ensure iptables rules exist
if ! iptables -C INPUT -m set --match-set "$BLOCKLIST_NAME" src -j DROP 2>/dev/null; then
    iptables -I INPUT -m set --match-set "$BLOCKLIST_NAME" src -j DROP
    log "Added iptables rule for IPv4"
else
    log "iptables rule for IPv4 already exists"
fi

if ! ip6tables -C INPUT -m set --match-set "$BLOCKLIST_NAME_V6" src -j DROP 2>/dev/null; then
    ip6tables -I INPUT -m set --match-set "$BLOCKLIST_NAME_V6" src -j DROP
    log "Added ip6tables rule for IPv6"
else
    log "ip6tables rule for IPv6 already exists"
fi

# Cleanup temp files
rm -rf "$TEMP_DIR"

# Final stats
FINAL_V4=$(ipset list "$BLOCKLIST_NAME" 2>/dev/null | grep -E '^[0-9]+\.' | wc -l)
FINAL_V6=$(ipset list "$BLOCKLIST_NAME_V6" 2>/dev/null | grep -E '^[0-9a-fA-F:]+/' | wc -l)
log "=== Update complete ==="
log "Total IPv4 IPs/networks blocked: $FINAL_V4"
log "Total IPv6 IPs/networks blocked: $FINAL_V6"
log ""
