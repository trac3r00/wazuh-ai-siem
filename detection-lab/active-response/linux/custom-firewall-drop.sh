#!/bin/bash
# Wazuh Active Response - Custom Suricata Block
# Author: Trac3r00
# Description: Intercepts Wazuh Active Response data, handles missing arguments, 
# extracting src_ip from JSON, and executes iptables block.

# 1. Define Log Files
DEBUG_LOG="/tmp/ar-debug.log"
INPUT_DUMP="/tmp/ar-input.txt"

echo "$(date) - Script started." >> "$DEBUG_LOG"

# 2. Dump EVERYTHING from STDIN to a file (No timeout, just cat)
# This handles cases where Wazuh pipes data instead of passing a file argument
/bin/cat > "$INPUT_DUMP"

echo "$(date) - Input dumped to $INPUT_DUMP" >> "$DEBUG_LOG"

# 3. Use grep with full path to find the IP in the file
# Matches: "src_ip":"10.10.0.155" (handles optional spaces)
IP=$(/bin/grep -oP '"src_ip"\s*:\s*"\K[^"]+' "$INPUT_DUMP")

echo "$(date) - Extracted IP: $IP" >> "$DEBUG_LOG"

# 4. Block the IP
if [ -n "$IP" ]; then
    /usr/sbin/iptables -I INPUT -s "$IP" -j DROP
    echo "$(date) - SUCCESS: Blocked $IP" >> "$DEBUG_LOG"
else
    echo "$(date) - ERROR: Could not find src_ip in input." >> "$DEBUG_LOG"
fi