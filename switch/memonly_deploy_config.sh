#!/bin/bash

# 1. Handle Parameters
if [ "$#" -eq 4 ]; then
    CONFIG_FILE="$1"
    SWITCH_IP="$2"
    CURRENT_PASS="$3"
    NEW_PASS="$4"
else
    echo "Usage: ./deploy_config.sh <config_file> <ip> <current_pass> <new_pass>"
    exit 1
fi

CLEAN_CONF="clean_config.txt"
EXPECT_SCRIPT="deploy.exp"

# 2. Pre-process the file (removes metadata tags and replaces passwords)
sed -e "s|<ClearTextPassword>|$NEW_PASS|g" \
    -e 's/\*\]//g' "$CONFIG_FILE" > "$CLEAN_CONF"

# 3. Create the Expect script with the fix for the 'copy' command
cat << 'EOF' > "$EXPECT_SCRIPT"
set timeout 60
set ip [lindex $argv 0]
set pass [lindex $argv 1]
set filename [lindex $argv 2]

spawn telnet $ip

expect "Password:"
send -- "$pass\r"

expect ">"
send "enable\r"
expect "Password:"
send -- "$pass\r"

expect "#"
send "configure terminal\r"
expect "(config)#"

set fd [open $filename r]
while {[gets $fd line] != -1} {
    set clean_line [string trim $line]
    if {$clean_line eq "" || [string match "!*" $clean_line] || [string match "end" $clean_line]} { continue }
    
    send -- "$clean_line\r"
    expect -re ".*\(config.*\)#"
}
close $fd

# Exit configuration mode cleanly
send "end\r"
expect "#"

send "exit\r"
expect eof
EOF

# 4. Run the deployment
expect "$EXPECT_SCRIPT" "$SWITCH_IP" "$CURRENT_PASS" "$CLEAN_CONF"

# 5. Cleanup
rm "$CLEAN_CONF" "$EXPECT_SCRIPT"
echo "----------------------------------------------------"
echo "Configuration deployed and saved to NVRAM on $SWITCH_IP"
