#!/bin/bash

# 1. Check for required parameters
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <switch_ip> <password>"
    exit 1
fi

# 2. Assign parameters to variables
SWITCH_IP="$1"
PASS="$2"
DATESTAMP=$(date +"%Y%m%d_%H%M")
BACKUP_FILE="ChezySwitch_Status_${DATESTAMP}.txt"

echo "Connecting to ${SWITCH_IP}..."
echo "Capturing full switch status and config to ${BACKUP_FILE}..."

# 3. Use 'expect -' to read from stdin while still accepting arguments
expect - "$SWITCH_IP" "$PASS" "$BACKUP_FILE" << 'EOF'
set timeout 60
set ip [lindex $argv 0]
set pass [lindex $argv 1]
set backup_file [lindex $argv 2]

spawn telnet $ip

expect {
    "Password:" {
        send -- "$pass\r"
    }
    timeout {
        send_user "\nError: Timed out waiting for login prompt.\n"
        exit 1
    }
    "Connection refused" {
        send_user "\nError: Connection refused. Check IP and Telnet status.\n"
        exit 1
    }
}

expect ">"
send "enable\r"
expect "Password:"
send -- "$pass\r"

expect "#"
send "terminal length 0\r"
expect "#"

log_file -a "$backup_file"

send "echo !!! STARTUP CONFIG !!!\r"
expect "#"
send "show startup-config\r"
expect "#"

send "echo !!! VLAN BRIEF !!!\r"
expect "#"
send "show vlan brief\r"
expect "#"

send "echo !!! IP INTERFACE BRIEF !!!\r"
expect "#"
send "show ip interface brief\r"
expect "#"

log_file
send "exit\r"
expect eof
EOF

echo "----------------------------------------------------"
echo "Backup complete: ${BACKUP_FILE}"