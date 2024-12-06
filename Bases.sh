#!/usr/bin/env bash
#===============================================================================
# Threat Hunting / DFIR Baseline Information Gathering Script with JSON Output
# and Enhanced Interactive GUI using Whiptail
#
# This script collects a snapshot of system state and information useful for DFIR
# (Digital Forensics & Incident Response) and Threat Hunting activities.
# It outputs the collected data in JSON format and provides both a terminal-based
# interactive menu and a Whiptail-based GUI for users to view and interact with
# specific sections.
#
# Data collected:
#   - System metadata (hostname, OS version, uptime)
#   - User/account data (who is logged in, last logins, environment variables)
#   - Process data (ps -eo user,pid,command and pstree)
#   - Network data (ss/netstat output, iptables rules, routing, interfaces)
#   - Filesystem data (mounts, df)
#   - Kernel modules, sysctl configs
#   - Logs from /var/log
#
# Usage:
#   sudo bash ./Bases.sh
#
# Always review this script before running to ensure it meets your needs.
#===============================================================================

set -euo pipefail

#------------------------------#
#        COLOR DEFINITIONS     #
#------------------------------#
# Reset
RESET='\033[0m'

# Regular Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'

# Bold
BOLD='\033[1m'

# Underline
UNDERLINE='\033[4m'

#------------------------------#
#        CONFIGURATION         #
#------------------------------#

# Use a timestamp format without colons to avoid issues with tar.
TIMESTAMP=$(date +%F_%H-%M-%S)
OUTPUT_DIR="dfir_baseline_${TIMESTAMP}"
JSON_FILE="${OUTPUT_DIR}.json"
LOGS_DIR="${OUTPUT_DIR}/logs"

mkdir -p "${OUTPUT_DIR}"
mkdir -p "${LOGS_DIR}"

printf "${GREEN}[*] Gathering baseline data into ${OUTPUT_DIR} ...${RESET}\n"

# Initialize JSON file
echo "{" > "${JSON_FILE}"

# Function to append JSON sections
append_json_section() {
    local section_name="$1"
    local section_content="$2"

    echo "  \"${section_name}\": {" >> "${JSON_FILE}"
    echo "${section_content}" >> "${JSON_FILE}"
    echo "  }," >> "${JSON_FILE}"
}

#------------------------------#
#        SYSTEM METADATA       #
#------------------------------#
printf "${BLUE}[*] Collecting system metadata...${RESET}\n"
HOSTNAME=$(hostname)
OS_INFO=$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
UNAME=$(uname -a)
UPTIME=$(uptime -p)
DATE_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Escape double quotes in variables
HOSTNAME_ESCAPED=$(echo "${HOSTNAME}" | sed 's/"/\\"/g')
OS_INFO_ESCAPED=$(echo "${OS_INFO}" | sed 's/"/\\"/g')
UNAME_ESCAPED=$(echo "${UNAME}" | sed 's/"/\\"/g')
UPTIME_ESCAPED=$(echo "${UPTIME}" | sed 's/"/\\"/g')
DATE_TIME_ESCAPED=$(echo "${DATE_TIME}" | sed 's/"/\\"/g')

SYSTEM_INFO=$(cat <<EOF
            "hostname": "${HOSTNAME_ESCAPED}",
            "os_info": "${OS_INFO_ESCAPED}",
            "uname": "${UNAME_ESCAPED}",
            "uptime": "${UPTIME_ESCAPED}",
            "date_time": "${DATE_TIME_ESCAPED}"
EOF
)

append_json_section "system_metadata" "${SYSTEM_INFO}"

#------------------------------#
#          USER DATA           #
#------------------------------#
printf "${BLUE}[*] Collecting user and login information...${RESET}\n"

# Current Users
CURRENT_USERS=$(who | awk '{print "\"" $1 "\""}' | paste -sd "," - | sed 's/^/[/' | sed 's/$/]/')

# Last Logins
LAST_LOGINS=$(last -n 20 | awk 'NR>0 {gsub(/"/, "\\\""); print "\"" $0 "\""}' | paste -sd "," - | sed 's/^/[/' | sed 's/$/]/')

# Environment Variables
ENV_VARS=$(env | awk -F= '{gsub(/"/, "\\\""); print "    \"" $1 "\": \"" $2 "\""}' | paste -sd ",\n" -)

USER_INFO=$(cat <<EOF
            "current_users": ${CURRENT_USERS},
            "last_logins": ${LAST_LOGINS},
            "environment_variables": {
        ${ENV_VARS}
            }
EOF
)

append_json_section "user_info" "${USER_INFO}"

#------------------------------#
#         PROCESS DATA         #
#------------------------------#
printf "${BLUE}[*] Collecting process information...${RESET}\n"

# Initialize the processes array
process_info_content=""
process_info_content+="\"processes\": [\n"

# Check if 'ps' command exists
if ! command -v ps >/dev/null 2>&1; then
    printf "${YELLOW}[!] ps command not found. Skipping process listing.${RESET}\n"
    process_info_content+="],\n\"process_tree\": \"ps command not found.\""
    append_json_section "process_info" "${process_info_content}"
else
    # Collect processes using ps
    while IFS= read -r user pid cpu command; do
        # Escape backslashes and double quotes in USER and COMMAND
        user_escaped=$(printf '%s' "$user" | sed 's/\\/\\\\/g; s/"/\\"/g')
        cmd_escaped=$(printf '%s' "$command" | sed 's/\\/\\\\/g; s/"/\\"/g')

        # Append the process object to the array
        process_info_content+="{ \"USER\": \"${user_escaped}\", \"PID\": ${pid}, \"CPU\": \"${cpu}\", \"COMMAND\": \"${cmd_escaped}\" },\n"
    done < <(ps -eo user,pid,pcpu,command --no-headers)

    # Remove the trailing comma and newline
    process_info_content=$(echo "${process_info_content}" | sed '$ s/,$//')

    # Close the processes array
    process_info_content+="\n],\n"

    # Collect Process Tree using pstree -p, check if pstree exists
    if command -v pstree >/dev/null 2>&1; then
        PSTREE_OUTPUT=$(pstree -p | head -n 100)
    else
        PSTREE_OUTPUT="pstree command not found."
    fi

    # Escape backslashes and double quotes, and replace newlines with \n for JSON compatibility
    PSTREE_OUTPUT_ESCAPED=$(echo "${PSTREE_OUTPUT}" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba;s/\n/\\n/g')

    # Append the process_tree to the JSON section
    process_info_content+="\"process_tree\": \"${PSTREE_OUTPUT_ESCAPED}\""

    # Append to JSON
    append_json_section "process_info" "${process_info_content}"
fi

#------------------------------#
#        NETWORK DATA          #
#------------------------------#
printf "${BLUE}[*] Collecting network information...${RESET}\n"

# Network Interfaces
NET_INTERFACES=$(ip addr show | awk '
    BEGIN {print "["}
    /^[0-9]+: / {
        if (iface != "") {
            if (ip_count > 0) {
                print "      ]"
            }
            print "    },"
        }
        iface = $2
        gsub(/:/, "", iface)
        print "    { \"interface\": \"" iface "\", \"addresses\": ["
        ip_count = 0
    }
    /inet / {
        gsub(/\/.*/, "", $2)
        if (ip_count > 0) {
            print "      , \"" $2 "\""
        } else {
            print "      \"" $2 "\""
            ip_count++
        }
    }
    END {
        if (iface != "") {
            if (ip_count > 0) {
                print "      ]"
            }
            print "    }"
        }
        print "  ]"
    }
')

# Routing Table
ROUTE_TABLE=$(ip route show | awk 'BEGIN {print "["}
    {gsub(/"/, "\\\""); print "    { \"route\": \"" $0 "\" },"
    }
    END {print "  ]"}' | sed '$ s/,$//')

# Active Connections
if command -v ss >/dev/null 2>&1; then
    ACTIVE_CONNECTIONS=$(ss -tulpn | awk 'NR>1 {gsub(/"/, "\\\""); print "\"" $0 "\""}' | paste -sd "," - | sed 's/^/[/' | sed 's/$/]/')
elif command -v netstat >/dev/null 2>&1; then
    ACTIVE_CONNECTIONS=$(netstat -tulpn | awk 'NR>2 {gsub(/"/, "\\\""); print "\"" $0 "\""}' | paste -sd "," - | sed 's/^/[/' | sed 's/$/]/')
else
    ACTIVE_CONNECTIONS="\"Neither ss nor netstat command found.\""
fi

# iptables Rules
if command -v iptables >/dev/null 2>&1; then
    IPTABLES_RULES=$(iptables -L -n -v 2>/dev/null | awk 'BEGIN {print "["}
        {gsub(/"/, "\\\""); print "\"" $0 "\""} 
        END {print "]"}')
else
    IPTABLES_RULES="\"iptables command not found.\""
fi

NETWORK_INFO=$(cat <<EOF
            "network_info": {
                "network_interfaces": ${NET_INTERFACES},
                "routing_table": ${ROUTE_TABLE},
                "active_connections": ${ACTIVE_CONNECTIONS},
                "iptables_rules": ${IPTABLES_RULES}
            }
EOF
)

append_json_section "network_info" "${NETWORK_INFO}"

#------------------------------#
#       FILESYSTEM DATA        #
#------------------------------#
printf "${BLUE}[*] Collecting filesystem information...${RESET}\n"

# Mounted Filesystems
MOUNTS=$(mount | awk 'BEGIN {print "["}
    {gsub(/"/, "\\\""); print "\"" $0 "\""} 
    END {print "]"}')

# Disk Usage
DF_OUTPUT=$(df -h | awk 'NR>1 {gsub(/"/, "\\\""); gsub(/%/, "", $5); printf "    { \"filesystem\": \"%s\", \"size\": \"%s\", \"used\": \"%s\", \"avail\": \"%s\", \"use%%\": \"%s\", \"mounted_on\": \"%s\" },\n", $1, $2, $3, $4, $5, $6}')
# Remove trailing comma and wrap in array
DF_OUTPUT=$(echo "[${DF_OUTPUT%,}]")

FILESYSTEM_INFO=$(cat <<EOF
            "filesystem_info": {
                "mounted_filesystems": ${MOUNTS},
                "disk_usage": ${DF_OUTPUT}
            }
EOF
)

append_json_section "filesystem_info" "${FILESYSTEM_INFO}"

#------------------------------#
#      KERNEL & SYSTEM CONF    #
#------------------------------#
printf "${BLUE}[*] Collecting kernel and system configuration...${RESET}\n"

# Kernel Modules
if command -v lsmod >/dev/null 2>&1; then
    KERNEL_MODULES=$(lsmod | awk 'BEGIN {print "["}
        NR>1 {
            gsub(/"/, "\\\"")
            printf "    { \"module\": \"%s\", \"size\": %s, \"used_by\": \"%s\" },\n", $1, $2, $3
        }
        END {print "]"}' | sed '$ s/,$//')
else
    KERNEL_MODULES="\"lsmod command not found.\""
fi

# sysctl Configuration
if command -v sysctl >/dev/null 2>&1; then
    SYSCTL_CONFIG=$(sysctl -a 2>/dev/null | awk -F= '{gsub(/ /, "", $1); gsub(/"/, "\\\""); gsub(/"/, "\\\"", $2); printf "    \"%s\": \"%s\",\n", $1, $2}' | sed '$ s/,$//')
else
    SYSCTL_CONFIG="\"sysctl command not found.\""
fi

KERNEL_SYSCTL_INFO=$(cat <<EOF
            "kernel_sysctl_info": {
                "kernel_modules": ${KERNEL_MODULES},
                "sysctl_configuration": {
            ${SYSCTL_CONFIG}
                }
            }
EOF
)

append_json_section "kernel_sysctl_info" "${KERNEL_SYSCTL_INFO}"

#------------------------------#
#        LOG COLLECTION        #
#------------------------------#
printf "${BLUE}[*] Collecting logs from /var/log...${RESET}\n"
# Optimize log collection by excluding large or irrelevant files
# Only archive essential log files to prevent hanging
LOG_FILES_TO_ARCHIVE=(
    "/var/log/syslog"
    "/var/log/auth.log"
    "/var/log/kern.log"
    "/var/log/dmesg"
    "/var/log/boot.log"
    "/var/log/faillog"
    "/var/log/wtmp"
    "/var/log/btmp"
    # Add more essential log files as needed
)

# Create a directory to copy selected log files
mkdir -p "${LOGS_DIR}/selected_logs"

# Copy selected log files
for log_file in "${LOG_FILES_TO_ARCHIVE[@]}"; do
    if [ -f "${log_file}" ]; then
        cp --parents "${log_file}" "${LOGS_DIR}/selected_logs/" 2>/dev/null || printf "${YELLOW}[!] Failed to copy ${log_file}.${RESET}\n"
    else
        printf "${YELLOW}[!] Log file ${log_file} does not exist.${RESET}\n"
    fi
done

# Compress the copied logs to save space
if command -v tar >/dev/null 2>&1; then
    tar -czf "${LOGS_DIR}/logs.tar.gz" -C "${LOGS_DIR}" selected_logs 2>/dev/null || printf "${YELLOW}[!] Failed to archive some log files.${RESET}\n"
else
    printf "${YELLOW}[!] tar command not found. Skipping log archiving.${RESET}\n"
fi

# Add log path to JSON
LOG_INFO=$(cat <<EOF
            "logs": {
                "logs_archive": "${LOGS_DIR}/logs.tar.gz"
            }
EOF
)

append_json_section "logs" "${LOG_INFO}"

# Remove trailing comma from the last section
sed -i '$ s/,$//' "${JSON_FILE}"

# Close JSON object
echo "}" >> "${JSON_FILE}"

printf "${GREEN}[*] JSON baseline data collected in ${JSON_FILE}.${RESET}\n"

#------------------------------#
#        INTERACTIVE MENU      #
#------------------------------#
# Function to clear the terminal
clear_screen() {
    clear
}

# Function to investigate logs for anomalies
investigate_logs() {
    printf "${GREEN}[*] Investigating logs for anomalies...${RESET}\n"
    # Define patterns for anomalies (case-insensitive)
    ANOMALY_PATTERNS=("error" "fail" "warning" "denied" "unauthorized" "critical" "exception" "segfault" "panic")

    # Create a temporary directory for extracted logs
    TEMP_LOG_DIR=$(mktemp -d)
    tar -xzf "${LOGS_DIR}/logs.tar.gz" -C "${TEMP_LOG_DIR}" 2>/dev/null || {
        printf "${RED}[!] Failed to extract logs for investigation.${RESET}\n"
        rm -rf "${TEMP_LOG_DIR}"
        return
    }

    # Iterate through log files and search for anomalies
    printf "${YELLOW}Searching for anomalies in log files...${RESET}\n"
    for log_file in "${TEMP_LOG_DIR}/selected_logs/"*; do
        if [ -f "${log_file}" ]; then
            printf "${CYAN}Analyzing ${log_file}...${RESET}\n"
            # Handle compressed log files
            if [[ "${log_file}" == *.gz ]]; then
                zcat "${log_file}" 2>/dev/null | while IFS= read -r line; do
                    for pattern in "${ANOMALY_PATTERNS[@]}"; do
                        if echo "$line" | grep -iq "${pattern}"; then
                            # Highlight the pattern in red
                            highlighted_line=$(echo "$line" | sed -E "s/(${pattern})/${RED}\1${RESET}/Ig")
                            printf "${RED}Anomaly Detected:${RESET} ${highlighted_line}\n"
                        fi
                    done
                done
            else
                while IFS= read -r line; do
                    for pattern in "${ANOMALY_PATTERNS[@]}"; do
                        if echo "$line" | grep -iq "${pattern}"; then
                            # Highlight the pattern in red
                            highlighted_line=$(echo "$line" | sed -E "s/(${pattern})/${RED}\1${RESET}/Ig")
                            printf "${RED}Anomaly Detected:${RESET} ${highlighted_line}\n"
                        fi
                    done
                done < "${log_file}"
            fi
        fi
    done

    # Clean up temporary directory
    rm -rf "${TEMP_LOG_DIR}"
    printf "${GREEN}[*] Log investigation completed.${RESET}\n"
}

# Function to display a section in the interactive menu
display_section() {
    local section="$1"
    case "${section}" in
        system_metadata)
            echo -e "${MAGENTA}┌───────────────────────────────┐${RESET}"
            echo -e "${MAGENTA}│       System Metadata         │${RESET}"
            echo -e "${MAGENTA}└───────────────────────────────┘${RESET}"
            # Extract and format system_metadata
            sed -n '/"system_metadata": {/,/^  },/p' "${JSON_FILE}" | \
            sed -E 's/.*"hostname": "(.*)",/\1/' | \
            sed -E 's/.*"os_info": "(.*)",/\1/' | \
            sed -E 's/.*"uname": "(.*)",/\1/' | \
            sed -E 's/.*"uptime": "(.*)",/\1/' | \
            sed -E 's/.*"date_time": "(.*)"/\1/' | \
            awk -v GREEN="${GREEN}" -v RESET="${RESET}" '
                BEGIN {print ""}
                {
                    if (NR==1) print GREEN"- Hostname: "RESET $0
                    else if (NR==2) print GREEN"- OS Info: "RESET $0
                    else if (NR==3) print GREEN"- Uname: "RESET $0
                    else if (NR==4) print GREEN"- Uptime: "RESET $0
                    else if (NR==5) print GREEN"- Date Time: "RESET $0
                }
            '
            ;;
        user_info)
            echo -e "${MAGENTA}┌───────────────────────────────┐${RESET}"
            echo -e "${MAGENTA}│        User Information       │${RESET}"
            echo -e "${MAGENTA}└───────────────────────────────┘${RESET}"
            # Extract and format user_info
            sed -n '/"user_info": {/,/^  },/p' "${JSON_FILE}" | \
            sed -E 's/"current_users": \[(.*)\],/\1/' | \
            sed -E 's/"last_logins": \[(.*)\],/\1/' | \
            sed -n '/"environment_variables": {/,/    }/p' | \
            sed -E 's/"([^"]+)": "([^"]+)",?/\1: \2/' | \
            awk -v GREEN="${GREEN}" -v RESET="${RESET}" '
                BEGIN {
                    print ""
                    print GREEN"- Current Users:" RESET
                }
                {
                    # Split by comma and print each user
                    n = split($0, users, ",")
                    for(i=1;i<=n;i++) {
                        gsub(/"/, "", users[i])
                        print "    * " users[i]
                    }
                }
                END {
                    print ""
                    print GREEN"- Last Logins:" RESET
                    n = split($0, logins, ",")
                    for(i=1;i<=n;i++) {
                        gsub(/"/, "", logins[i])
                        print "    * " logins[i]
                    }
                    print ""
                    print GREEN"- Environment Variables:" RESET
                }
                /environment_variables/ {
                    next
                }
                {
                    # Environment variables
                    print "    * " $0
                }
            '
            ;;
        network_info)
            echo -e "${MAGENTA}┌───────────────────────────────┐${RESET}"
            echo -e "${MAGENTA}│        Network Information     │${RESET}"
            echo -e "${MAGENTA}└───────────────────────────────┘${RESET}"
            # Extract and format network_info
            sed -n '/"network_info": {/,/^  },/p' "${JSON_FILE}" | \
            sed 's/"network_interfaces": \[/&\n/' | \
            sed 's/"routing_table": \[/&\n/' | \
            sed 's/"active_connections": \[/&\n/' | \
            sed 's/"iptables_rules": \[/&\n/' | \
            awk -v GREEN="${GREEN}" -v RESET="${RESET}" '
                BEGIN {
                    print ""
                    print GREEN"- Network Interfaces:" RESET
                }
                /{ "interface":/ {
                    gsub(/"/, "", $0)
                    split($0, arr, ": ")
                    iface = arr[2]
                    print "    * Interface: " iface
                }
                /"addresses": \[/ {
                    print "        Addresses:"
                }
                /"/ {
                    gsub(/"/, "", $0)
                    gsub(/,/, "", $0)
                    if ($0 != "],") {
                        print "            - " $0
                    }
                }
            '

            # Routing Table
            printf "\n${GREEN}- Routing Table:${RESET}\n"
            sed -n '/"routing_table": \[/,/  \]/p' "${JSON_FILE}" | \
            grep -o '{ "route": "[^"]*" }' | \
            sed 's/{ "route": "\(.*\)" }/\1/' | \
            awk -v GREEN="${GREEN}" -v RESET="${RESET}" '{
                printf "    * %s\n", $0
            }'

            # Active Connections
            printf "\n${GREEN}- Active Connections:${RESET}\n"
            sed -n '/"active_connections": \[/,/  \]/p' "${JSON_FILE}" | \
            grep -o '"[^"]*"' | \
            sed 's/"//g' | \
            awk -v GREEN="${GREEN}" -v RESET="${RESET}" '{
                printf "    * %s\n", $0
            }'

            # iptables Rules
            printf "\n${GREEN}- iptables Rules:${RESET}\n"
            sed -n '/"iptables_rules": \[/,/  \]/p' "${JSON_FILE}" | \
            grep -o '"[^"]*"' | \
            sed 's/"//g' | \
            awk -v GREEN="${GREEN}" -v RESET="${RESET}" '{
                printf "    * %s\n", $0
            }'
            ;;
        filesystem_info)
            echo -e "${MAGENTA}┌───────────────────────────────┐${RESET}"
            echo -e "${MAGENTA}│      Filesystem Information   │${RESET}"
            echo -e "${MAGENTA}└───────────────────────────────┘${RESET}"
            # Extract and format filesystem_info
            sed -n '/"filesystem_info": {/,/^  },/p' "${JSON_FILE}" | \
            sed 's/"mounted_filesystems": \[/&\n/' | \
            sed 's/"disk_usage": \[/&\n/' | \
            sed 's/  \],/  ],/' | \
            awk -v GREEN="${GREEN}" -v RESET="${RESET}" '
                BEGIN {
                    print ""
                    print GREEN"- Mounted Filesystems:" RESET
                }
                /"mounted_filesystems": \[/ {
                    next
                }
                /"/ && !/"mounted_filesystems": \[/ && !/"disk_usage": \[/ {
                    gsub(/"/, "", $0)
                    gsub(/,/, "", $0)
                    print "    * " $0
                }
                /"disk_usage": \[/ {
                    print ""
                    print GREEN"- Disk Usage:" RESET
                }
                /"/ && /"disk_usage": \[/ {
                    next
                }
                /{ "filesystem":/ {
                    gsub(/"/, "", $0)
                    gsub(/,/, "", $0)
                    split($0, arr, ", ")
                    filesystem=""
                    size=""
                    used=""
                    avail=""
                    usep=""
                    mounted_on=""
                    for(i=1;i<=length(arr);i++) {
                        split(arr[i], kv, ": ")
                        key = kv[1]
                        value = kv[2]
                        if (key == "filesystem") filesystem = value
                        else if (key == "size") size = value
                        else if (key == "used") used = value
                        else if (key == "avail") avail = value
                        else if (key == "use%") usep = value
                        else if (key == "mounted_on") mounted_on = value
                    }
                    printf "    * Filesystem: %s\n      Size: %s\n      Used: %s\n      Available: %s\n      Use%%: %s\n      Mounted on: %s\n\n", filesystem, size, used, avail, usep, mounted_on
                }
            '
            ;;
        kernel_sysctl_info)
            echo -e "${MAGENTA}┌───────────────────────────────┐${RESET}"
            echo -e "${MAGENTA}│   Kernel & Sysctl Information  │${RESET}"
            echo -e "${MAGENTA}└───────────────────────────────┘${RESET}"
            # Extract and format kernel_sysctl_info
            sed -n '/"kernel_sysctl_info": {/,/^  },/p' "${JSON_FILE}" | \
            sed 's/"kernel_modules": \[/&\n/' | \
            sed 's/"sysctl_configuration": {/&\n/' | \
            awk -v GREEN="${GREEN}" -v RESET="${RESET}" '
                BEGIN {
                    print ""
                    print GREEN"- Kernel Modules:" RESET
                }
                /{ "module":/ {
                    gsub(/"/, "", $0)
                    split($0, arr, ", ")
                    module=""
                    size=""
                    used_by=""
                    for(i=1;i<=length(arr);i++) {
                        split(arr[i], kv, ": ")
                        key = kv[1]
                        value = kv[2]
                        if (key == "module") module = value
                        else if (key == "size") size = value
                        else if (key == "used_by") used_by = value
                    }
                    print "    * Module: " module
                    print "      Size: " size
                    print "      Used by: " used_by "\n"
                }
                /"sysctl_configuration": {/ {
                    print "\nSysctl Configuration:"
                }
                /"[^"]+": "/ {
                    gsub(/"/, "", $0)
                    split($0, arr, ": ")
                    key = arr[1]
                    value = arr[2]
                    print "    * " key ": " value
                }
            '
            ;;
        logs)
            echo -e "${MAGENTA}┌───────────────────────────────┐${RESET}"
            echo -e "${MAGENTA}│             Logs              │${RESET}"
            echo -e "${MAGENTA}└───────────────────────────────┘${RESET}"
            printf "${CYAN}Logs have been archived at: ${LOGS_DIR}/logs.tar.gz${RESET}\n"

            # Option to investigate logs
            if whiptail --title "Log Investigation" --yesno "Would you like to investigate logs for anomalies?" 10 60; then
                investigate_logs
            fi
            ;;
        clear)
            clear_screen
            ;;
        *)
            printf "${RED}[!] Invalid section.${RESET}\n"
            ;;
    esac
}

# Function to display Process Information (Removed from Interactive and GUI Menus)
display_process_info() {
    # This function has been removed as per the requirement.
    # All process information operations are now handled within the File Operations Submenu.
    :
}

#------------------------------#
#        WHIPTAIL GUI           #
#------------------------------#

# Function for Disk and Memory Operations Submenu
disk_memory_operations_menu() {
    while true; do
        DISK_MEMORY_MENU=$(whiptail --title "Disk and Memory Operations" --menu "Choose an operation" 20 80 12 \
            "1" "List Disk Partitions (fdisk -l)" \
            "2" "Create Disk Image (dd if=... of=...)" \
            "3" "Dump Memory (dd if=/dev/mem of=...)" \
            "4" "Dump Kernel Memory (dd if=/dev/kmem of=...)" \
            "5" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_dm=$?
        if [ $exitstatus_dm -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $DISK_MEMORY_MENU in
            "1")
                # List Disk Partitions
                if command -v fdisk >/dev/null 2>&1; then
                    OUTPUT=$(fdisk -l 2>&1 | head -n 100)  # Limit output
                else
                    OUTPUT="fdisk command not found."
                fi
                # Create a temporary file
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                # Display using whiptail
                whiptail --title "Disk Partitions" --scrolltext --textbox "${TEMP_FILE}" 30 120
                # Remove the temporary file
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # Create Disk Image
                SOURCE=$(whiptail --inputbox "Enter the source device (e.g., /dev/sda1):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_src=$?
                if [ $exitstatus_src -ne 0 ] || [ -z "${SOURCE}" ]; then
                    continue
                fi

                DESTINATION=$(whiptail --inputbox "Enter the destination path (e.g., /path/to/image.img):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_dst=$?
                if [ $exitstatus_dst -ne 0 ] || [ -z "${DESTINATION}" ]; then
                    continue
                fi

                # Confirm action
                if whiptail --title "Confirm" --yesno "Are you sure you want to create a disk image from ${SOURCE} to ${DESTINATION}?" 10 60; then
                    if command -v dd >/dev/null 2>&1; then
                        # Use whiptail's gauge to show progress
                        (
                            dd if="${SOURCE}" of="${DESTINATION}" bs=4M status=none &
                            PID=$!
                            while kill -0 $PID 2>/dev/null; do
                                sleep 1
                                echo "# Creating disk image..."
                            done
                        ) | whiptail --title "Creating Disk Image" --gauge "Please wait..." 10 70 0
                        if [ $? -eq 0 ]; then
                            whiptail --title "Success" --msgbox "Disk image created successfully at ${DESTINATION}." 8 60
                        else
                            whiptail --title "Error" --msgbox "Failed to create disk image." 8 60
                        fi
                    else
                        whiptail --title "Error" --msgbox "dd command not found." 8 60
                    fi
                else
                    whiptail --title "Cancelled" --msgbox "Disk image creation cancelled." 8 60
                fi
                ;;
            "3")
                # Dump Memory
                DESTINATION=$(whiptail --inputbox "Enter the destination path for memory dump (e.g., /root/mem_dump.img):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_mem=$?
                if [ $exitstatus_mem -ne 0 ] || [ -z "${DESTINATION}" ]; then
                    continue
                fi

                # Confirm action
                if whiptail --title "Confirm" --yesno "Are you sure you want to dump memory to ${DESTINATION}?" 10 60; then
                    if command -v dd >/dev/null 2>&1; then
                        # Use whiptail's gauge to show progress
                        (
                            dd if=/dev/mem of="${DESTINATION}" bs=1M status=none &
                            PID=$!
                            while kill -0 $PID 2>/dev/null; do
                                sleep 1
                                echo "# Dumping memory..."
                            done
                        ) | whiptail --title "Dumping Memory" --gauge "Please wait..." 10 70 0
                        if [ $? -eq 0 ]; then
                            whiptail --title "Success" --msgbox "Memory dumped successfully to ${DESTINATION}." 8 60
                        else
                            whiptail --title "Error" --msgbox "Failed to dump memory." 8 60
                        fi
                    else
                        whiptail --title "Error" --msgbox "dd command not found." 8 60
                    fi
                else
                    whiptail --title "Cancelled" --msgbox "Memory dump cancelled." 8 60
                fi
                ;;
            "4")
                # Dump Kernel Memory
                DESTINATION=$(whiptail --inputbox "Enter the destination path for kernel memory dump (e.g., /root/kmem_dump.img):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_kmem=$?
                if [ $exitstatus_kmem -ne 0 ] || [ -z "${DESTINATION}" ]; then
                    continue
                fi

                # Confirm action
                if whiptail --title "Confirm" --yesno "Are you sure you want to dump kernel memory to ${DESTINATION}?" 10 60; then
                    if command -v dd >/dev/null 2>&1; then
                        # Use whiptail's gauge to show progress
                        (
                            dd if=/dev/kmem of="${DESTINATION}" bs=1M status=none &
                            PID=$!
                            while kill -0 $PID 2>/dev/null; do
                                sleep 1
                                echo "# Dumping kernel memory..."
                            done
                        ) | whiptail --title "Dumping Kernel Memory" --gauge "Please wait..." 10 70 0
                        if [ $? -eq 0 ]; then
                            whiptail --title "Success" --msgbox "Kernel memory dumped successfully to ${DESTINATION}." 8 60
                        else
                            whiptail --title "Error" --msgbox "Failed to dump kernel memory." 8 60
                        fi
                    else
                        whiptail --title "Error" --msgbox "dd command not found." 8 60
                    fi
                else
                    whiptail --title "Cancelled" --msgbox "Kernel memory dump cancelled." 8 60
                fi
                ;;
            "5")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 5." 8 60
                ;;
        esac
    done
}

# Function for System Information Submenu
system_information_menu() {
    while true; do
        SYSTEM_INFO_MENU=$(whiptail --title "System Information" --menu "Choose an operation" 25 80 20 \
            "1" "Display Date" \
            "2" "Display Uname Information" \
            "3" "Display Hostname" \
            "4" "Display OS Version (lsb_release -a)" \
            "5" "Display /proc/version" \
            "6" "Display Loaded Kernel Modules (lsmod)" \
            "7" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_si=$?
        if [ $exitstatus_si -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $SYSTEM_INFO_MENU in
            "1")
                # Display Date
                OUTPUT=$(date)
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Current Date and Time" --textbox "${TEMP_FILE}" 10 60
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # Display Uname Information
                OUTPUT=$(uname -a)
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Uname Information" --textbox "${TEMP_FILE}" 10 80
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # Display Hostname
                OUTPUT=$(hostname)
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Hostname" --textbox "${TEMP_FILE}" 10 40
                rm -f "${TEMP_FILE}"
                ;;
            "4")
                # Display OS Version
                if command -v lsb_release >/dev/null 2>&1; then
                    OUTPUT=$(lsb_release -a 2>/dev/null)
                else
                    OUTPUT=$(cat /etc/os-release 2>/dev/null || echo "OS information not available.")
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "OS Version" --textbox "${TEMP_FILE}" 15 80
                rm -f "${TEMP_FILE}"
                ;;
            "5")
                # Display /proc/version
                if [ -f /proc/version ]; then
                    OUTPUT=$(cat /proc/version)
                else
                    OUTPUT="File /proc/version does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "/proc/version" --textbox "${TEMP_FILE}" 10 80
                rm -f "${TEMP_FILE}"
                ;;
            "6")
                # Display Loaded Kernel Modules
                if command -v lsmod >/dev/null 2>&1; then
                    OUTPUT=$(lsmod | head -n 100)  # Limit output
                else
                    OUTPUT="lsmod command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Loaded Kernel Modules" --textbox "${TEMP_FILE}" 20 100
                rm -f "${TEMP_FILE}"
                ;;
            "7")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 7." 8 60
                ;;
        esac
    done
}

# Function for Account Information Submenu
account_information_menu() {
    while true; do
        ACCOUNT_INFO_MENU=$(whiptail --title "Account Information" --menu "Choose an operation" 30 80 20 \
            "1" "View /etc/passwd" \
            "2" "View /etc/shadow" \
            "3" "View /etc/sudoers" \
            "4" "View /etc/sudoers.d/*" \
            "5" "List All Usernames (cut /etc/passwd)" \
            "6" "List All Usernames (getent passwd)" \
            "7" "List All Usernames (compgen -u)" \
            "8" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_ai=$?
        if [ $exitstatus_ai -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $ACCOUNT_INFO_MENU in
            "1")
                # View /etc/passwd
                if [ -f /etc/passwd ]; then
                    OUTPUT=$(cat /etc/passwd | head -n 100)  # Limit output
                else
                    OUTPUT="/etc/passwd does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "/etc/passwd" --scrolltext --textbox "${TEMP_FILE}" 20 100
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # View /etc/shadow
                if [ -f /etc/shadow ]; then
                    OUTPUT=$(cat /etc/shadow | head -n 100)  # Limit output
                else
                    OUTPUT="/etc/shadow does not exist or access is denied."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "/etc/shadow" --scrolltext --textbox "${TEMP_FILE}" 20 100
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # View /etc/sudoers
                if [ -f /etc/sudoers ]; then
                    OUTPUT=$(cat /etc/sudoers | head -n 100)  # Limit output
                else
                    OUTPUT="/etc/sudoers does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "/etc/sudoers" --scrolltext --textbox "${TEMP_FILE}" 20 100
                rm -f "${TEMP_FILE}"
                ;;
            "4")
                # View /etc/sudoers.d/*
                if ls /etc/sudoers.d/* >/dev/null 2>&1; then
                    OUTPUT=$(cat /etc/sudoers.d/* | head -n 100)  # Limit output
                else
                    OUTPUT="No files found in /etc/sudoers.d/."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "/etc/sudoers.d/*" --scrolltext --textbox "${TEMP_FILE}" 20 100
                rm -f "${TEMP_FILE}"
                ;;
            "5")
                # List All Usernames (cut /etc/passwd)
                if [ -f /etc/passwd ]; then
                    OUTPUT=$(cut -d: -f1 /etc/passwd | head -n 100)
                else
                    OUTPUT="/etc/passwd does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "List of Usernames (cut /etc/passwd)" --textbox "${TEMP_FILE}" 20 60
                rm -f "${TEMP_FILE}"
                ;;
            "6")
                # List All Usernames (getent passwd)
                if command -v getent >/dev/null 2>&1; then
                    OUTPUT=$(getent passwd | cut -d: -f1 | head -n 100)
                else
                    OUTPUT="getent command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "List of Usernames (getent passwd)" --textbox "${TEMP_FILE}" 20 60
                rm -f "${TEMP_FILE}"
                ;;
            "7")
                # List All Usernames (compgen -u)
                if command -v compgen >/dev/null 2>&1; then
                    OUTPUT=$(compgen -u | head -n 100)
                else
                    OUTPUT="compgen command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "List of Usernames (compgen -u)" --textbox "${TEMP_FILE}" 20 60
                rm -f "${TEMP_FILE}"
                ;;
            "8")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 8." 8 60
                ;;
        esac
    done
}

# Function for Scheduled Tasks Submenu
scheduled_tasks_menu() {
    while true; do
        SCHEDULED_TASKS_MENU=$(whiptail --title "Scheduled Tasks" --menu "Choose an operation" 25 80 20 \
            "1" "List /etc/cron.* Directories" \
            "2" "List /etc/cron.*/* Files" \
            "3" "View /etc/crontab" \
            "4" "View User Crontabs (crontab -l)" \
            "5" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_st=$?
        if [ $exitstatus_st -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $SCHEDULED_TASKS_MENU in
            "1")
                # List /etc/cron.* Directories
                OUTPUT=$(ls /etc/cron.* 2>/dev/null | head -n 100)
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No cron directories found in /etc/cron.*."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "List of /etc/cron.* Directories" --textbox "${TEMP_FILE}" 15 60
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # List /etc/cron.*/* Files
                OUTPUT=$(ls /etc/cron.*/* 2>/dev/null | head -n 100)
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No files found in /etc/cron.*/*."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "List of /etc/cron.*/* Files" --textbox "${TEMP_FILE}" 20 80
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # View /etc/crontab
                if [ -f /etc/crontab ]; then
                    OUTPUT=$(cat /etc/crontab | head -n 100)  # Limit output
                else
                    OUTPUT="/etc/crontab does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "/etc/crontab" --scrolltext --textbox "${TEMP_FILE}" 20 80
                rm -f "${TEMP_FILE}"
                ;;
            "4")
                # View User Crontabs
                if command -v crontab >/dev/null 2>&1; then
                    OUTPUT=$(crontab -l 2>/dev/null | head -n 100 || echo "No crontab for current user.")
                else
                    OUTPUT="crontab command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "User Crontabs" --scrolltext --textbox "${TEMP_FILE}" 20 80
                rm -f "${TEMP_FILE}"
                ;;
            "5")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 5." 8 60
                ;;
        esac
    done
}

# Function for SSH Keys and Authorized Users Submenu
ssh_keys_menu() {
    while true; do
        SSH_KEYS_MENU=$(whiptail --title "SSH Keys and Authorized Users" --menu "Choose an operation" 25 80 20 \
            "1" "View /etc/ssh/sshd_config" \
            "2" "List SSH Keys in Home Directories" \
            "3" "View Public SSH Keys" \
            "4" "View Authorized Keys" \
            "5" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_sk=$?
        if [ $exitstatus_sk -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $SSH_KEYS_MENU in
            "1")
                # View /etc/ssh/sshd_config
                if [ -f /etc/ssh/sshd_config ]; then
                    OUTPUT=$(cat /etc/ssh/sshd_config | head -n 100)  # Limit output
                else
                    OUTPUT="/etc/ssh/sshd_config does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "/etc/ssh/sshd_config" --scrolltext --textbox "${TEMP_FILE}" 20 80
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # List SSH Keys in Home Directories
                OUTPUT=$(find /home/*/.ssh/ -type f 2>/dev/null | head -n 100)
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No SSH keys found in home directories."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "SSH Keys in Home Directories" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # View Public SSH Keys
                OUTPUT=$(find /home/*/.ssh/id_rsa.pub 2>/dev/null | xargs cat 2>/dev/null || echo "No public SSH keys found." | head -n 100)
                if [ "$(echo "${OUTPUT}" | wc -l)" -gt 100 ]; then
                    OUTPUT=$(echo "${OUTPUT}" | head -n 100)
                    OUTPUT+="\n\nNote: Displaying the first 100 lines."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Public SSH Keys" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "4")
                # View Authorized Keys
                OUTPUT=$(find /home/*/.ssh/authorized_keys 2>/dev/null | xargs cat 2>/dev/null || echo "No authorized_keys found." | head -n 100)
                if [ "$(echo "${OUTPUT}" | wc -l)" -gt 100 ]; then
                    OUTPUT=$(echo "${OUTPUT}" | head -n 100)
                    OUTPUT+="\n\nNote: Displaying the first 100 lines."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Authorized SSH Keys" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "5")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 5." 8 60
                ;;
        esac
    done
}

# Function for Network Information Submenu
network_information_menu() {
    while true; do
        NETWORK_INFO_MENU=$(whiptail --title "Network Information" --menu "Choose an operation" 30 80 20 \
            "1" "List Network Interfaces (ifconfig -a)" \
            "2" "List Network Interfaces (ip addr show)" \
            "3" "Display Network Connections (netstat -apetul)" \
            "4" "Display Network Connections (ss -apetul)" \
            "5" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_ni=$?
        if [ $exitstatus_ni -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $NETWORK_INFO_MENU in
            "1")
                # List Network Interfaces using ifconfig -a
                if command -v ifconfig >/dev/null 2>&1; then
                    OUTPUT=$(ifconfig -a 2>&1 | head -n 100)  # Limit output
                else
                    OUTPUT="ifconfig command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Network Interfaces (ifconfig -a)" --scrolltext --textbox "${TEMP_FILE}" 25 120
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # List Network Interfaces using ip addr show
                if command -v ip >/dev/null 2>&1; then
                    OUTPUT=$(ip addr show 2>&1 | head -n 100)  # Limit output
                else
                    OUTPUT="ip command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Network Interfaces (ip addr show)" --scrolltext --textbox "${TEMP_FILE}" 25 120
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # Display Network Connections using netstat
                if command -v netstat >/dev/null 2>&1; then
                    OUTPUT=$(netstat -apetul 2>&1 | head -n 100)  # Limit output
                else
                    OUTPUT="netstat command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Network Connections (netstat -apetul)" --scrolltext --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "4")
                # Display Network Connections using ss
                if command -v ss >/dev/null 2>&1; then
                    OUTPUT=$(ss -apetul 2>&1 | head -n 100)  # Limit output
                else
                    OUTPUT="ss command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Network Connections (ss -apetul)" --scrolltext --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "5")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 5." 8 60
                ;;
        esac
    done
}

# Function for DNS Queries Submenu
dns_queries_menu() {
    while true; do
        DNS_QUERIES_MENU=$(whiptail --title "DNS Queries" --menu "Choose an operation" 35 80 20 \
            "1" "Query A Record" \
            "2" "Query ANY Record" \
            "3" "Query NS Record" \
            "4" "Query SOA Record" \
            "5" "Query HINFO Record" \
            "6" "Query TXT Record" \
            "7" "Short Query" \
            "8" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_dq=$?
        if [ $exitstatus_dq -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $DNS_QUERIES_MENU in
            "1"|"2"|"3"|"4"|"5"|"6"|"7")
                # Prompt for domain name
                DOMAIN=$(whiptail --inputbox "Enter the domain name (e.g., www.google.com):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_dom=$?
                if [ $exitstatus_dom -ne 0 ] || [ -z "${DOMAIN}" ]; then
                    continue
                fi

                # Determine the query type
                case $DNS_QUERIES_MENU in
                    "1")
                        QUERY_TYPE="a"
                        ;;
                    "2")
                        QUERY_TYPE="any"
                        ;;
                    "3")
                        QUERY_TYPE="ns"
                        ;;
                    "4")
                        QUERY_TYPE="soa"
                        ;;
                    "5")
                        QUERY_TYPE="hinfo"
                        ;;
                    "6")
                        QUERY_TYPE="txt"
                        ;;
                    "7")
                        QUERY_TYPE="+short"
                        ;;
                esac

                # Check if dig command exists
                if ! command -v dig >/dev/null 2>&1; then
                    OUTPUT="dig command not found."
                else
                    # Execute the dig command with output limits and sanitization
                    if [[ "${QUERY_TYPE}" == "+short" ]]; then
                        OUTPUT=$(dig ${QUERY_TYPE} "${DOMAIN}" 2>&1 | head -n 100)
                    else
                        OUTPUT=$(dig ${QUERY_TYPE} "${DOMAIN}" 2>&1 | head -n 100)
                        OUTPUT+="\n\nNote: Displaying the first 100 lines."
                    fi
                fi

                # Sanitize output to prevent Whiptail crashes
                OUTPUT_SANITIZED=$(echo -e "${OUTPUT}" | sed 's/\\/\\\\/g; s/"/\\"/g')

                # Create a temporary file
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT_SANITIZED}" > "${TEMP_FILE}"

                # Display using whiptail with scrolltext to handle large outputs
                whiptail --title "DNS Query: dig ${QUERY_TYPE} ${DOMAIN}" --scrolltext --textbox "${TEMP_FILE}" 30 120

                # Remove the temporary file
                rm -f "${TEMP_FILE}"
                ;;
            "8")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 8." 8 60
                ;;
        esac
    done
}

# Function for iptables Information Submenu
iptables_information_menu() {
    while true; do
        IPTABLES_MENU=$(whiptail --title "iptables Information" --menu "Choose an operation" 20 80 20 \
            "1" "List IPv4 iptables Rules (iptables -L -n -v)" \
            "2" "List IPv6 iptables Rules (ip6tables -L -n -v)" \
            "3" "View iptables Configuration Files" \
            "4" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_ip=$?
        if [ $exitstatus_ip -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $IPTABLES_MENU in
            "1")
                # List IPv4 iptables Rules
                if command -v iptables >/dev/null 2>&1; then
                    OUTPUT=$(iptables -L -n -v 2>/dev/null | head -n 100)  # Limit output
                else
                    OUTPUT="iptables command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "IPv4 iptables Rules" --scrolltext --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # List IPv6 iptables Rules
                if command -v ip6tables >/dev/null 2>&1; then
                    OUTPUT=$(ip6tables -L -n -v 2>/dev/null | head -n 100)  # Limit output
                else
                    OUTPUT="ip6tables command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "IPv6 iptables Rules" --scrolltext --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # View iptables Configuration Files
                if ls /etc/iptables/*.v4 >/dev/null 2>&1; then
                    OUTPUT=$(cat /etc/iptables/*.v4 2>/dev/null | head -n 100)  # Limit output
                else
                    OUTPUT="No iptables configuration files found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "iptables Configuration Files" --scrolltext --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "4")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 4." 8 60
                ;;
        esac
    done
}

# Function for Network Configuration Submenu
network_configuration_menu() {
    while true; do
        NETWORK_CONFIG_MENU=$(whiptail --title "Network Configuration" --menu "Choose an operation" 25 80 20 \
            "1" "Display All Network Interfaces (ifconfig -a)" \
            "2" "Display All Network Interfaces (ip addr show)" \
            "3" "Compare Two Files (diff)" \
            "4" "Find Hidden Directories and Files" \
            "5" "Find Immutable Files and Directories" \
            "6" "Find SUID/SGID and Sticky Bit Files" \
            "7" "Find Files with No User/Group" \
            "8" "Find Executables on File System" \
            "9" "Find Hidden Executables on File System" \
            "10" "Find Files Modified Within Past Day" \
            "11" "Find Files for a Particular User" \
            "12" "View Pluggable Authentication Modules (PAM) Configuration" \
            "13" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_nc=$?
        if [ $exitstatus_nc -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $NETWORK_CONFIG_MENU in
            "1")
                # Display All Network Interfaces (ifconfig -a)
                if command -v ifconfig >/dev/null 2>&1; then
                    OUTPUT=$(ifconfig -a 2>&1 | head -n 100)  # Limit output
                else
                    OUTPUT="ifconfig command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Network Interfaces (ifconfig -a)" --scrolltext --textbox "${TEMP_FILE}" 25 120
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # Display All Network Interfaces (ip addr show)
                if command -v ip >/dev/null 2>&1; then
                    OUTPUT=$(ip addr show 2>&1 | head -n 100)  # Limit output
                else
                    OUTPUT="ip command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Network Interfaces (ip addr show)" --scrolltext --textbox "${TEMP_FILE}" 25 120
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # Compare Two Files (diff)
                FILE1=$(whiptail --inputbox "Enter the path for the first file:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_f1=$?
                if [ $exitstatus_f1 -ne 0 ] || [ -z "${FILE1}" ]; then
                    continue
                fi

                FILE2=$(whiptail --inputbox "Enter the path for the second file:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_f2=$?
                if [ $exitstatus_f2 -ne 0 ] || [ -z "${FILE2}" ]; then
                    continue
                fi

                if [ ! -f "${FILE1}" ] || [ ! -f "${FILE2}" ]; then
                    whiptail --title "Error" --msgbox "One or both files do not exist." 8 60
                    continue
                fi

                if command -v diff >/dev/null 2>&1; then
                    OUTPUT=$(diff "${FILE1}" "${FILE2}" 2>&1 || echo "Differences above.")
                else
                    OUTPUT="diff command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Difference Between ${FILE1} and ${FILE2}" --scrolltext --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "4")
                # Find Hidden Directories and Files
                if command -v find >/dev/null 2>&1; then
                    OUTPUT=$(find / -name ".*" -type d 2>/dev/null | head -n 100)
                else
                    OUTPUT="find command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No hidden directories or files found."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Hidden Directories and Files" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "5")
                # Find Immutable Files and Directories
                if command -v lsattr >/dev/null 2>&1; then
                    OUTPUT=$(lsattr / -R 2>/dev/null | grep "\----i" | head -n 100)
                else
                    OUTPUT="lsattr command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No immutable files or directories found."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Immutable Files and Directories" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "6")
                # Find SUID/SGID and Sticky Bit Files
                if command -v find >/dev/null 2>&1; then
                    OUTPUT=$(find / -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \; 2>/dev/null | head -n 100)
                else
                    OUTPUT="find command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No SUID/SGID or Sticky Bit files found."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "SUID/SGID and Sticky Bit Files" --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "7")
                # Find Files with No User/Group
                if command -v find >/dev/null 2>&1; then
                    OUTPUT=$(find / \( -nouser -o -nogroup \) -exec ls -lg {} \; 2>/dev/null | head -n 100)
                else
                    OUTPUT="find command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No files with no user/group found."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Files with No User/Group" --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "8")
                # Find Executables on File System
                if command -v find >/dev/null 2>&1 && command -v file >/dev/null 2>&1; then
                    OUTPUT=$(find / -type f -exec file -p '{}' \; | grep ELF | head -n 100)
                else
                    OUTPUT="find or file command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No ELF executables found."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "ELF Executables on File System" --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "9")
                # Find Hidden Executables on File System
                if command -v find >/dev/null 2>&1 && command -v file >/dev/null 2>&1; then
                    OUTPUT=$(find / -name ".*" -type f -exec file -p '{}' \; | grep ELF | head -n 100)
                else
                    OUTPUT="find or file command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No hidden ELF executables found."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Hidden ELF Executables on File System" --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "10")
                # Find Files Modified Within Past Day
                if command -v find >/dev/null 2>&1; then
                    OUTPUT=$(find / -mtime -1 2>/dev/null | head -n 100)
                else
                    OUTPUT="find command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No files modified within the past day."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Files Modified Within Past Day" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "11")
                # Find Files for a Particular User
                USERNAME=$(whiptail --inputbox "Enter the username to search for:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_user=$?
                if [ $exitstatus_user -ne 0 ] || [ -z "${USERNAME}" ]; then
                    continue
                fi

                if command -v find >/dev/null 2>&1; then
                    OUTPUT=$(find /home/ -user "${USERNAME}" -type f 2>/dev/null | head -n 100)
                else
                    OUTPUT="find command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No files found for user ${USERNAME}."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Files for User ${USERNAME}" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "12")
                # View Pluggable Authentication Modules (PAM) Configuration
                if [ -f /etc/pam.d/sudo ]; then
                    OUTPUT=$(cat /etc/pam.d/sudo | head -n 100)  # Limit output
                else
                    OUTPUT="/etc/pam.d/sudo does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "PAM Configuration (/etc/pam.d/sudo)" --scrolltext --textbox "${TEMP_FILE}" 20 80
                rm -f "${TEMP_FILE}"
                ;;
            "13")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 13." 8 60
                ;;
        esac
    done
}

# Function for File Operations Submenu
file_operations_menu() {
    while true; do
        FILE_OPERATIONS_MENU=$(whiptail --title "File Operations" --menu "Choose an operation" 35 80 20 \
            "1" "Decode Base64 Encoded File" \
            "2" "Find IPs Making Most Requests in Access Log" \
            "3" "Count of Unique IPs in Access Log" \
            "4" "List Unique User Agents in Access Log" \
            "5" "Most Requested URLs for POST Requests in Access Log" \
            "6" "Find Strings in a File" \
            "7" "Find Strings in a File (binary)" \
            "8" "Find Executable File Paths" \
            "9" "Find Hidden Directories and Files" \
            "10" "Process Information Operations" \
            "11" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_fo=$?
        if [ $exitstatus_fo -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $FILE_OPERATIONS_MENU in
            "1")
                # Decode Base64 Encoded File
                INPUT_FILE=$(whiptail --inputbox "Enter the path of the Base64 encoded file:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_in=$?
                if [ $exitstatus_in -ne 0 ] || [ -z "${INPUT_FILE}" ]; then
                    continue
                fi

                DESTINATION=$(whiptail --inputbox "Enter the destination path for decoded file:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_dest=$?
                if [ $exitstatus_dest -ne 0 ] || [ -z "${DESTINATION}" ]; then
                    continue
                fi

                if [ ! -f "${INPUT_FILE}" ]; then
                    whiptail --title "Error" --msgbox "Input file does not exist." 8 60
                    continue
                fi

                if command -v base64 >/dev/null 2>&1; then
                    if base64 -d "${INPUT_FILE}" > "${DESTINATION}" 2>/dev/null; then
                        whiptail --title "Success" --msgbox "File decoded successfully to ${DESTINATION}." 8 60
                    else
                        whiptail --title "Error" --msgbox "Failed to decode the file." 8 60
                    fi
                else
                    whiptail --title "Error" --msgbox "base64 command not found." 8 60
                fi
                ;;
            "2")
                # Find IPs Making Most Requests in Access Log
                ACCESS_LOG=$(whiptail --inputbox "Enter the path to the access log (e.g., /var/log/apache2/access.log):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_al=$?
                if [ $exitstatus_al -ne 0 ] || [ -z "${ACCESS_LOG}" ]; then
                    continue
                fi

                if [ ! -f "${ACCESS_LOG}" ]; then
                    whiptail --title "Error" --msgbox "Access log file does not exist." 8 60
                    continue
                fi

                if command -v cut >/dev/null 2>&1 && command -v sort >/dev/null 2>&1 && command -v uniq >/dev/null 2>&1; then
                    OUTPUT=$(cut -d " " -f 1 "${ACCESS_LOG}" | sort | uniq -c | sort -nr | head -n 20)
                else
                    OUTPUT="Required commands (cut, sort, uniq) not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Top 20 IPs Making Most Requests" --textbox "${TEMP_FILE}" 25 80
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # Count of Unique IPs in Access Log
                ACCESS_LOG=$(whiptail --inputbox "Enter the path to the access log (e.g., /var/log/apache2/access.log):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_alc=$?
                if [ $exitstatus_alc -ne 0 ] || [ -z "${ACCESS_LOG}" ]; then
                    continue
                fi

                if [ ! -f "${ACCESS_LOG}" ]; then
                    whiptail --title "Error" --msgbox "Access log file does not exist." 8 60
                    continue
                fi

                if command -v cut >/dev/null 2>&1 && command -v sort >/dev/null 2>&1 && command -v uniq >/dev/null 2>&1 && command -v wc >/dev/null 2>&1; then
                    COUNT=$(cut -d " " -f 1 "${ACCESS_LOG}" | sort -u | wc -l)
                else
                    COUNT="Required commands (cut, sort, uniq, wc) not found."
                fi
                whiptail --title "Unique IP Count" --msgbox "Total Unique IPs: ${COUNT}" 8 60
                ;;
            "4")
                # List Unique User Agents in Access Log
                ACCESS_LOG=$(whiptail --inputbox "Enter the path to the access log (e.g., /var/log/apache2/access.log):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_uag=$?
                if [ $exitstatus_uag -ne 0 ] || [ -z "${ACCESS_LOG}" ]; then
                    continue
                fi

                if [ ! -f "${ACCESS_LOG}" ]; then
                    whiptail --title "Error" --msgbox "Access log file does not exist." 8 60
                    continue
                fi

                if command -v awk >/dev/null 2>&1 && command -v sort >/dev/null 2>&1 && command -v uniq >/dev/null 2>&1; then
                    OUTPUT=$(awk -F\" '{print $6}' "${ACCESS_LOG}" | sort -u | head -n 1000)
                    if [ "$(echo "${OUTPUT}" | wc -l)" -gt 1000 ]; then
                        OUTPUT=$(echo "${OUTPUT}" | head -n 1000)
                        OUTPUT+="\n\nNote: Displaying the first 1000 lines."
                    fi
                else
                    OUTPUT="Required commands (awk, sort, uniq) not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Unique User Agents" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "5")
                # Most Requested URLs for POST Requests in Access Log
                ACCESS_LOG=$(whiptail --inputbox "Enter the path to the access log (e.g., /var/log/apache2/access.log):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_mpurl=$?
                if [ $exitstatus_mpurl -ne 0 ] || [ -z "${ACCESS_LOG}" ]; then
                    continue
                fi

                if [ ! -f "${ACCESS_LOG}" ]; then
                    whiptail --title "Error" --msgbox "Access log file does not exist." 8 60
                    continue
                fi

                if command -v awk >/dev/null 2>&1 && command -v grep >/dev/null 2>&1 && command -v sort >/dev/null 2>&1 && command -v uniq >/dev/null 2>&1; then
                    OUTPUT=$(awk -F\" '{print $2}' "${ACCESS_LOG}" | grep "POST" | sort | uniq -c | sort -nr | head -n 20)
                else
                    OUTPUT="Required commands (awk, grep, sort, uniq) not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Top 20 Most Requested URLs for POST" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "6")
                # Find Strings in a File
                INPUT_FILE=$(whiptail --inputbox "Enter the path of the file to search for strings:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_sf=$?
                if [ $exitstatus_sf -ne 0 ] || [ -z "${INPUT_FILE}" ]; then
                    continue
                fi

                if [ ! -f "${INPUT_FILE}" ]; then
                    whiptail --title "Error" --msgbox "File does not exist." 8 60
                    continue
                fi

                if command -v strings >/dev/null 2>&1; then
                    # Limit output to prevent GUI from crashing
                    OUTPUT=$(strings "${INPUT_FILE}" | head -n 1000)
                else
                    OUTPUT="strings command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Strings in ${INPUT_FILE}" --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "7")
                # Find Strings in a File (binary)
                INPUT_FILE=$(whiptail --inputbox "Enter the path of the binary file to search for strings:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_sb=$?
                if [ $exitstatus_sb -ne 0 ] || [ -z "${INPUT_FILE}" ]; then
                    continue
                fi

                if [ ! -f "${INPUT_FILE}" ]; then
                    whiptail --title "Error" --msgbox "File does not exist." 8 60
                    continue
                fi

                if command -v strings >/dev/null 2>&1; then
                    # Limit output to prevent GUI from crashing
                    OUTPUT=$(strings -e b "${INPUT_FILE}" | head -n 1000)
                else
                    OUTPUT="strings command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Strings (Binary) in ${INPUT_FILE}" --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "8")
                # Find Executable File Paths
                if command -v find >/dev/null 2>&1 && command -v file >/dev/null 2>&1; then
                    OUTPUT=$(find / -type f -exec file -p '{}' \; | grep ELF | head -n 100)
                else
                    OUTPUT="find or file command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No ELF executables found."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "ELF Executables on File System" --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "9")
                # Find Hidden Directories and Files
                if command -v find >/dev/null 2>&1; then
                    OUTPUT=$(find / -name ".*" -type d 2>/dev/null | head -n 100)
                else
                    OUTPUT="find command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No hidden directories or files found."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Hidden Directories and Files" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "10")
                # Process Information Operations Submenu
                process_information_submenu
                ;;
            "11")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 11." 8 60
                ;;
        esac
    done
}

# Function for Process Information Submenu within File Operations
process_information_submenu() {
    while true; do
        PROCESS_INFO_MENU=$(whiptail --title "Process Information Operations" --menu "Choose an option" 20 80 10 \
            "1" "Full Process List" \
            "2" "Process Tree" \
            "3" "Return to File Operations Menu" 3>&1 1>&2 2>&3)

        exitstatus_pi=$?
        if [ $exitstatus_pi -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $PROCESS_INFO_MENU in
            "1")
                # Full Process List
                if command -v ps >/dev/null 2>&1; then
                    OUTPUT=$(ps -eo user,pid,pcpu,command --no-headers | head -n 100)
                else
                    OUTPUT="ps command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Full Process List" --scrolltext --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # Process Tree
                if command -v pstree >/dev/null 2>&1; then
                    OUTPUT=$(pstree -p | head -n 100)
                else
                    OUTPUT="pstree command not found."
                fi
                # Escape backslashes and double quotes
                OUTPUT_ESCAPED=$(echo "${OUTPUT}" | sed 's/\\/\\\\/g; s/"/\\"/g')
                # Replace newlines with \n for JSON compatibility
                OUTPUT_ESCAPED=$(echo -e "${OUTPUT_ESCAPED}" | sed ':a;N;$!ba;s/\n/\\n/g')
                # Display in a temporary file
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT_ESCAPED}" > "${TEMP_FILE}"
                whiptail --title "Process Tree" --scrolltext --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # Return to File Operations Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 3." 8 60
                ;;
        esac
    done
}

# Function for Logs Investigation Submenu
logs_investigation_menu() {
    while true; do
        LOGS_INVESTIGATION_MENU=$(whiptail --title "Logs Investigation" --menu "Choose an operation" 20 80 20 \
            "1" "List All Logs in /var/log" \
            "2" "Analyze btmp with utmpdump" \
            "3" "Analyze utmp with utmpdump" \
            "4" "Analyze wtmp with utmpdump" \
            "5" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_li=$?
        if [ $exitstatus_li -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $LOGS_INVESTIGATION_MENU in
            "1")
                # List All Logs in /var/log
                if command -v ls >/dev/null 2>&1; then
                    OUTPUT=$(ls -al /var/log/* 2>/dev/null | head -n 100)
                else
                    OUTPUT="ls command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No logs found in /var/log."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "List of Logs in /var/log" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # Analyze btmp with utmpdump
                if [ -f /var/log/btmp ]; then
                    if command -v utmpdump >/dev/null 2>&1; then
                        OUTPUT=$(utmpdump /var/log/btmp 2>/dev/null || echo "Failed to analyze /var/log/btmp.")
                    else
                        OUTPUT="utmpdump command not found."
                    fi
                else
                    OUTPUT="/var/log/btmp does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Analyze btmp with utmpdump" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # Analyze utmp with utmpdump
                if [ -f /var/run/utmp ]; then
                    if command -v utmpdump >/dev/null 2>&1; then
                        OUTPUT=$(utmpdump /var/run/utmp 2>/dev/null || echo "Failed to analyze /var/run/utmp.")
                    else
                        OUTPUT="utmpdump command not found."
                    fi
                else
                    OUTPUT="/var/run/utmp does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Analyze utmp with utmpdump" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "4")
                # Analyze wtmp with utmpdump
                if [ -f /var/log/wtmp ]; then
                    if command -v utmpdump >/dev/null 2>&1; then
                        OUTPUT=$(utmpdump /var/log/wtmp 2>/dev/null || echo "Failed to analyze /var/log/wtmp.")
                    else
                        OUTPUT="utmpdump command not found."
                    fi
                else
                    OUTPUT="/var/log/wtmp does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Analyze wtmp with utmpdump" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "5")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 5." 8 60
                ;;
        esac
    done
}

# Function for File Operations Submenu
file_operations_menu() {
    while true; do
        FILE_OPERATIONS_MENU=$(whiptail --title "File Operations" --menu "Choose an operation" 35 80 20 \
            "1" "Decode Base64 Encoded File" \
            "2" "Find IPs Making Most Requests in Access Log" \
            "3" "Count of Unique IPs in Access Log" \
            "4" "List Unique User Agents in Access Log" \
            "5" "Most Requested URLs for POST Requests in Access Log" \
            "6" "Find Strings in a File" \
            "7" "Find Strings in a File (binary)" \
            "8" "Find Executable File Paths" \
            "9" "Find Hidden Directories and Files" \
            "10" "Process Information Operations" \
            "11" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_fo=$?
        if [ $exitstatus_fo -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $FILE_OPERATIONS_MENU in
            "1")
                # Decode Base64 Encoded File
                INPUT_FILE=$(whiptail --inputbox "Enter the path of the Base64 encoded file:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_in=$?
                if [ $exitstatus_in -ne 0 ] || [ -z "${INPUT_FILE}" ]; then
                    continue
                fi

                DESTINATION=$(whiptail --inputbox "Enter the destination path for decoded file:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_dest=$?
                if [ $exitstatus_dest -ne 0 ] || [ -z "${DESTINATION}" ]; then
                    continue
                fi

                if [ ! -f "${INPUT_FILE}" ]; then
                    whiptail --title "Error" --msgbox "Input file does not exist." 8 60
                    continue
                fi

                if command -v base64 >/dev/null 2>&1; then
                    if base64 -d "${INPUT_FILE}" > "${DESTINATION}" 2>/dev/null; then
                        whiptail --title "Success" --msgbox "File decoded successfully to ${DESTINATION}." 8 60
                    else
                        whiptail --title "Error" --msgbox "Failed to decode the file." 8 60
                    fi
                else
                    whiptail --title "Error" --msgbox "base64 command not found." 8 60
                fi
                ;;
            "2")
                # Find IPs Making Most Requests in Access Log
                ACCESS_LOG=$(whiptail --inputbox "Enter the path to the access log (e.g., /var/log/apache2/access.log):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_al=$?
                if [ $exitstatus_al -ne 0 ] || [ -z "${ACCESS_LOG}" ]; then
                    continue
                fi

                if [ ! -f "${ACCESS_LOG}" ]; then
                    whiptail --title "Error" --msgbox "Access log file does not exist." 8 60
                    continue
                fi

                if command -v cut >/dev/null 2>&1 && command -v sort >/dev/null 2>&1 && command -v uniq >/dev/null 2>&1; then
                    OUTPUT=$(cut -d " " -f 1 "${ACCESS_LOG}" | sort | uniq -c | sort -nr | head -n 20)
                else
                    OUTPUT="Required commands (cut, sort, uniq) not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Top 20 IPs Making Most Requests" --textbox "${TEMP_FILE}" 25 80
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # Count of Unique IPs in Access Log
                ACCESS_LOG=$(whiptail --inputbox "Enter the path to the access log (e.g., /var/log/apache2/access.log):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_alc=$?
                if [ $exitstatus_alc -ne 0 ] || [ -z "${ACCESS_LOG}" ]; then
                    continue
                fi

                if [ ! -f "${ACCESS_LOG}" ]; then
                    whiptail --title "Error" --msgbox "Access log file does not exist." 8 60
                    continue
                fi

                if command -v cut >/dev/null 2>&1 && command -v sort >/dev/null 2>&1 && command -v uniq >/dev/null 2>&1 && command -v wc >/dev/null 2>&1; then
                    COUNT=$(cut -d " " -f 1 "${ACCESS_LOG}" | sort -u | wc -l)
                else
                    COUNT="Required commands (cut, sort, uniq, wc) not found."
                fi
                whiptail --title "Unique IP Count" --msgbox "Total Unique IPs: ${COUNT}" 8 60
                ;;
            "4")
                # List Unique User Agents in Access Log
                ACCESS_LOG=$(whiptail --inputbox "Enter the path to the access log (e.g., /var/log/apache2/access.log):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_uag=$?
                if [ $exitstatus_uag -ne 0 ] || [ -z "${ACCESS_LOG}" ]; then
                    continue
                fi

                if [ ! -f "${ACCESS_LOG}" ]; then
                    whiptail --title "Error" --msgbox "Access log file does not exist." 8 60
                    continue
                fi

                if command -v awk >/dev/null 2>&1 && command -v sort >/dev/null 2>&1 && command -v uniq >/dev/null 2>&1; then
                    OUTPUT=$(awk -F\" '{print $6}' "${ACCESS_LOG}" | sort -u | head -n 1000)
                    if [ "$(echo "${OUTPUT}" | wc -l)" -gt 1000 ]; then
                        OUTPUT=$(echo "${OUTPUT}" | head -n 1000)
                        OUTPUT+="\n\nNote: Displaying the first 1000 lines."
                    fi
                else
                    OUTPUT="Required commands (awk, sort, uniq) not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Unique User Agents" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "5")
                # Most Requested URLs for POST Requests in Access Log
                ACCESS_LOG=$(whiptail --inputbox "Enter the path to the access log (e.g., /var/log/apache2/access.log):" 10 60 3>&1 1>&2 2>&3)
                exitstatus_mpurl=$?
                if [ $exitstatus_mpurl -ne 0 ] || [ -z "${ACCESS_LOG}" ]; then
                    continue
                fi

                if [ ! -f "${ACCESS_LOG}" ]; then
                    whiptail --title "Error" --msgbox "Access log file does not exist." 8 60
                    continue
                fi

                if command -v awk >/dev/null 2>&1 && command -v grep >/dev/null 2>&1 && command -v sort >/dev/null 2>&1 && command -v uniq >/dev/null 2>&1; then
                    OUTPUT=$(awk -F\" '{print $2}' "${ACCESS_LOG}" | grep "POST" | sort | uniq -c | sort -nr | head -n 20)
                else
                    OUTPUT="Required commands (awk, grep, sort, uniq) not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Top 20 Most Requested URLs for POST" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "6")
                # Find Strings in a File
                INPUT_FILE=$(whiptail --inputbox "Enter the path of the file to search for strings:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_sf=$?
                if [ $exitstatus_sf -ne 0 ] || [ -z "${INPUT_FILE}" ]; then
                    continue
                fi

                if [ ! -f "${INPUT_FILE}" ]; then
                    whiptail --title "Error" --msgbox "File does not exist." 8 60
                    continue
                fi

                if command -v strings >/dev/null 2>&1; then
                    # Limit output to prevent GUI from crashing
                    OUTPUT=$(strings "${INPUT_FILE}" | head -n 1000)
                else
                    OUTPUT="strings command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Strings in ${INPUT_FILE}" --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "7")
                # Find Strings in a File (binary)
                INPUT_FILE=$(whiptail --inputbox "Enter the path of the binary file to search for strings:" 10 60 3>&1 1>&2 2>&3)
                exitstatus_sb=$?
                if [ $exitstatus_sb -ne 0 ] || [ -z "${INPUT_FILE}" ]; then
                    continue
                fi

                if [ ! -f "${INPUT_FILE}" ]; then
                    whiptail --title "Error" --msgbox "File does not exist." 8 60
                    continue
                fi

                if command -v strings >/dev/null 2>&1; then
                    # Limit output to prevent GUI from crashing
                    OUTPUT=$(strings -e b "${INPUT_FILE}" | head -n 1000)
                else
                    OUTPUT="strings command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Strings (Binary) in ${INPUT_FILE}" --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "8")
                # Find Executable File Paths
                if command -v find >/dev/null 2>&1 && command -v file >/dev/null 2>&1; then
                    OUTPUT=$(find / -type f -exec file -p '{}' \; | grep ELF | head -n 100)
                else
                    OUTPUT="find or file command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No ELF executables found."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "ELF Executables on File System" --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "9")
                # Find Hidden Directories and Files
                if command -v find >/dev/null 2>&1; then
                    OUTPUT=$(find / -name ".*" -type d 2>/dev/null | head -n 100)
                else
                    OUTPUT="find command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No hidden directories or files found."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Hidden Directories and Files" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "10")
                # Process Information Operations Submenu
                process_information_submenu
                ;;
            "11")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 11." 8 60
                ;;
        esac
    done
}

# Function for Process Information Submenu within File Operations
process_information_submenu() {
    while true; do
        PROCESS_INFO_MENU=$(whiptail --title "Process Information Operations" --menu "Choose an option" 20 80 10 \
            "1" "Full Process List" \
            "2" "Process Tree" \
            "3" "Return to File Operations Menu" 3>&1 1>&2 2>&3)

        exitstatus_pi=$?
        if [ $exitstatus_pi -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $PROCESS_INFO_MENU in
            "1")
                # Full Process List
                if command -v ps >/dev/null 2>&1; then
                    OUTPUT=$(ps -eo user,pid,pcpu,command --no-headers | head -n 100)
                else
                    OUTPUT="ps command not found."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Full Process List" --scrolltext --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # Process Tree
                if command -v pstree >/dev/null 2>&1; then
                    OUTPUT=$(pstree -p | head -n 100)
                else
                    OUTPUT="pstree command not found."
                fi
                # Escape backslashes and double quotes
                OUTPUT_ESCAPED=$(echo "${OUTPUT}" | sed 's/\\/\\\\/g; s/"/\\"/g')
                # Replace newlines with \n for JSON compatibility
                OUTPUT_ESCAPED=$(echo -e "${OUTPUT_ESCAPED}" | sed ':a;N;$!ba;s/\n/\\n/g')
                # Display in a temporary file
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT_ESCAPED}" > "${TEMP_FILE}"
                whiptail --title "Process Tree" --scrolltext --textbox "${TEMP_FILE}" 30 120
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # Return to File Operations Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 3." 8 60
                ;;
        esac
    done
}

# Function for Logs Investigation Submenu
logs_investigation_menu() {
    while true; do
        LOGS_INVESTIGATION_MENU=$(whiptail --title "Logs Investigation" --menu "Choose an operation" 20 80 20 \
            "1" "List All Logs in /var/log" \
            "2" "Analyze btmp with utmpdump" \
            "3" "Analyze utmp with utmpdump" \
            "4" "Analyze wtmp with utmpdump" \
            "5" "Return to Main GUI Menu" 3>&1 1>&2 2>&3)

        exitstatus_li=$?
        if [ $exitstatus_li -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $LOGS_INVESTIGATION_MENU in
            "1")
                # List All Logs in /var/log
                if command -v ls >/dev/null 2>&1; then
                    OUTPUT=$(ls -al /var/log/* 2>/dev/null | head -n 100)
                else
                    OUTPUT="ls command not found."
                fi
                if [ -z "${OUTPUT}" ]; then
                    OUTPUT="No logs found in /var/log."
                else
                    OUTPUT+="\n\nNote: Displaying the first 100 results."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "List of Logs in /var/log" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "2")
                # Analyze btmp with utmpdump
                if [ -f /var/log/btmp ]; then
                    if command -v utmpdump >/dev/null 2>&1; then
                        OUTPUT=$(utmpdump /var/log/btmp 2>/dev/null || echo "Failed to analyze /var/log/btmp.")
                    else
                        OUTPUT="utmpdump command not found."
                    fi
                else
                    OUTPUT="/var/log/btmp does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Analyze btmp with utmpdump" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "3")
                # Analyze utmp with utmpdump
                if [ -f /var/run/utmp ]; then
                    if command -v utmpdump >/dev/null 2>&1; then
                        OUTPUT=$(utmpdump /var/run/utmp 2>/dev/null || echo "Failed to analyze /var/run/utmp.")
                    else
                        OUTPUT="utmpdump command not found."
                    fi
                else
                    OUTPUT="/var/run/utmp does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Analyze utmp with utmpdump" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "4")
                # Analyze wtmp with utmpdump
                if [ -f /var/log/wtmp ]; then
                    if command -v utmpdump >/dev/null 2>&1; then
                        OUTPUT=$(utmpdump /var/log/wtmp 2>/dev/null || echo "Failed to analyze /var/log/wtmp.")
                    else
                        OUTPUT="utmpdump command not found."
                    fi
                else
                    OUTPUT="/var/log/wtmp does not exist."
                fi
                TEMP_FILE=$(mktemp)
                echo -e "${OUTPUT}" > "${TEMP_FILE}"
                whiptail --title "Analyze wtmp with utmpdump" --textbox "${TEMP_FILE}" 25 100
                rm -f "${TEMP_FILE}"
                ;;
            "5")
                # Return to Main GUI Menu
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid choice. Please select a number between 1 and 5." 8 60
                ;;
        esac
    done
}

# Function to launch the interactive GUI
launch_gui() {
    # Check if whiptail is installed
    if ! command -v whiptail >/dev/null 2>&1; then
        printf "${RED}[!] whiptail is not installed. Please install it using 'sudo apt-get install whiptail' and rerun the script.${RESET}\n"
        return
    fi

    while true; do
        # Whiptail Main GUI Menu
        GUI_MENU=$(whiptail --title "DFIR Baseline DFIR Triage GUI" --menu "Choose an option" 30 120 20 \
            "1" "Disk and Memory Operations" \
            "2" "System Information" \
            "3" "Account Information" \
            "4" "Scheduled Tasks" \
            "5" "SSH Keys and Authorized Users" \
            "6" "Network Information" \
            "7" "DNS Queries" \
            "8" "iptables Information" \
            "9" "Network Configuration" \
            "10" "File Operations" \
            "11" "Logs Investigation" \
            "12" "Exit" 3>&1 1>&2 2>&3)

        exitstatus=$?
        if [ $exitstatus -ne 0 ]; then
            # User selected Cancel or Esc
            break
        fi

        case $GUI_MENU in
            "1")
                # Disk and Memory Operations Submenu
                disk_memory_operations_menu
                ;;
            "2")
                # System Information Submenu
                system_information_menu
                ;;
            "3")
                # Account Information Submenu
                account_information_menu
                ;;
            "4")
                # Scheduled Tasks Submenu
                scheduled_tasks_menu
                ;;
            "5")
                # SSH Keys and Authorized Users Submenu
                ssh_keys_menu
                ;;
            "6")
                # Network Information Submenu
                network_information_menu
                ;;
            "7")
                # DNS Queries Submenu
                dns_queries_menu
                ;;
            "8")
                # iptables Information Submenu
                iptables_information_menu
                ;;
            "9")
                # Network Configuration Submenu
                network_configuration_menu
                ;;
            "10")
                # File Operations Submenu
                file_operations_menu
                ;;
            "11")
                # Logs Investigation Submenu
                logs_investigation_menu
                ;;
            "12")
                # Exit GUI
                break
                ;;
            *)
                whiptail --title "Error" --msgbox "Invalid option selected." 8 40
                ;;
        esac
    done
}

#------------------------------#
#        INTERACTIVE MENU      #
#------------------------------#
# Interactive menu loop
while true; do
    echo
    echo -e "${CYAN}===========================================${RESET}"
    echo -e "${CYAN}      ${BOLD}DFIR Baseline Interactive Menu${RESET}       ${CYAN}        "
    echo -e "${CYAN}===========================================${RESET}"
    echo -e "${YELLOW}Please select an option to view the corresponding data:${RESET}"
    echo -e "${GREEN}1)${RESET} System Metadata"
    echo -e "${GREEN}2)${RESET} User Information"
    # Removed Option 3: Process Information
    echo -e "${GREEN}3)${RESET} Network Information"
    echo -e "${GREEN}4)${RESET} Filesystem Information"
    echo -e "${GREEN}5)${RESET} Kernel & Sysctl Information"
    echo -e "${GREEN}6)${RESET} Logs"
    echo -e "${GREEN}7)${RESET} Launch GUI"
    echo -e "${GREEN}8)${RESET} Clear Screen"
    echo -e "${GREEN}9)${RESET} Exit"
    echo -e "${CYAN}===========================================${RESET}"
    read -rp "$(printf "${BOLD}Enter your choice [1-9]: ${RESET}")" choice

    case "$choice" in
        1)
            display_section "system_metadata"
            ;;
        2)
            display_section "user_info"
            ;;
        3)
            display_section "network_info"
            ;;
        4)
            display_section "filesystem_info"
            ;;
        5)
            display_section "kernel_sysctl_info"
            ;;
        6)
            display_section "logs"
            ;;
        7)
            launch_gui
            ;;
        8)
            clear_screen
            ;;
        9)
            printf "${GREEN}[*] Exiting. Thank you!${RESET}\n"
            break
            ;;
        *)
            printf "${RED}[!] Invalid choice. Please select a number between 1 and 9.${RESET}\n"
            ;;
    esac
done

exit 0
