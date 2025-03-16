#!/bin/bash

# MR Legacy - Helper Functions
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.1.0

# Colors for terminal output
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
PURPLE="\033[0;35m"
CYAN="\033[0;36m"
NC="\033[0m" # No Color

# Function to print log messages
function log_message() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    # Log to file
    if [[ -n "$target_dir" ]]; then
        mkdir -p "${target_dir}/logs" 2>/dev/null
        echo "[$timestamp] [$level] $message" >> "${target_dir}/logs/mr_legacy.log"
    fi
    
    # Also log to console with colors
    case "$level" in
        "DEBUG")
            echo -e "${BLUE}[$timestamp] [DEBUG] $message${NC}" ;;
        "INFO")
            echo -e "${GREEN}[$timestamp] [INFO] $message${NC}" ;;
        "WARNING")
            echo -e "${YELLOW}[$timestamp] [WARNING] $message${NC}" ;;
        "ERROR")
            echo -e "${RED}[$timestamp] [ERROR] $message${NC}" ;;
        "SUCCESS")
            echo -e "${CYAN}[$timestamp] [SUCCESS] $message${NC}" ;;
        "CRITICAL")
            echo -e "${PURPLE}[$timestamp] [CRITICAL] $message${NC}" ;;
        *)
            echo -e "[$timestamp] [$level] $message" ;;
    esac
}

# Function to check if a command exists
function command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if a function has already been executed (to prevent duplicate runs)
function is_completed() {
    local func_name="$1"
    
    if [[ -f "${CALLED_FN_DIR}/$func_name" ]]; then
        return 0  # Function has been completed
    else
        return 1  # Function has not been completed
    fi
}

# Function to mark a function as started
function start_function() {
    local func_name="$1"
    local display_name="${2:-$func_name}"
    
    log_message "Starting: $display_name" "INFO"
    
    # Record the start time
    echo "$(date +%s)" > "${CALLED_FN_DIR}/${func_name}.start"
}

# Function to mark a function as completed
function end_function() {
    local func_name="$1"
    local exit_code="${2:-0}"
    local display_name="${3:-$func_name}"
    
    # Record the end time and calculate duration
    if [[ -f "${CALLED_FN_DIR}/${func_name}.start" ]]; then
        local start_time=$(cat "${CALLED_FN_DIR}/${func_name}.start")
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        # Format duration for display
        local duration_formatted=$(format_duration $duration)
        
        # Remove the start time file
        rm -f "${CALLED_FN_DIR}/${func_name}.start" 2>/dev/null
    else
        local duration_formatted="unknown"
    fi
    
    if [[ "$exit_code" -eq 0 ]]; then
        log_message "Completed: $display_name (Duration: $duration_formatted)" "SUCCESS"
    else
        log_message "Failed: $display_name (Duration: $duration_formatted)" "ERROR"
    fi
    
    # Mark the function as completed
    touch "${CALLED_FN_DIR}/$func_name"
}

# Function to format duration in seconds to human-readable format
function format_duration() {
    local seconds=$1
    
    local days=$((seconds / 86400))
    local hours=$(( (seconds % 86400) / 3600 ))
    local minutes=$(( (seconds % 3600) / 60 ))
    local remaining_seconds=$((seconds % 60))
    
    local result=""
    [[ $days -gt 0 ]] && result="${days}d "
    [[ $hours -gt 0 ]] && result="${result}${hours}h "
    [[ $minutes -gt 0 ]] && result="${result}${minutes}m "
    result="${result}${remaining_seconds}s"
    
    echo "$result"
}

# Function to execute a command with timeout and retries
function execute_command() {
    local command="$1"
    local description="${2:-Command execution}"
    local timeout="${3:-300}"  # Default timeout: 5 minutes
    local max_retries="${4:-2}"  # Default retries: 2
    
    local retries=0
    local command_output="${target_dir}/.tmp/cmd_output.txt"
    mkdir -p "${target_dir}/.tmp" 2>/dev/null
    
    log_message "Executing: $description" "DEBUG"
    
    while [[ $retries -lt $max_retries ]]; do
        # Create a temporary file to store the command output
        > "$command_output"
        
        # Execute the command with timeout
        timeout --preserve-status $timeout bash -c "$command" > "$command_output" 2>&1
        local exit_code=$?
        
        # Check if the command succeeded
        if [[ $exit_code -eq 0 ]]; then
            # Success
            log_message "Command execution succeeded: $description" "DEBUG"
            return 0
        elif [[ $exit_code -eq 124 ]]; then
            # Timeout occurred
            log_message "Command timed out after ${timeout}s: $description" "WARNING"
            retries=$((retries + 1))
            
            if [[ $retries -lt $max_retries ]]; then
                log_message "Retrying ($retries/$max_retries)..." "INFO"
                sleep 2  # Small delay before retrying
            else
                log_message "Exceeded maximum retries for: $description" "ERROR"
                return 1
            fi
        else
            # Other error
            log_message "Command failed with exit code $exit_code: $description" "WARNING"
            retries=$((retries + 1))
            
            if [[ $retries -lt $max_retries ]]; then
                log_message "Retrying ($retries/$max_retries)..." "INFO"
                sleep 2  # Small delay before retrying
            else
                log_message "Exceeded maximum retries for: $description" "ERROR"
                return 1
            fi
        fi
    done
    
    return 1  # Should not reach here, but just in case
}

# Function to validate if input is a valid domain
function is_valid_domain() {
    local domain="$1"
    # Basic domain validation: contains at least one dot and only valid characters
    [[ "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})*$ ]]
}

# Function to validate if input is a valid URL
function is_valid_url() {
    local url="$1"
    # Basic URL validation
    [[ "$url" =~ ^https?://[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})*(:[0-9]{1,5})?(/.*)?$ ]]
}

# Function to validate if input is a valid IP address
function is_valid_ip() {
    local ip="$1"
    # Basic IPv4 validation
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && {
        local IFS='.'
        local -a octets=($ip)
        [[ ${octets[0]} -le 255 && ${octets[1]} -le 255 && ${octets[2]} -le 255 && ${octets[3]} -le 255 ]]
    }
}

# Function to resolve a domain to an IP address
function resolve_domain() {
    local domain="$1"
    
    # First try with dig
    if command_exists "dig"; then
        local ip=$(dig +short "$domain" | grep -v ";" | head -n 1)
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    fi
    
    # If dig fails, try with host
    if command_exists "host"; then
        local ip=$(host "$domain" | grep "has address" | head -n 1 | awk '{print $NF}')
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    fi
    
    # If host fails, try with nslookup
    if command_exists "nslookup"; then
        local ip=$(nslookup "$domain" | grep "Address:" | tail -n 1 | awk '{print $2}')
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    fi
    
    # If all else fails, try with getent
    if command_exists "getent"; then
        local ip=$(getent hosts "$domain" | awk '{print $1}')
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    fi
    
    # Last resort, try with ping (usually available on most systems)
    if command_exists "ping"; then
        local ip=$(ping -c 1 -W 1 "$domain" 2>/dev/null | head -n 1 | grep -o -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    fi
    
    # No resolution method worked
    return 1
}

# Function to check if a port is open on a host
function is_port_open() {
    local host="$1"
    local port="$2"
    local timeout="${3:-2}"  # Default timeout: 2 seconds
    
    # First try with nc
    if command_exists "nc"; then
        nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1 && return 0
    fi
    
    # If nc fails, try with telnet
    if command_exists "telnet"; then
        echo -e "\n" | telnet "$host" "$port" 2>/dev/null | grep -q "Connected" && return 0
    fi
    
    # If telnet fails, try with curl
    if command_exists "curl"; then
        curl -s --connect-timeout "$timeout" "telnet://${host}:${port}" >/dev/null 2>&1 && return 0
    fi
    
    # If all else fails, try with /dev/tcp (bash built-in)
    (echo > "/dev/tcp/${host}/${port}") >/dev/null 2>&1 && return 0
    
    # No method worked, port is likely closed
    return 1
}

# Function to URL encode a string
function url_encode() {
    local string="$1"
    local encoded=""
    local length=${#string}
    local pos c o
    
    for (( pos=0; pos<length; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9]) 
                o="$c" ;;
            *) 
                printf -v o '%%%02x' "'$c"
                ;;
        esac
        encoded+="$o"
    done
    echo "$encoded"
}

# Function to get the base domain from a domain/subdomain
function get_base_domain() {
    local domain="$1"
    
    # Remove protocol if present
    domain=$(echo "$domain" | sed 's|^https\?://||')
    
    # Remove path and query if present
    domain=$(echo "$domain" | sed 's|/.*||')
    
    # Extract the last two parts of the domain (example.com)
    echo "$domain" | grep -o '[^.]*\.[^.]*$'
}

# Function to check if a tool is installed
function is_tool_installed() {
    local tool_name="$1"
    
    # Check if the tool exists
    if command_exists "$tool_name"; then
        return 0  # Tool exists
    else
        return 1  # Tool does not exist
    fi
}

# Function to save vulnerability count to a file
function save_vuln_count() {
    local vuln_type="$1"
    local count="$2"
    
    # Ensure the directory exists
    mkdir -p "$target_dir/vulnerabilities/counts" 2>/dev/null
    
    # Save the count to a file
    echo "$count" > "$target_dir/vulnerabilities/counts/$vuln_type.count"
    
    # Log the count
    log_message "Saved vulnerability count for $vuln_type: $count" "DEBUG"
}

# Export functions for use in other scripts
export -f log_message
export -f command_exists
export -f is_completed
export -f start_function
export -f end_function
export -f format_duration
export -f execute_command
export -f is_valid_domain
export -f is_valid_url
export -f is_valid_ip
export -f resolve_domain
export -f is_port_open
export -f url_encode
export -f get_base_domain
export -f is_tool_installed
export -f save_vuln_count