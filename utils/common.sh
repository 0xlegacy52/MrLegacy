#!/bin/bash
# Common utility functions for MR Legacy Bug Bounty Tool
# Author: Abdulrahman Muhammad (0xLegacy)

# ANSI color codes for colorized output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'
UNDERLINE='\033[4m'

# Display colored log messages
# Usage: log_message "Message" "INFO|SUCCESS|WARNING|ERROR|DEBUG"
log_message() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    case "${level}" in
        "INFO")
            echo -e "[${timestamp}] ${BLUE}[INFO]${NC} ${message}"
            ;;
        "SUCCESS")
            echo -e "[${timestamp}] ${GREEN}[SUCCESS]${NC} ${message}"
            ;;
        "WARNING")
            echo -e "[${timestamp}] ${YELLOW}[WARNING]${NC} ${message}"
            ;;
        "ERROR")
            echo -e "[${timestamp}] ${RED}[ERROR]${NC} ${message}"
            ;;
        "DEBUG")
            # Only show debug messages if verbose mode is enabled
            if [[ "${verbose}" == true ]]; then
                echo -e "[${timestamp}] ${PURPLE}[DEBUG]${NC} ${message}"
            fi
            ;;
        *)
            echo -e "[${timestamp}] ${message}"
            ;;
    esac
}

# Check if a command exists
# Usage: if command_exists "nmap"; then ... fi
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Create a directory if it doesn't exist
# Usage: create_dir "/path/to/directory"
create_dir() {
    local dir="$1"
    if [[ ! -d "${dir}" ]]; then
        mkdir -p "${dir}" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_message "Created directory: ${dir}" "DEBUG"
            return 0
        else
            log_message "Failed to create directory: ${dir}" "ERROR"
            return 1
        fi
    fi
    return 0
}

# Check if a file exists
# Usage: if file_exists "/path/to/file"; then ... fi
file_exists() {
    [[ -f "$1" ]]
}

# Check if a directory exists
# Usage: if dir_exists "/path/to/directory"; then ... fi
dir_exists() {
    [[ -d "$1" ]]
}

# Check if a value is in an array
# Usage: if in_array "value" "${array[@]}"; then ... fi
in_array() {
    local needle="$1"
    shift
    local haystack=("$@")
    for item in "${haystack[@]}"; do
        if [[ "${item}" == "${needle}" ]]; then
            return 0
        fi
    done
    return 1
}

# URL encode a string
# Usage: url_encode "string with spaces and special chars"
url_encode() {
    local string="$1"
    local length="${#string}"
    local result=""
    
    for (( i = 0; i < length; i++ )); do
        local c="${string:i:1}"
        case "${c}" in
            [a-zA-Z0-9.~_-])
                result+="${c}"
                ;;
            *)
                printf -v hex '%02X' "'${c}"
                result+="%${hex}"
                ;;
        esac
    done
    
    echo "${result}"
}

# URL decode a string
# Usage: url_decode "encoded%20string"
url_decode() {
    local encoded="$1"
    local decoded=""
    
    # Replace + with space
    encoded="${encoded//+/ }"
    
    # Decode % encoding
    while [[ "${encoded}" =~ (%[0-9A-Fa-f]{2}) ]]; do
        local hex="${BASH_REMATCH[1]}"
        local char=$(printf "\x${hex:1:2}")
        encoded="${encoded/${hex}/${char}}"
    done
    
    echo "${encoded}"
}

# Generate a random string of a specific length
# Usage: random_string 10
random_string() {
    local length="${1:-10}"
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "${length}"
}

# Extract domain from URL
# Usage: extract_domain "https://subdomain.example.com/path"
extract_domain() {
    local url="$1"
    # Remove protocol (http://, https://, etc.)
    local domain="${url#*://}"
    # Remove path and query string
    domain="${domain%%/*}"
    # Remove port number if present
    domain="${domain%%:*}"
    echo "${domain}"
}

# Extract base domain from a domain (strips subdomains)
# Usage: extract_base_domain "subdomain.example.com"
extract_base_domain() {
    local domain="$1"
    
    # Try to extract using domain name pattern matching
    if [[ "${domain}" =~ ([^.]+\.[^.]+)$ ]]; then
        local base_domain="${BASH_REMATCH[1]}"
        
        # Check for common TLDs that require preserving one more level (co.uk, com.au, etc.)
        local special_tlds=("co.uk" "org.uk" "net.uk" "ac.uk" "gov.uk" "com.au" "net.au" "org.au" "com.br" "net.br" "co.jp" "co.nz")
        
        for tld in "${special_tlds[@]}"; do
            if [[ "${domain}" =~ ([^.]+\.${tld})$ ]]; then
                base_domain="${BASH_REMATCH[1]}"
                break
            fi
        done
        
        echo "${base_domain}"
    else
        # If no match (unlikely), return the original domain
        echo "${domain}"
    fi
}

# Check if the target is a valid domain or IP
# Usage: is_valid_target "example.com"
is_valid_target() {
    local target="$1"
    
    # Check if it's a valid domain
    if [[ "${target}" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    
    # Check if it's a valid IP address
    if [[ "${target}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -ra octets <<< "${target}"
        
        for octet in "${octets[@]}"; do
            if (( octet < 0 || octet > 255 )); then
                return 1
            fi
        done
        
        return 0
    fi
    
    return 1
}

# Calculate MD5 hash
# Usage: md5_hash "string"
md5_hash() {
    local input="$1"
    
    if command_exists "md5sum"; then
        echo -n "${input}" | md5sum | awk '{print $1}'
    elif command_exists "md5"; then
        echo -n "${input}" | md5
    else
        log_message "No MD5 tool found" "ERROR"
        echo ""
    fi
}

# Calculate SHA256 hash
# Usage: sha256_hash "string"
sha256_hash() {
    local input="$1"
    
    if command_exists "sha256sum"; then
        echo -n "${input}" | sha256sum | awk '{print $1}'
    elif command_exists "shasum"; then
        echo -n "${input}" | shasum -a 256 | awk '{print $1}'
    else
        log_message "No SHA256 tool found" "ERROR"
        echo ""
    fi
}

# Parse command-line arguments
# This function should be called from the main script
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                target="$2"
                shift 2
                ;;
            -o|--output)
                output_format="$2"
                shift 2
                ;;
            -T|--threads)
                threads="$2"
                shift 2
                ;;
            --tor)
                use_tor=true
                shift
                ;;
            -a|--auto)
                auto_mode=true
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -d|--deep)
                deep_scan=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_message "Unknown option: $1" "ERROR"
                show_help
                exit 1
                ;;
        esac
    done
}

# Execute a command with timeout
# Usage: execute_with_timeout "command" timeout_seconds
execute_with_timeout() {
    local cmd="$1"
    local timeout="${2:-60}"  # Default timeout: 60 seconds
    
    # Use timeout command if available
    if command_exists "timeout"; then
        timeout "${timeout}s" bash -c "${cmd}" 2>/dev/null
        return $?
    else
        # Fallback: Run the command in the background and kill it after timeout
        local pid
        local timeout_reached=false
        
        # Start the command in background
        bash -c "${cmd}" 2>/dev/null &
        pid=$!
        
        # Wait for the command to complete or timeout
        local elapsed=0
        while (( elapsed < timeout )); do
            if ! kill -0 ${pid} 2>/dev/null; then
                # Process has completed
                wait ${pid}
                return $?
            fi
            sleep 1
            ((elapsed++))
        done
        
        # If we reach here, the timeout has been reached
        kill ${pid} 2>/dev/null
        return 124  # Return 124 to indicate timeout (same as 'timeout' command)
    fi
}

# Save results to a file in the desired format (txt, json, html)
# Usage: save_results "result_data" "output_file" "format" "title"
save_results() {
    local data="$1"
    local output_file="$2"
    local format="${3:-txt}"
    local title="${4:-Scan Results}"
    
    case "${format}" in
        "txt")
            echo "${title}" > "${output_file}"
            echo "====================================" >> "${output_file}"
            echo "${data}" >> "${output_file}"
            ;;
        "json")
            # Convert to simple JSON format
            echo "{" > "${output_file}"
            echo "  \"title\": \"${title}\"," >> "${output_file}"
            echo "  \"timestamp\": \"$(date "+%Y-%m-%d %H:%M:%S")\"," >> "${output_file}"
            echo "  \"data\": [" >> "${output_file}"
            
            # Convert each line to a JSON object
            local IFS=$'\n'
            local lines=($data)
            local last_index=$((${#lines[@]} - 1))
            
            for i in "${!lines[@]}"; do
                local line="${lines[i]}"
                line="${line//\"/\\\"}"  # Escape double quotes
                
                echo -n "    {\"line\": \"${line}\"}" >> "${output_file}"
                if [[ $i -lt $last_index ]]; then
                    echo "," >> "${output_file}"
                else
                    echo "" >> "${output_file}"
                fi
            done
            
            echo "  ]" >> "${output_file}"
            echo "}" >> "${output_file}"
            ;;
        "html")
            # Create a simple HTML report
            cat > "${output_file}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1 {
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .results {
            white-space: pre-wrap;
            font-family: monospace;
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>${title}</h1>
        <p class="timestamp">Generated on $(date)</p>
        <div class="results">
$(echo "${data}" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
        </div>
    </div>
</body>
</html>
EOF
            ;;
        *)
            log_message "Unsupported output format: ${format}" "ERROR"
            return 1
            ;;
    esac
    
    log_message "Results saved to ${output_file}" "SUCCESS"
    return 0
}

# Check internet connectivity
# Usage: if check_internet; then ... fi
check_internet() {
    # Try to connect to common sites to check internet
    local test_sites=("google.com" "cloudflare.com" "1.1.1.1")
    
    for site in "${test_sites[@]}"; do
        if ping -c 1 -W 2 "${site}" >/dev/null 2>&1; then
            return 0
        fi
    done
    
    return 1
}

# Run a command with a spinner to show progress
# Usage: run_with_spinner "command" "Loading message"
run_with_spinner() {
    local cmd="$1"
    local message="${2:-Processing...}"
    local pid
    local delay=0.1
    local spinstr='|/-\'
    
    # Start the command in background
    eval "$cmd" &
    pid=$!
    
    # Display spinner while command is running
    local i=0
    printf "${message} "
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf "\b%c" "${spinstr}"
        spinstr=${temp}${spinstr%"${temp}"}
        sleep ${delay}
    done
    printf "\b \n"
    
    # Wait for the command to complete and get its return code
    wait $pid
    return $?
}

# Print a section separator for better output readability
# Usage: print_separator "Section Title"
print_separator() {
    local title="${1:-}"
    local width=50
    local line_char="-"
    
    echo ""
    if [[ -n "${title}" ]]; then
        echo -e "${BOLD}${title}${NC}"
    fi
    printf "%${width}s\n" | tr " " "${line_char}"
    echo ""
}

# Send a notification when a job is complete
# Usage: send_notification "Scan completed"
send_notification() {
    local message="$1"
    
    # Check if we're in a desktop environment with notification capabilities
    if command_exists "notify-send"; then
        notify-send "MR Legacy" "${message}"
    else
        # Fallback to terminal bell
        echo -e "\a"
        log_message "${message}" "INFO"
    fi
}

# Get the current script path
# Usage: script_path=$(get_script_path)
get_script_path() {
    local script_path
    
    # Try to get the real path of the script
    if command_exists "realpath"; then
        script_path=$(dirname "$(realpath "$0")")
    else
        # Fallback if realpath is not available
        script_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    fi
    
    echo "${script_path}"
}

# Convert seconds to a human-readable time format
# Usage: format_time 3661
format_time() {
    local seconds=$1
    local hours=$((seconds / 3600))
    local minutes=$(( (seconds % 3600) / 60 ))
    local secs=$((seconds % 60))
    
    if [[ ${hours} -gt 0 ]]; then
        printf "%02d:%02d:%02d" ${hours} ${minutes} ${secs}
    else
        printf "%02d:%02d" ${minutes} ${secs}
    fi
}

# Get the size of a file in human-readable format
# Usage: get_file_size "/path/to/file"
get_file_size() {
    local file="$1"
    
    if [[ ! -f "${file}" ]]; then
        echo "0B"
        return
    fi
    
    local size=$(stat -c %s "${file}" 2>/dev/null || stat -f %z "${file}" 2>/dev/null)
    
    if [[ -z "${size}" ]]; then
        echo "Unknown"
        return
    fi
    
    if ((size < 1024)); then
        echo "${size}B"
    elif ((size < 1048576)); then
        echo "$(( (size * 10 + 512) / 1024 / 10 ))K"
    elif ((size < 1073741824)); then
        echo "$(( (size * 10 + 524288) / 1048576 / 10 ))M"
    else
        echo "$(( (size * 10 + 536870912) / 1073741824 / 10 ))G"
    fi
}

# Check if a port is open on a host
# Usage: if is_port_open "example.com" 80; then ... fi
is_port_open() {
    local host="$1"
    local port="$2"
    local timeout="${3:-2}"
    
    # Try with netcat
    if command_exists "nc"; then
        if nc -z -w "${timeout}" "${host}" "${port}" >/dev/null 2>&1; then
            return 0
        fi
    # Try with /dev/tcp if netcat is not available (Bash only)
    elif (echo > "/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

# Check if Tor is running
# Usage: if is_tor_running; then ... fi
is_tor_running() {
    # Check if Tor proxy is running on default port 9050
    if is_port_open "127.0.0.1" 9050; then
        return 0
    fi
    
    # Also check alternate port 9150 (used by Tor Browser)
    if is_port_open "127.0.0.1" 9150; then
        return 0
    fi
    
    return 1
}

# Get the IP address of the machine
# Usage: get_local_ip
get_local_ip() {
    local ip
    
    # Try different methods to get the IP
    if command_exists "hostname"; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    elif command_exists "ip"; then
        ip=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)
    elif command_exists "ifconfig"; then
        ip=$(ifconfig | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)
    fi
    
    if [[ -n "${ip}" ]]; then
        echo "${ip}"
    else
        echo "Unknown"
    fi
}

# Get the external IP address
# Usage: get_external_ip
get_external_ip() {
    local ip
    
    # Try different services to get external IP
    for service in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com"; do
        if ip=$(curl -s "${service}"); then
            echo "${ip}"
            return 0
        fi
    done
    
    echo "Unknown"
    return 1
}

# Display results in a simple table format
# Usage: display_table "Header1,Header2,Header3" "Value1,Value2,Value3" "Value4,Value5,Value6"
display_table() {
    local headers="$1"
    shift
    
    # Split headers
    IFS=',' read -ra header_array <<< "${headers}"
    
    # Calculate column widths
    local widths=()
    for header in "${header_array[@]}"; do
        widths+=(${#header})
    done
    
    # Check data rows for wider content
    for row in "$@"; do
        IFS=',' read -ra fields <<< "${row}"
        for i in "${!fields[@]}"; do
            if [[ ${i} -lt ${#widths[@]} && ${#fields[${i}]} -gt ${widths[${i}]} ]]; then
                widths[${i}]=${#fields[${i}]}
            fi
        done
    done
    
    # Print headers
    local line=""
    for i in "${!header_array[@]}"; do
        printf "| %-$((widths[i] + 1))s" "${header_array[${i}]}"
        line+="+-"
        for ((j=0; j<widths[i]; j++)); do
            line+="-"
        done
        line+="-"
    done
    printf "|\n"
    
    # Print separator line
    echo "${line}+"
    
    # Print data rows
    for row in "$@"; do
        IFS=',' read -ra fields <<< "${row}"
        for i in "${!fields[@]}"; do
            if [[ ${i} -lt ${#widths[@]} ]]; then
                printf "| %-$((widths[i] + 1))s" "${fields[${i}]}"
            fi
        done
        printf "|\n"
    done
    
    # Print bottom line
    echo "${line}+"
}