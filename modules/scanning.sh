#!/bin/bash

# MR Legacy - Scanning Module
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.1.0

# Create necessary variables to track module execution
CALLED_FN_DIR="${target_dir}/.called_fn"
mkdir -p "$CALLED_FN_DIR" 2>/dev/null
chmod 755 "$CALLED_FN_DIR" 2>/dev/null

# Function to run port scanning
function port_scanning() {
    if is_completed "port_scanning"; then
        log_message "Port scanning already completed for $target" "INFO"
        return 0
    fi
    
    start_function "port_scanning" "Port Scanning for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/scanning/ports" 2>/dev/null
    local output_file="${target_dir}/scanning/ports/open_ports.txt"
    local detailed_output="${target_dir}/scanning/ports/detailed_scan.txt"
    
    # Check if target is valid
    if ! is_valid_domain "$target" && ! is_valid_ip "$target"; then
        log_message "Target doesn't appear to be a valid domain or IP. Skipping port scanning." "ERROR"
        echo "Target is not a valid domain or IP for port scanning." > "$output_file"
        end_function "port_scanning" 1 "Port scanning skipped - invalid target"
        return 1
    fi
    
    # If target is a domain, try to resolve it first
    local ip=""
    if is_valid_domain "$target"; then
        log_message "Resolving domain to IP address" "INFO"
        ip=$(resolve_domain "$target")
        if [[ -z "$ip" ]]; then
            log_message "Failed to resolve domain to IP. Using domain name directly." "WARNING"
            ip=$target
        else
            log_message "Resolved $target to $ip" "INFO"
        fi
    else
        ip=$target
    fi
    
    log_message "Starting port scan on $ip" "INFO"
    
    # Try to use nmap for comprehensive scan
    if command_exists "nmap"; then
        log_message "Using nmap for port scanning" "INFO"
        
        # Quick scan for common ports
        execute_command "nmap -F -sV -sC -oN \"$output_file\" $ip" "Quick port scan with nmap" 300 2
        
        # If deep scan is enabled, do a more thorough scan
        if [[ "$DEEP" == true ]]; then
            log_message "Deep scan enabled. Running comprehensive port scan." "INFO"
            execute_command "nmap -p- -sV -sC --min-rate=1000 -oN \"$detailed_output\" $ip" "Comprehensive port scan with nmap" 1800 1
        fi
    # Try masscan as alternative
    elif command_exists "masscan"; then
        log_message "Using masscan for port scanning" "INFO"
        execute_command "masscan -p1-65535 --rate=1000 -oL \"$output_file\" $ip" "Port scan with masscan" 600 2
    # Fall back to basic nc port scanning
    else
        log_message "No port scanning tools found. Using basic netcat scanning." "WARNING"
        local common_ports=(21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5900 8080)
        > "$output_file"
        
        for port in "${common_ports[@]}"; do
            if is_port_open "$ip" "$port" 1; then
                echo "Port $port: open" >> "$output_file"
                log_message "Found open port: $port" "INFO"
            fi
        done
    fi
    
    # Check results
    if [[ -s "$output_file" ]]; then
        local port_count=$(grep -c "open" "$output_file")
        log_message "Found $port_count open ports on $target" "SUCCESS"
    else
        log_message "No open ports found on $target" "WARNING"
        echo "No open ports were found for $target" > "$output_file"
    fi
    
    end_function "port_scanning" 0 "Port scanning completed for $target"
    return 0
}

# Function to perform web fingerprinting
function web_fingerprinting() {
    if is_completed "web_fingerprinting"; then
        log_message "Web fingerprinting already completed for $target" "INFO"
        return 0
    fi
    
    start_function "web_fingerprinting" "Web Application Fingerprinting for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/scanning/web" 2>/dev/null
    local http_hosts="${target_dir}/recon/http/http_hosts.txt"
    local output_file="${target_dir}/scanning/web/fingerprinting.txt"
    
    # Check if HTTP hosts file exists - if not, create one with just the target
    if [[ ! -f "$http_hosts" ]]; then
        log_message "No HTTP hosts file found. Using main target." "WARNING"
        mkdir -p "${target_dir}/recon/http" 2>/dev/null
        if is_valid_url "$target"; then
            echo "$target" > "$http_hosts"
        else
            echo "http://$target" > "$http_hosts"
        fi
    fi
    
    log_message "Starting web fingerprinting" "INFO"
    
    # Use whatweb if available
    if command_exists "whatweb"; then
        log_message "Using whatweb for fingerprinting" "INFO"
        while read -r host; do
            [[ -z "$host" ]] && continue
            log_message "Fingerprinting $host" "INFO"
            execute_command "whatweb -a 3 \"$host\" >> \"$output_file\"" "Fingerprinting with whatweb" 300 2
        done < "$http_hosts"
    # Use curl and basic checks as fallback
    elif command_exists "curl"; then
        log_message "Using curl for basic fingerprinting" "INFO"
        > "$output_file"
        while read -r host; do
            [[ -z "$host" ]] && continue
            log_message "Fingerprinting $host" "INFO"
            
            # Get basic headers and response
            local headers=$(curl -s -I -L -m 10 "$host")
            local server=$(echo "$headers" | grep -i "Server:" | head -n 1)
            local content_type=$(echo "$headers" | grep -i "Content-Type:" | head -n 1)
            local status=$(curl -s -o /dev/null -w "%{http_code}" "$host")
            
            # Get HTML title
            local title=$(curl -s -L -m 10 "$host" | grep -o '<title>[^<]*' | sed 's/<title>//')
            
            echo "URL: $host" >> "$output_file"
            echo "Status: $status" >> "$output_file"
            echo "Server: ${server:-Unknown}" >> "$output_file"
            echo "Content-Type: ${content_type:-Unknown}" >> "$output_file"
            echo "Title: ${title:-No Title}" >> "$output_file"
            echo "----------------------------------------" >> "$output_file"
        done < "$http_hosts"
    else
        log_message "No web fingerprinting tools available. Skipping." "ERROR"
        echo "Web fingerprinting skipped - no tools available" > "$output_file"
        end_function "web_fingerprinting" 1 "Web fingerprinting skipped - no tools available"
        return 1
    fi
    
    # Check results
    if [[ -s "$output_file" ]]; then
        log_message "Web fingerprinting completed successfully" "SUCCESS"
    else
        log_message "No fingerprinting results found" "WARNING"
        echo "No fingerprinting results found" > "$output_file"
    fi
    
    end_function "web_fingerprinting" 0 "Web fingerprinting completed for $target"
    return 0
}

# Main scanning function
function run_scanning_module() {
    log_message "Starting scanning module for $target" "INFO"
    
    # Create output directories
    mkdir -p "${target_dir}/scanning" 2>/dev/null
    mkdir -p "${target_dir}/.tmp" 2>/dev/null
    
    # Create .called_fn directory with proper permissions
    CALLED_FN_DIR="${target_dir}/.called_fn"
    mkdir -p "$CALLED_FN_DIR" 2>/dev/null
    chmod 755 "$CALLED_FN_DIR" 2>/dev/null
    
    # Show banner
    show_scanning_banner
    
    # Run scanning functions
    port_scanning
    web_fingerprinting
    
    # Clean up temp files
    rm -rf "${target_dir}/.tmp" 2>/dev/null
    
    log_message "Scanning module completed for $target" "SUCCESS"
}

# Export functions
export -f port_scanning
export -f web_fingerprinting
export -f run_scanning_module