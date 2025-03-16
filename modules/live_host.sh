#!/bin/bash
# MR Legacy - Live Host Detection Module

# Function to check if a host is live using ping
check_host_ping() {
    local host="$1"
    
    if ping -c 1 -W 1 "$host" >/dev/null 2>&1; then
        return 0  # Host is up
    else
        return 1  # Host is down
    fi
}

# Function to check if a host has HTTP/HTTPS service
check_host_http() {
    local host="$1"
    
    # Try HTTP
    if curl -s --head --connect-timeout 3 "http://$host" >/dev/null; then
        echo "http"
        return 0
    fi
    
    # Try HTTPS
    if curl -s --head --connect-timeout 3 --insecure "https://$host" >/dev/null; then
        echo "https"
        return 0
    fi
    
    return 1  # No HTTP/HTTPS service
}

# Function to probe a host with httpx
probe_with_httpx() {
    local host="$1"
    local output_file="$2"
    
    if is_tool_installed "httpx"; then
        log_message "Probing $host with httpx..." "INFO"
        
        echo "$host" | httpx -silent -follow-redirects -status-code -title -tech-detect -timeout 5 >> "$output_file"
        
        return $?
    else
        log_message "httpx not found" "WARNING"
        return 1
    fi
}

# Function to check subdomains in parallel
check_hosts_parallel() {
    local input_file="$1"
    local output_file="$2"
    local threads="$3"
    local temp_dir="$4"
    
    log_message "Checking hosts in parallel (threads: $threads)..." "INFO"
    
    # Create temporary directory
    mkdir -p "$temp_dir"
    
    # Split input file into chunks
    split_file_for_parallel "$input_file" "$threads" "$temp_dir/chunk_"
    
    # Process each chunk in parallel
    find "$temp_dir" -name "chunk_*" | sort | while read chunk_file; do
        {
            while IFS= read -r host || [[ -n "$host" ]]; do
                # Skip empty lines
                if [ -z "$host" ]; then
                    continue
                fi
                
                # Extract the host name (remove protocol if present)
                host=$(echo "$host" | sed 's|^https\?://||' | sed 's|/.*$||')
                
                # Check if host is alive
                if check_host_ping "$host"; then
                    # Check if host has HTTP/HTTPS service
                    protocol=$(check_host_http "$host")
                    
                    if [ -n "$protocol" ]; then
                        # Host is alive and has HTTP/HTTPS service
                        echo "$protocol://$host" >> "$temp_dir/live_hosts_$$.txt"
                    else
                        # Host is alive but no HTTP/HTTPS service
                        echo "$host (no HTTP/HTTPS)" >> "$temp_dir/other_hosts_$$.txt"
                    fi
                fi
            done < "$chunk_file"
        } &
    done
    
    # Wait for all background processes to finish
    wait
    
    # Merge results
    touch "$temp_dir/live_hosts_$$.txt" "$temp_dir/other_hosts_$$.txt"
    cat "$temp_dir/live_hosts_$$.txt" "$temp_dir/other_hosts_$$.txt" | sort -u > "$output_file"
    
    # Count live hosts
    local count=$(wc -l < "$output_file")
    log_message "Found $count live hosts" "SUCCESS"
    
    # Cleanup temporary files
    rm -rf "$temp_dir"
}

# Function to get additional information about live hosts using httpx
get_hosts_info() {
    local input_file="$1"
    local output_file="$2"
    
    if is_tool_installed "httpx"; then
        log_message "Getting additional information about live hosts..." "INFO"
        
        # Extract URLs (filter out non-HTTP hosts)
        grep -E "^https?://" "$input_file" > "$output_file.urls"
        
        if [ -s "$output_file.urls" ]; then
            # Run httpx with detailed options
            cat "$output_file.urls" | httpx -silent -follow-redirects -status-code -title -tech-detect -server -timeout 5 -o "$output_file"
            
            if [ $? -eq 0 ]; then
                log_message "Successfully gathered information about live hosts" "SUCCESS"
            else
                log_message "Error while gathering information about live hosts" "ERROR"
            fi
        else
            log_message "No HTTP/HTTPS hosts found" "WARNING"
            touch "$output_file"  # Create empty file
        fi
    else
        log_message "httpx not found, skipping detailed host information" "WARNING"
        cp "$input_file" "$output_file"  # Use the basic list as fallback
    fi
}

# Main function to run live host detection
run_live_host_detection() {
    log_message "Starting live host detection..." "INFO"
    
    # Setup Tor proxy if enabled
    setup_tor_proxy
    
    # Create output directory
    local output_dir="$target_dir/subdomains"
    mkdir -p "$output_dir"
    
    # Temporary directory for parallel processing
    local temp_dir="$output_dir/temp_live"
    mkdir -p "$temp_dir"
    
    # Input file with subdomains
    local input_file="$output_dir/all_subdomains.txt"
    
    # Check if the input file exists
    if [ ! -f "$input_file" ]; then
        log_message "Subdomain list not found. Run subdomain enumeration first." "ERROR"
        return 1
    fi
    
    # Output files
    local live_hosts_file="$output_dir/live_hosts.txt"
    local detailed_hosts_file="$output_dir/live_hosts_detailed.txt"
    
    # Check hosts in parallel
    check_hosts_parallel "$input_file" "$live_hosts_file" "$threads" "$temp_dir"
    
    # Get additional information about live hosts
    get_hosts_info "$live_hosts_file" "$detailed_hosts_file"
    
    # Save results in different formats
    save_results "$live_hosts_file" "$output_dir" "live_hosts" "$output_format"
    save_results "$detailed_hosts_file" "$output_dir" "live_hosts_detailed" "$output_format"
    
    log_message "Live host detection completed" "SUCCESS"
    return 0
}
