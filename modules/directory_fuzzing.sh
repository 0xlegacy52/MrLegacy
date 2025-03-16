#!/bin/bash
# MR Legacy - Directory Fuzzing Module

# Function to run Gobuster
run_gobuster() {
    local target="$1"
    local output_file="$2"
    local wordlist="$3"
    local threads="$4"
    local extensions="$5"
    
    if is_tool_installed "gobuster"; then
        log_message "Running Gobuster on $target..." "INFO"
        
        # Check if extensions were provided
        if [ -n "$extensions" ]; then
            ext_param="-x $extensions"
        else
            ext_param=""
        fi
        
        # Run Gobuster with the specified parameters
        gobuster dir -u "$target" -w "$wordlist" -t "$threads" $ext_param -o "$output_file.gobuster" > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            log_message "Gobuster completed successfully" "SUCCESS"
            
            # Extract found directories and files
            grep -v "^$" "$output_file.gobuster" | awk '{print $1}' > "$output_file"
            
            # Count found directories and files
            local count=$(wc -l < "$output_file")
            log_message "Found $count directories and files" "SUCCESS"
        else
            log_message "Gobuster failed or was interrupted" "WARNING"
        fi
    else
        log_message "Gobuster not found" "WARNING"
    fi
}

# Function to run Dirsearch
run_dirsearch() {
    local target="$1"
    local output_file="$2"
    local wordlist="$3"
    local threads="$4"
    local extensions="$5"
    
    if is_tool_installed "dirsearch"; then
        log_message "Running Dirsearch on $target..." "INFO"
        
        # Create Dirsearch command
        local cmd="dirsearch -u $target -w $wordlist -t $threads"
        
        # Add extensions if provided
        if [ -n "$extensions" ]; then
            cmd="$cmd -e $extensions"
        fi
        
        # Add output file
        cmd="$cmd -o $output_file.dirsearch"
        
        # Run Dirsearch
        eval "$cmd" > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            log_message "Dirsearch completed successfully" "SUCCESS"
            
            # Check if output file exists (Dirsearch might not create it if nothing found)
            if [ -f "$output_file.dirsearch" ]; then
                # Extract found directories and files
                grep -v "^$" "$output_file.dirsearch" | grep -v "^#" | awk '{print $1}' > "$output_file"
                
                # Count found directories and files
                local count=$(wc -l < "$output_file")
                log_message "Found $count directories and files" "SUCCESS"
            else
                log_message "No directories or files found by Dirsearch" "WARNING"
                touch "$output_file"
            fi
        else
            log_message "Dirsearch failed or was interrupted" "WARNING"
        fi
    else
        log_message "Dirsearch not found" "WARNING"
    fi
}

# Function to run Feroxbuster
run_feroxbuster() {
    local target="$1"
    local output_file="$2"
    local wordlist="$3"
    local threads="$4"
    local extensions="$5"
    
    if is_tool_installed "feroxbuster"; then
        log_message "Running Feroxbuster on $target..." "INFO"
        
        # Create Feroxbuster command
        local cmd="feroxbuster --url $target --wordlist $wordlist --threads $threads --quiet"
        
        # Add extensions if provided
        if [ -n "$extensions" ]; then
            # Convert comma-separated to required format
            extensions=$(echo "$extensions" | tr ',' ' ' | sed 's/ / -x /g')
            cmd="$cmd -x $extensions"
        fi
        
        # Add output file
        cmd="$cmd --output $output_file.feroxbuster"
        
        # Run Feroxbuster
        eval "$cmd" > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            log_message "Feroxbuster completed successfully" "SUCCESS"
            
            # Extract found directories and files
            grep -v "^$" "$output_file.feroxbuster" | grep -v "^#" | awk '{print $1}' > "$output_file"
            
            # Count found directories and files
            local count=$(wc -l < "$output_file")
            log_message "Found $count directories and files" "SUCCESS"
        else
            log_message "Feroxbuster failed or was interrupted" "WARNING"
        fi
    else
        log_message "Feroxbuster not found" "WARNING"
    fi
}

# Function to merge directory fuzzing results
merge_directory_results() {
    local output_dir="$1"
    local merged_file="$2"
    
    log_message "Merging directory fuzzing results..." "INFO"
    
    # Create a temporary file for merging
    local tmp_file=$(mktemp)
    
    # Find all directory files and merge them
    find "$output_dir" -name "*.directories" | xargs cat > "$tmp_file"
    
    # Sort unique entries
    sort -u "$tmp_file" > "$merged_file"
    
    # Count unique directories
    local count=$(wc -l < "$merged_file")
    
    # Cleanup temporary file
    rm -f "$tmp_file"
    
    log_message "Found $count unique directories and files" "SUCCESS"
}

# Function to run directory fuzzing
run_directory_fuzzing() {
    log_message "Starting directory fuzzing on $target..." "INFO"
    
    # Setup Tor proxy if enabled
    setup_tor_proxy
    
    # Create output directory
    local output_dir="$target_dir/directories"
    mkdir -p "$output_dir"
    
    # Use common extensions for web files
    local extensions="php,html,js,txt,xml,json,sql,bak,zip,tar.gz,git"
    
    # Use default wordlists if they exist
    local wordlist_dirs="/usr/share/wordlists/dirb/common.txt"
    local wordlist_files="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    
    # Check if wordlists exist, otherwise use fallbacks
    if [ ! -f "$wordlist_dirs" ]; then
        log_message "Default directory wordlist not found, using alternative..." "WARNING"
        wordlist_dirs="/usr/share/seclists/Discovery/Web-Content/common.txt"
    fi
    
    if [ ! -f "$wordlist_files" ]; then
        log_message "Default file wordlist not found, using alternative..." "WARNING"
        wordlist_files="/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"
    fi
    
    # Run directory fuzzing tools
    run_gobuster "$target" "$output_dir/gobuster.directories" "$wordlist_dirs" "$threads" "$extensions"
    run_dirsearch "$target" "$output_dir/dirsearch.directories" "$wordlist_dirs" "$threads" "$extensions"
    
    # Merge results
    merge_directory_results "$output_dir" "$output_dir/all_directories.txt"
    
    # Save results in different formats
    save_results "$output_dir/all_directories.txt" "$output_dir" "directories" "$output_format"
    
    log_message "Directory fuzzing completed" "SUCCESS"
    return 0
}

# Function to run file enumeration
run_file_enumeration() {
    log_message "Starting file enumeration on $target..." "INFO"
    
    # Setup Tor proxy if enabled
    setup_tor_proxy
    
    # Create output directory
    local output_dir="$target_dir/directories"
    mkdir -p "$output_dir"
    
    # Use common extensions for sensitive files
    local extensions="bak,old,swp,txt,xml,json,conf,config,sql,env,ini,log,backup,zip,tar,gz"
    
    # Use default wordlists if they exist
    local wordlist="/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt"
    
    # Check if wordlist exists, otherwise use fallback
    if [ ! -f "$wordlist" ]; then
        log_message "Default file wordlist not found, using alternative..." "WARNING"
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    fi
    
    # Run file enumeration tool
    run_gobuster "$target" "$output_dir/gobuster.files" "$wordlist" "$threads" "$extensions"
    
    # Save results in different formats
    save_results "$output_dir/gobuster.files" "$output_dir" "sensitive_files" "$output_format"
    
    log_message "File enumeration completed" "SUCCESS"
    return 0
}

# Function to run parameter discovery
run_parameter_discovery() {
    log_message "Starting parameter discovery on $target..." "INFO"
    
    # Setup Tor proxy if enabled
    setup_tor_proxy
    
    # Create output directory
    local output_dir="$target_dir/directories"
    mkdir -p "$output_dir"
    
    # Use Arjun for parameter discovery if available
    if is_tool_installed "arjun"; then
        log_message "Running Arjun on $target..." "INFO"
        
        arjun -u "$target" -t "$threads" -o "$output_dir/parameters.txt" > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            log_message "Arjun completed successfully" "SUCCESS"
            
            # Save results in different formats
            save_results "$output_dir/parameters.txt" "$output_dir" "parameters" "$output_format"
        else
            log_message "Arjun failed or was interrupted" "WARNING"
        fi
    else
        log_message "Arjun not found, skipping parameter discovery" "WARNING"
    fi
    
    log_message "Parameter discovery completed" "SUCCESS"
    return 0
}

# Function to run virtual host discovery
run_vhost_discovery() {
    log_message "Starting virtual host discovery on $target..." "INFO"
    
    # Setup Tor proxy if enabled
    setup_tor_proxy
    
    # Create output directory
    local output_dir="$target_dir/directories"
    mkdir -p "$output_dir"
    
    # Use Gobuster vhost mode for virtual host discovery
    if is_tool_installed "gobuster"; then
        log_message "Running Gobuster vhost mode on $target..." "INFO"
        
        # Use a wordlist for virtual hosts
        local wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        
        # Check if wordlist exists, otherwise use fallback
        if [ ! -f "$wordlist" ]; then
            log_message "Default vhost wordlist not found, using alternative..." "WARNING"
            wordlist="/usr/share/wordlists/dirb/common.txt"
        fi
        
        # Extract domain from target
        local domain=$(extract_domain "$target")
        
        # Run Gobuster vhost mode
        gobuster vhost -u "$target" -w "$wordlist" -t "$threads" -o "$output_dir/vhosts.gobuster" > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            log_message "Gobuster vhost mode completed successfully" "SUCCESS"
            
            # Extract found virtual hosts
            grep -v "^$" "$output_dir/vhosts.gobuster" | awk '{print $1}' > "$output_dir/vhosts.txt"
            
            # Count found virtual hosts
            local count=$(wc -l < "$output_dir/vhosts.txt")
            log_message "Found $count virtual hosts" "SUCCESS"
            
            # Save results in different formats
            save_results "$output_dir/vhosts.txt" "$output_dir" "vhosts" "$output_format"
        else
            log_message "Gobuster vhost mode failed or was interrupted" "WARNING"
        fi
    else
        log_message "Gobuster not found, skipping virtual host discovery" "WARNING"
    fi
    
    log_message "Virtual host discovery completed" "SUCCESS"
    return 0
}
