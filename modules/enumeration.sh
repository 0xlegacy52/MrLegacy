#!/bin/bash

# MR Legacy - Enumeration Module
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.1.0

# Create necessary variables to track module execution
CALLED_FN_DIR="${target_dir}/.called_fn"
mkdir -p "$CALLED_FN_DIR" 2>/dev/null
chmod 755 "$CALLED_FN_DIR" 2>/dev/null

# Function to perform directory fuzzing
function directory_enum() {
    if is_completed "directory_enum"; then
        log_message "Directory fuzzing already completed for $target" "INFO"
        return 0
    fi
    
    start_function "directory_enum" "Directory Fuzzing for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/enumeration/directories" 2>/dev/null
    local http_hosts="${target_dir}/recon/http/http_hosts.txt"
    local output_dir="${target_dir}/enumeration/directories"
    
    # Check if HTTP hosts file exists
    if [[ ! -f "$http_hosts" ]]; then
        log_message "No HTTP hosts file found. Using main target." "WARNING"
        mkdir -p "${target_dir}/recon/http" 2>/dev/null
        if is_valid_url "$target"; then
            echo "$target" > "$http_hosts"
        else
            echo "http://$target" > "$http_hosts"
        fi
    fi
    
    log_message "Starting directory fuzzing on $target" "INFO"
    
    # Check if we have a wordlist
    local wordlist=""
    
    # Try to find a wordlist
    if [[ -f "/usr/share/wordlists/dirb/common.txt" ]]; then
        wordlist="/usr/share/wordlists/dirb/common.txt"
        log_message "Using dirb common wordlist" "INFO"
    elif [[ -f "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ]]; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        log_message "Using dirbuster medium wordlist" "INFO"
    else
        log_message "No wordlist found. Creating a small basic wordlist." "WARNING"
        
        # Create a basic wordlist with common directories
        local basic_wordlist="${target_dir}/.tmp/basic_dirs.txt"
        mkdir -p "${target_dir}/.tmp" 2>/dev/null
        
        cat > "$basic_wordlist" << EOF
admin
wp-admin
login
wp-login.php
administrator
admins
wp-content
assets
images
img
css
js
api
v1
v2
backup
backups
dev
development
staging
test
temp
old
new
beta
EOF
        
        wordlist="$basic_wordlist"
        log_message "Created basic wordlist with common directories" "INFO"
    fi
    
    # Try different directory fuzzing tools
    if command_exists "ffuf"; then
        log_message "Using ffuf for directory fuzzing" "INFO"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            local host_clean=$(echo "$host" | sed 's/https\?:\/\///' | sed 's/\/$//')
            local output_file="${output_dir}/${host_clean}_directories.txt"
            
            log_message "Fuzzing directories on $host" "INFO"
            execute_command "ffuf -u \"${host}/FUZZ\" -w \"$wordlist\" -mc 200,204,301,302,307,401,403 -o \"$output_file\" -of csv" "Directory fuzzing with ffuf" 600 1
        done < "$http_hosts"
        
    elif command_exists "gobuster"; then
        log_message "Using gobuster for directory fuzzing" "INFO"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            local host_clean=$(echo "$host" | sed 's/https\?:\/\///' | sed 's/\/$//')
            local output_file="${output_dir}/${host_clean}_directories.txt"
            
            log_message "Fuzzing directories on $host" "INFO"
            execute_command "gobuster dir -u \"$host\" -w \"$wordlist\" -o \"$output_file\" -q" "Directory fuzzing with gobuster" 600 1
        done < "$http_hosts"
        
    elif command_exists "dirsearch"; then
        log_message "Using dirsearch for directory fuzzing" "INFO"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            local host_clean=$(echo "$host" | sed 's/https\?:\/\///' | sed 's/\/$//')
            local output_file="${output_dir}/${host_clean}_directories.txt"
            
            log_message "Fuzzing directories on $host" "INFO"
            execute_command "dirsearch -u \"$host\" -w \"$wordlist\" -o \"$output_file\" -q" "Directory fuzzing with dirsearch" 600 1
        done < "$http_hosts"
        
    else
        log_message "No directory fuzzing tools found. Directory fuzzing skipped." "ERROR"
        echo "Directory fuzzing skipped - no tools available" > "${output_dir}/README.txt"
        end_function "directory_enum" 1 "Directory fuzzing skipped - no tools available"
        return 1
    fi
    
    # Check if we found any directories
    local file_count=$(find "$output_dir" -type f -not -name "README.txt" | wc -l)
    
    if [[ $file_count -gt 0 ]]; then
        log_message "Directory fuzzing completed. Results saved to $output_dir" "SUCCESS"
        end_function "directory_enum" 0 "Directory fuzzing completed successfully"
        return 0
    else
        log_message "No directories found during fuzzing" "WARNING"
        echo "No directories found during fuzzing" > "${output_dir}/README.txt"
        end_function "directory_enum" 0 "Directory fuzzing completed - no directories found"
        return 0
    fi
}

# Function to discover parameters
function parameter_discovery() {
    if is_completed "parameter_discovery"; then
        log_message "Parameter discovery already completed for $target" "INFO"
        return 0
    fi
    
    start_function "parameter_discovery" "Parameter Discovery for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/enumeration/parameters" 2>/dev/null
    local http_hosts="${target_dir}/recon/http/http_hosts.txt"
    local output_file="${target_dir}/enumeration/parameters/all_parameters.txt"
    
    # Check if HTTP hosts file exists
    if [[ ! -f "$http_hosts" ]]; then
        log_message "No HTTP hosts file found. Using main target." "WARNING"
        mkdir -p "${target_dir}/recon/http" 2>/dev/null
        if is_valid_url "$target"; then
            echo "$target" > "$http_hosts"
        else
            echo "http://$target" > "$http_hosts"
        fi
    fi
    
    log_message "Starting parameter discovery on $target" "INFO"
    
    # Try different parameter discovery tools
    if command_exists "paramspider"; then
        log_message "Using ParamSpider for parameter discovery" "INFO"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            local host_clean=$(echo "$host" | sed 's/https\?:\/\///' | sed 's/\/$//')
            local tmp_output="${target_dir}/.tmp/${host_clean}_params.txt"
            
            mkdir -p "${target_dir}/.tmp" 2>/dev/null
            
            log_message "Discovering parameters on $host" "INFO"
            execute_command "python3 -m paramspider -d $host_clean -o \"$tmp_output\" -q" "Parameter discovery with ParamSpider" 300 1
            
            # Append to main output if file exists
            if [[ -f "$tmp_output" ]]; then
                cat "$tmp_output" >> "$output_file" 2>/dev/null
            fi
        done < "$http_hosts"
        
    elif command_exists "arjun"; then
        log_message "Using Arjun for parameter discovery" "INFO"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            local host_clean=$(echo "$host" | sed 's/https\?:\/\///' | sed 's/\/$//')
            local tmp_output="${target_dir}/.tmp/${host_clean}_params.txt"
            
            mkdir -p "${target_dir}/.tmp" 2>/dev/null
            
            log_message "Discovering parameters on $host" "INFO"
            execute_command "arjun -u \"$host\" -t 20 -o \"$tmp_output\"" "Parameter discovery with Arjun" 300 1
            
            # Append to main output if file exists
            if [[ -f "$tmp_output" ]]; then
                cat "$tmp_output" >> "$output_file" 2>/dev/null
            fi
        done < "$http_hosts"
        
    elif command_exists "gau" || command_exists "waybackurls"; then
        log_message "Using gau/waybackurls for basic parameter discovery" "INFO"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            local host_clean=$(echo "$host" | sed 's/https\?:\/\///' | sed 's/\/$//')
            local tmp_output="${target_dir}/.tmp/${host_clean}_urls.txt"
            
            mkdir -p "${target_dir}/.tmp" 2>/dev/null
            
            # Collect URLs first
            if command_exists "gau"; then
                log_message "Using gau to collect URLs from $host" "INFO"
                execute_command "gau --subs $host_clean > \"$tmp_output\"" "URL collection with gau" 300 1
            elif command_exists "waybackurls"; then
                log_message "Using waybackurls to collect URLs from $host" "INFO"
                execute_command "waybackurls $host_clean > \"$tmp_output\"" "URL collection with waybackurls" 300 1
            fi
            
            # Extract parameters from collected URLs
            if [[ -f "$tmp_output" ]]; then
                log_message "Extracting parameters from collected URLs" "INFO"
                execute_command "grep -o '\\?[^\" ]*' \"$tmp_output\" | sort -u | sed 's/^\\?//' > \"${target_dir}/.tmp/${host_clean}_params.txt\"" "Parameter extraction" 60 1
                
                # Append to main output
                cat "${target_dir}/.tmp/${host_clean}_params.txt" >> "$output_file" 2>/dev/null
            fi
        done < "$http_hosts"
        
    else
        log_message "No parameter discovery tools found. Parameter discovery skipped." "ERROR"
        echo "Parameter discovery skipped - no tools available" > "$output_file"
        end_function "parameter_discovery" 1 "Parameter discovery skipped - no tools available"
        return 1
    fi
    
    # Sort and deduplicate the results
    if [[ -f "$output_file" ]]; then
        sort -u "$output_file" -o "$output_file"
        local param_count=$(wc -l < "$output_file")
        
        if [[ $param_count -gt 0 ]]; then
            log_message "Parameter discovery completed. Found $param_count unique parameters." "SUCCESS"
            end_function "parameter_discovery" 0 "Parameter discovery completed successfully"
            return 0
        else
            log_message "No parameters found during discovery" "WARNING"
            echo "No parameters found during discovery" > "$output_file"
            end_function "parameter_discovery" 0 "Parameter discovery completed - no parameters found"
            return 0
        fi
    else
        log_message "No parameters found during discovery" "WARNING"
        echo "No parameters found during discovery" > "$output_file"
        end_function "parameter_discovery" 0 "Parameter discovery completed - no parameters found"
        return 0
    fi
}

# Function to find virtual hosts (vhost)
function vhost_discovery() {
    if is_completed "vhost_discovery"; then
        log_message "Virtual host discovery already completed for $target" "INFO"
        return 0
    fi
    
    start_function "vhost_discovery" "Virtual Host Discovery for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/enumeration/vhosts" 2>/dev/null
    local output_file="${target_dir}/enumeration/vhosts/vhosts.txt"
    
    # Check if target is valid
    if ! is_valid_domain "$target"; then
        log_message "Target doesn't appear to be a valid domain. Skipping virtual host discovery." "ERROR"
        echo "Target is not a valid domain for virtual host discovery." > "$output_file"
        end_function "vhost_discovery" 1 "Virtual host discovery skipped - invalid target"
        return 1
    fi
    
    log_message "Starting virtual host discovery on $target" "INFO"
    
    # Try different vhost discovery tools
    if command_exists "gobuster"; then
        log_message "Using gobuster for virtual host discovery" "INFO"
        
        # Create a wordlist of potential vhosts
        local vhost_wordlist="${target_dir}/.tmp/vhosts.txt"
        mkdir -p "${target_dir}/.tmp" 2>/dev/null
        
        # Extract base domain
        local base_domain=$(get_base_domain "$target")
        
        # Create basic wordlist of common subdomains
        cat > "$vhost_wordlist" << EOF
dev
test
staging
admin
app
api
mail
webmail
www
intranet
internal
dev-api
stage
beta
uat
prod
qa
EOF
        
        # Add variations of the target domain
        while read -r prefix; do
            echo "${prefix}.${base_domain}" >> "$vhost_wordlist"
        done < "$vhost_wordlist"
        
        # Add the base domain itself
        echo "$base_domain" >> "$vhost_wordlist"
        
        # Run gobuster vhost
        execute_command "gobuster vhost -u \"$target\" -w \"$vhost_wordlist\" -o \"$output_file\"" "Virtual host discovery with gobuster" 300 1
        
    elif command_exists "ffuf"; then
        log_message "Using ffuf for virtual host discovery" "INFO"
        
        # Create a wordlist of potential vhosts
        local vhost_wordlist="${target_dir}/.tmp/vhosts.txt"
        mkdir -p "${target_dir}/.tmp" 2>/dev/null
        
        # Extract base domain
        local base_domain=$(get_base_domain "$target")
        
        # Create basic wordlist of common subdomains
        cat > "$vhost_wordlist" << EOF
dev
test
staging
admin
app
api
mail
webmail
www
intranet
internal
dev-api
stage
beta
uat
prod
qa
EOF
        
        # Add variations of the target domain
        local tmp_vhosts="${target_dir}/.tmp/tmp_vhosts.txt"
        > "$tmp_vhosts"
        
        while read -r prefix; do
            echo "${prefix}.${base_domain}" >> "$tmp_vhosts"
        done < "$vhost_wordlist"
        
        # Add the base domain itself
        echo "$base_domain" >> "$tmp_vhosts"
        
        # Move the expanded list back to vhost_wordlist
        mv "$tmp_vhosts" "$vhost_wordlist"
        
        # Run ffuf for vhost discovery
        execute_command "ffuf -u \"http://$target\" -H \"Host: FUZZ\" -w \"$vhost_wordlist\" -fr 'no host' -o \"$output_file\"" "Virtual host discovery with ffuf" 300 1
        
    else
        log_message "No virtual host discovery tools found. Virtual host discovery skipped." "ERROR"
        echo "Virtual host discovery skipped - no tools available" > "$output_file"
        end_function "vhost_discovery" 1 "Virtual host discovery skipped - no tools available"
        return 1
    fi
    
    # Check if we found any virtual hosts
    if [[ -s "$output_file" ]]; then
        local vhost_count=$(grep -v "^#" "$output_file" | wc -l)
        log_message "Virtual host discovery completed. Found $vhost_count potential virtual hosts." "SUCCESS"
        end_function "vhost_discovery" 0 "Virtual host discovery completed successfully"
        return 0
    else
        log_message "No virtual hosts found" "WARNING"
        echo "No virtual hosts found" > "$output_file"
        end_function "vhost_discovery" 0 "Virtual host discovery completed - no virtual hosts found"
        return 0
    fi
}

# Function to analyze JavaScript files
function js_analysis() {
    if is_completed "js_analysis"; then
        log_message "JavaScript analysis already completed for $target" "INFO"
        return 0
    fi
    
    start_function "js_analysis" "JavaScript Analysis for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/enumeration/js" 2>/dev/null
    local http_hosts="${target_dir}/recon/http/http_hosts.txt"
    local js_urls="${target_dir}/enumeration/js/js_urls.txt"
    local endpoints="${target_dir}/enumeration/js/endpoints.txt"
    local secrets="${target_dir}/enumeration/js/secrets.txt"
    
    # Check if HTTP hosts file exists
    if [[ ! -f "$http_hosts" ]]; then
        log_message "No HTTP hosts file found. Using main target." "WARNING"
        mkdir -p "${target_dir}/recon/http" 2>/dev/null
        if is_valid_url "$target"; then
            echo "$target" > "$http_hosts"
        else
            echo "http://$target" > "$http_hosts"
        fi
    fi
    
    log_message "Starting JavaScript analysis on $target" "INFO"
    
    # Find JavaScript files first
    > "$js_urls"
    
    if command_exists "hakrawler"; then
        log_message "Using hakrawler to find JavaScript files" "INFO"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            log_message "Finding JavaScript files on $host" "INFO"
            execute_command "echo \"$host\" | hakrawler -js -plain | sort -u >> \"$js_urls\"" "Finding JavaScript files with hakrawler" 300 1
        done < "$http_hosts"
        
    elif command_exists "gau" || command_exists "waybackurls"; then
        log_message "Using gau/waybackurls to find JavaScript files" "INFO"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            # Collect URLs
            local urls_file="${target_dir}/.tmp/$(echo "$host" | sed 's/https\?:\/\///' | sed 's/\/$//')_urls.txt"
            mkdir -p "${target_dir}/.tmp" 2>/dev/null
            
            if command_exists "gau"; then
                log_message "Using gau to collect URLs from $host" "INFO"
                execute_command "gau --subs $host > \"$urls_file\"" "URL collection with gau" 300 1
            elif command_exists "waybackurls"; then
                log_message "Using waybackurls to collect URLs from $host" "INFO"
                execute_command "waybackurls $host > \"$urls_file\"" "URL collection with waybackurls" 300 1
            fi
            
            # Filter for JavaScript files
            if [[ -f "$urls_file" ]]; then
                log_message "Filtering JavaScript URLs from collected URLs" "INFO"
                execute_command "grep -E '\\.js(\\?|$)' \"$urls_file\" >> \"$js_urls\"" "Filtering JavaScript URLs" 60 1
            fi
        done < "$http_hosts"
        
    else
        log_message "No JavaScript discovery tools found. Using basic curl and grep." "WARNING"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            log_message "Finding JavaScript files on $host using curl" "INFO"
            local html=$(curl -s -L -m 10 "$host")
            echo "$html" | grep -o 'src="[^"]*\.js[^"]*"' | grep -o '"[^"]*"' | tr -d '"' | while read -r js_path; do
                # Handle relative and absolute URLs
                if [[ "$js_path" == /* ]]; then
                    # Path is relative to domain root
                    local domain=$(echo "$host" | grep -o 'https\?://[^/]*')
                    echo "${domain}${js_path}" >> "$js_urls"
                elif [[ "$js_path" == http* ]]; then
                    # Path is already absolute
                    echo "$js_path" >> "$js_urls"
                else
                    # Path is relative to current URL
                    echo "${host%/}/${js_path}" >> "$js_urls"
                fi
            done
        done < "$http_hosts"
    fi
    
    # Extract endpoints and secrets from JavaScript files
    if [[ -s "$js_urls" ]]; then
        log_message "Found $(wc -l < "$js_urls") JavaScript files. Analyzing..." "INFO"
        
        # Process JavaScript files for endpoints
        > "$endpoints"
        > "$secrets"
        
        # Function to analyze a JavaScript file
        analyze_js_file() {
            local js_url="$1"
            local js_content="${target_dir}/.tmp/$(echo "$js_url" | md5sum | cut -d' ' -f1).js"
            
            # Download the JS file
            curl -s -L -m 10 "$js_url" -o "$js_content"
            
            if [[ -s "$js_content" ]]; then
                # Extract potential endpoints (URLs, API paths)
                grep -o 'https\?://[^"'\''`]*' "$js_content" >> "$endpoints" 2>/dev/null
                grep -o '"/[^"]*"' "$js_content" | tr -d '"' >> "$endpoints" 2>/dev/null
                grep -o "'/[^']*'" "$js_content" | tr -d "'" >> "$endpoints" 2>/dev/null
                
                # Extract potential secrets
                grep -E 'api[_-]?key|api[_-]?token|app[_-]?key|app[_-]?token|auth[_-]?token|access[_-]?token|secret[_-]?key|client[_-]?secret|aws[_-]?key|aws[_-]?token|password|passwd|pwd|token|Bearer' "$js_content" >> "$secrets" 2>/dev/null
            fi
            
            # Clean up
            rm -f "$js_content" 2>/dev/null
        }
        
        # Process each JavaScript file (with limit to avoid overload)
        cat "$js_urls" | head -n 100 | while read -r js_url; do
            [[ -z "$js_url" ]] && continue
            analyze_js_file "$js_url"
        done
        
        # Sort and deduplicate results
        if [[ -f "$endpoints" ]]; then
            sort -u "$endpoints" -o "$endpoints"
        fi
        
        if [[ -f "$secrets" ]]; then
            sort -u "$secrets" -o "$secrets"
        fi
        
        # Count findings
        local endpoint_count=$(wc -l < "$endpoints")
        local secret_count=$(wc -l < "$secrets")
        
        log_message "JavaScript analysis completed. Found $endpoint_count endpoints and $secret_count potential secrets." "SUCCESS"
        end_function "js_analysis" 0 "JavaScript analysis completed successfully"
        return 0
    else
        log_message "No JavaScript files found" "WARNING"
        echo "No JavaScript files found" > "$js_urls"
        end_function "js_analysis" 0 "JavaScript analysis completed - no JavaScript files found"
        return 0
    fi
}

# Main enumeration function
function run_enumeration_module() {
    log_message "Starting enumeration module for $target" "INFO"
    
    # Create output directories
    mkdir -p "${target_dir}/enumeration" 2>/dev/null
    mkdir -p "${target_dir}/.tmp" 2>/dev/null
    
    # Create .called_fn directory with proper permissions
    CALLED_FN_DIR="${target_dir}/.called_fn"
    mkdir -p "$CALLED_FN_DIR" 2>/dev/null
    chmod 755 "$CALLED_FN_DIR" 2>/dev/null
    
    # Show banner
    show_enumeration_banner
    
    # Run enumeration functions
    directory_enum
    parameter_discovery
    vhost_discovery
    js_analysis
    
    # Clean up temp files
    rm -rf "${target_dir}/.tmp" 2>/dev/null
    
    log_message "Enumeration module completed for $target" "SUCCESS"
}

# Export functions
export -f directory_enum
export -f parameter_discovery
export -f vhost_discovery
export -f js_analysis
export -f run_enumeration_module