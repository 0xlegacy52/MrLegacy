#!/bin/bash

# MR Legacy - Reconnaissance Module
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.1.0

# Create necessary variables to track module execution
CALLED_FN_DIR="${target_dir}/.called_fn"
mkdir -p "$CALLED_FN_DIR" 2>/dev/null
chmod 755 "$CALLED_FN_DIR" 2>/dev/null

# Function to perform subdomain enumeration
function subdomain_enum() {
    if is_completed "subdomain_enum"; then
        log_message "Subdomain enumeration already completed for $target" "INFO"
        return 0
    fi
    
    start_function "subdomain_enum" "Subdomain Enumeration for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/recon/subdomains" 2>/dev/null
    local output_file="${target_dir}/recon/subdomains/subdomains.txt"
    
    # Check if target is a valid domain
    if ! is_valid_domain "$target"; then
        log_message "Target doesn't appear to be a valid domain. Skipping subdomain enumeration." "ERROR"
        echo "Target is not a valid domain for subdomain enumeration." > "$output_file"
        end_function "subdomain_enum" 1 "Subdomain enumeration skipped - invalid target"
        return 1
    fi
    
    log_message "Starting subdomain enumeration for $target" "INFO"
    
    # Initialize results file
    > "$output_file"
    
    # Add the main domain to the results
    echo "$target" > "$output_file"
    
    # Use multiple tools for subdomain discovery
    
    # 0. First, try our custom wordlist for bruteforcing subdomains
    log_message "Using custom wordlist for subdomain enumeration" "INFO"
    local custom_wordlist="${script_path}/modules/wordlists/subdomains.txt"
    
    if [[ -f "$custom_wordlist" ]]; then
        log_message "Using custom subdomain wordlist: $custom_wordlist ($(wc -l < "$custom_wordlist") entries)" "INFO"
        local tmp_results="${target_dir}/.tmp/bruted_subdomains.txt"
        > "$tmp_results"
        
        while read -r subdomain; do
            host_to_check="${subdomain}.${target}"
            if host "$host_to_check" >/dev/null 2>&1; then
                echo "$host_to_check" >> "$tmp_results"
                log_message "Found subdomain: $host_to_check" "DEBUG"
            fi
        done < "$custom_wordlist"
        
        log_message "Custom wordlist subdomain discovery completed. Found $(wc -l < "$tmp_results") subdomains." "INFO"
        if [[ -s "$tmp_results" ]]; then
            cat "$tmp_results" >> "$output_file"
        fi
    else
        log_message "Custom subdomain wordlist not found. Skipping custom wordlist enumeration." "WARNING"
    fi
    
    # 1. Check if subfinder is available
    if command_exists "subfinder"; then
        log_message "Using subfinder for subdomain enumeration" "INFO"
        execute_command "subfinder -d $target -silent >> \"$output_file\"" "Subdomain enumeration with subfinder" 300 2
    fi
    
    # 2. Check if assetfinder is available
    if command_exists "assetfinder"; then
        log_message "Using assetfinder for subdomain enumeration" "INFO"
        execute_command "assetfinder --subs-only $target >> \"$output_file\"" "Subdomain enumeration with assetfinder" 300 2
    fi
    
    # 3. Check if findomain is available
    if command_exists "findomain"; then
        log_message "Using findomain for subdomain enumeration" "INFO"
        execute_command "findomain -t $target -q >> \"$output_file\"" "Subdomain enumeration with findomain" 300 2
    fi
    
    # 4. Check if sublist3r is available
    if command_exists "sublist3r"; then
        log_message "Using sublist3r for subdomain enumeration" "INFO"
        execute_command "sublist3r -d $target -o \"${target_dir}/.tmp/sublist3r.txt\"" "Subdomain enumeration with sublist3r" 300 2
        if [[ -f "${target_dir}/.tmp/sublist3r.txt" ]]; then
            cat "${target_dir}/.tmp/sublist3r.txt" >> "$output_file"
        fi
    fi
    
    # 5. DNS bruteforce using dnsx if available
    if command_exists "dnsx" && [[ "$DEEP" == true ]]; then
        log_message "Using dnsx for DNS bruteforce" "INFO"
        
        # Check for wordlist
        local wordlist=""
        
        if [[ -f "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt" ]]; then
            wordlist="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        elif [[ -f "/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt" ]]; then
            wordlist="/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt"
        else
            # Create a basic wordlist
            log_message "No suitable wordlist found. Creating basic subdomain wordlist." "WARNING"
            local basic_wordlist="${target_dir}/.tmp/basic_subdomains.txt"
            mkdir -p "${target_dir}/.tmp" 2>/dev/null
            
            cat > "$basic_wordlist" << EOF
www
mail
remote
blog
webmail
server
ns1
ns2
smtp
secure
vpn
m
shop
ftp
apps
api
dev
test
portal
admin
cdn
app
my
mobile
support
beta
wap
members
forums
store
host
web
cloud
online
proxy
staging
stage
new
old
forum
chat
services
intranet
test1
test2
backup
wiki
help
EOF
            
            wordlist="$basic_wordlist"
        fi
        
        # Run DNS bruteforce
        execute_command "for sub in \$(cat \"$wordlist\"); do echo \"\${sub}.$target\"; done | dnsx -silent -a -resp >> \"${target_dir}/.tmp/dnsx_results.txt\"" "DNS bruteforce with dnsx" 900 1
        
        # Extract subdomains from results
        if [[ -f "${target_dir}/.tmp/dnsx_results.txt" ]]; then
            cat "${target_dir}/.tmp/dnsx_results.txt" | awk '{print $1}' | sort -u >> "$output_file"
        fi
    fi
    
    # Fallback to basic DNS enumeration if no tools are available
    if ! (command_exists "subfinder" || command_exists "assetfinder" || command_exists "findomain" || command_exists "sublist3r" || command_exists "dnsx"); then
        log_message "No specialized subdomain enumeration tools found. Using basic DNS queries." "WARNING"
        
        # Try to get subdomains using dig
        if command_exists "dig"; then
            log_message "Using dig for basic subdomain enumeration" "INFO"
            
            # Check for common subdomains
            local common_subs=("www" "mail" "remote" "blog" "webmail" "server" "ns" "ns1" "ns2" "smtp" "secure" "vpn" "m" "shop" "ftp" "apps" "api")
            
            for sub in "${common_subs[@]}"; do
                local result=$(dig +short "${sub}.${target}")
                if [[ -n "$result" ]]; then
                    echo "${sub}.${target}" >> "$output_file"
                    log_message "Found subdomain: ${sub}.${target}" "INFO"
                fi
            done
        # If dig is not available, try host command
        elif command_exists "host"; then
            log_message "Using host for basic subdomain enumeration" "INFO"
            
            # Check for common subdomains
            local common_subs=("www" "mail" "remote" "blog" "webmail" "server" "ns" "ns1" "ns2" "smtp" "secure" "vpn" "m" "shop" "ftp" "apps" "api")
            
            for sub in "${common_subs[@]}"; do
                if host "${sub}.${target}" &>/dev/null; then
                    echo "${sub}.${target}" >> "$output_file"
                    log_message "Found subdomain: ${sub}.${target}" "INFO"
                fi
            done
        # If neither dig nor host is available, skip
        else
            log_message "No DNS query tools available. Basic subdomain enumeration skipped." "ERROR"
        fi
    fi
    
    # Sort and deduplicate results
    if [[ -f "$output_file" ]]; then
        sort -u "$output_file" -o "$output_file"
        local subdomain_count=$(wc -l < "$output_file")
        
        log_message "Subdomain enumeration completed. Found $subdomain_count subdomains." "SUCCESS"
        end_function "subdomain_enum" 0 "Subdomain enumeration completed successfully"
        return 0
    else
        log_message "Subdomain enumeration failed. No output file created." "ERROR"
        end_function "subdomain_enum" 1 "Subdomain enumeration failed"
        return 1
    fi
}

# Function to perform DNS enumeration
function dns_enum() {
    if is_completed "dns_enum"; then
        log_message "DNS enumeration already completed for $target" "INFO"
        return 0
    fi
    
    start_function "dns_enum" "DNS Enumeration for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/recon/dns" 2>/dev/null
    local subdomains_file="${target_dir}/recon/subdomains/subdomains.txt"
    local output_file="${target_dir}/recon/dns/dns_records.txt"
    
    # Check if subdomains file exists
    if [[ ! -f "$subdomains_file" ]]; then
        log_message "No subdomains file found. Running subdomain enumeration first." "WARNING"
        subdomain_enum
    fi
    
    # Check again if subdomains file exists and is not empty
    if [[ ! -f "$subdomains_file" || ! -s "$subdomains_file" ]]; then
        log_message "Still no subdomains found. Using just the main target." "WARNING"
        echo "$target" > "$subdomains_file"
    fi
    
    log_message "Starting DNS enumeration" "INFO"
    
    # Initialize output file
    > "$output_file"
    
    # Determine which tool to use for DNS enumeration
    if command_exists "dnsx"; then
        log_message "Using dnsx for DNS enumeration" "INFO"
        
        # Run dnsx to get various DNS records
        execute_command "cat \"$subdomains_file\" | dnsx -silent -a -aaaa -cname -mx -ns -soa -txt -resp >> \"$output_file\"" "DNS enumeration with dnsx" 300 2
        
    elif command_exists "dig"; then
        log_message "Using dig for DNS enumeration" "INFO"
        
        while read -r domain; do
            [[ -z "$domain" ]] && continue
            
            log_message "Enumerating DNS records for $domain" "DEBUG"
            
            # Get A records
            echo "# A records for $domain" >> "$output_file"
            dig +short A "$domain" >> "$output_file" 2>/dev/null
            
            # Get AAAA records
            echo -e "\n# AAAA records for $domain" >> "$output_file"
            dig +short AAAA "$domain" >> "$output_file" 2>/dev/null
            
            # Get CNAME records
            echo -e "\n# CNAME records for $domain" >> "$output_file"
            dig +short CNAME "$domain" >> "$output_file" 2>/dev/null
            
            # Get MX records
            echo -e "\n# MX records for $domain" >> "$output_file"
            dig +short MX "$domain" >> "$output_file" 2>/dev/null
            
            # Get NS records
            echo -e "\n# NS records for $domain" >> "$output_file"
            dig +short NS "$domain" >> "$output_file" 2>/dev/null
            
            # Get TXT records
            echo -e "\n# TXT records for $domain" >> "$output_file"
            dig +short TXT "$domain" >> "$output_file" 2>/dev/null
            
            echo -e "\n------------------------------------------\n" >> "$output_file"
        done < "$subdomains_file"
        
    elif command_exists "host"; then
        log_message "Using host for DNS enumeration" "INFO"
        
        while read -r domain; do
            [[ -z "$domain" ]] && continue
            
            log_message "Enumerating DNS records for $domain" "DEBUG"
            
            echo "# DNS records for $domain" >> "$output_file"
            host -a "$domain" >> "$output_file" 2>/dev/null
            
            echo -e "\n------------------------------------------\n" >> "$output_file"
        done < "$subdomains_file"
        
    else
        log_message "No DNS enumeration tools available. DNS enumeration skipped." "ERROR"
        echo "DNS enumeration skipped - no tools available" > "$output_file"
        end_function "dns_enum" 1 "DNS enumeration skipped - no tools available"
        return 1
    fi
    
    # Check if we got any results
    if [[ -s "$output_file" ]]; then
        log_message "DNS enumeration completed successfully" "SUCCESS"
        end_function "dns_enum" 0 "DNS enumeration completed successfully"
        return 0
    else
        log_message "DNS enumeration completed but no records found" "WARNING"
        echo "No DNS records found" > "$output_file"
        end_function "dns_enum" 0 "DNS enumeration completed - no records found"
        return 0
    fi
}

# Function to check which hosts are alive
function alive_hosts() {
    if is_completed "alive_hosts"; then
        log_message "Alive hosts check already completed for $target" "INFO"
        return 0
    fi
    
    start_function "alive_hosts" "Checking for Alive Hosts"
    
    # Create output directories
    mkdir -p "${target_dir}/recon/hosts" 2>/dev/null
    local subdomains_file="${target_dir}/recon/subdomains/subdomains.txt"
    local output_file="${target_dir}/recon/hosts/alive_hosts.txt"
    local ips_file="${target_dir}/recon/hosts/ip_addresses.txt"
    
    # Check if subdomains file exists
    if [[ ! -f "$subdomains_file" ]]; then
        log_message "No subdomains file found. Running subdomain enumeration first." "WARNING"
        subdomain_enum
    fi
    
    # Check again if subdomains file exists and is not empty
    if [[ ! -f "$subdomains_file" || ! -s "$subdomains_file" ]]; then
        log_message "Still no subdomains found. Using just the main target." "WARNING"
        echo "$target" > "$subdomains_file"
    fi
    
    log_message "Starting alive hosts check" "INFO"
    
    # Initialize output files
    > "$output_file"
    > "$ips_file"
    
    # Determine which tool to use for checking alive hosts
    if command_exists "httprobe"; then
        log_message "Using httprobe to find alive HTTP/HTTPS services" "INFO"
        
        # Check for HTTP/HTTPS services
        execute_command "cat \"$subdomains_file\" | httprobe -c 50 >> \"$output_file\"" "Finding alive HTTP/HTTPS services with httprobe" 300 2
        
        # Create HTTP hosts file
        mkdir -p "${target_dir}/recon/http" 2>/dev/null
        cp "$output_file" "${target_dir}/recon/http/http_hosts.txt"
        
        # Try to resolve IP addresses for alive hosts
        if command_exists "dig"; then
            log_message "Resolving IP addresses for alive hosts using dig" "INFO"
            
            while read -r host; do
                [[ -z "$host" ]] && continue
                
                # Extract domain from URL
                local domain=$(echo "$host" | sed 's/https\?:\/\///' | sed 's/:.*//' | sed 's/\/.*//')
                
                # Resolve IP address
                local ip=$(dig +short "$domain" | grep -v ";" | head -n 1)
                
                if [[ -n "$ip" ]]; then
                    echo "$domain,$ip" >> "$ips_file"
                fi
            done < "$output_file"
        fi
        
    elif command_exists "httpx"; then
        log_message "Using httpx to find alive HTTP/HTTPS services" "INFO"
        
        # Check for HTTP/HTTPS services
        execute_command "cat \"$subdomains_file\" | httpx -silent -follow-redirects >> \"$output_file\"" "Finding alive HTTP/HTTPS services with httpx" 300 2
        
        # Create HTTP hosts file
        mkdir -p "${target_dir}/recon/http" 2>/dev/null
        cp "$output_file" "${target_dir}/recon/http/http_hosts.txt"
        
        # Try to get IP addresses
        log_message "Resolving IP addresses for alive hosts using httpx" "INFO"
        execute_command "cat \"$subdomains_file\" | httpx -silent -ip >> \"${target_dir}/.tmp/httpx_ips.txt\"" "Resolving IP addresses with httpx" 300 2
        
        # Process the IPs
        if [[ -f "${target_dir}/.tmp/httpx_ips.txt" ]]; then
            while read -r line; do
                [[ -z "$line" ]] && continue
                
                local domain=$(echo "$line" | awk '{print $1}')
                local ip=$(echo "$line" | awk '{print $2}' | tr -d '[]')
                
                if [[ -n "$domain" && -n "$ip" ]]; then
                    echo "$domain,$ip" >> "$ips_file"
                fi
            done < "${target_dir}/.tmp/httpx_ips.txt"
        fi
        
    else
        log_message "No specialized tools found for checking alive hosts. Using basic curl checks." "WARNING"
        
        while read -r domain; do
            [[ -z "$domain" ]] && continue
            
            log_message "Checking if $domain is alive" "DEBUG"
            
            # Try HTTP
            local http_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "http://${domain}")
            
            if [[ "$http_status" != "000" ]]; then
                echo "http://${domain}" >> "$output_file"
                log_message "Found alive host: http://${domain} (Status: $http_status)" "INFO"
                
                # Try to resolve IP
                if command_exists "dig"; then
                    local ip=$(dig +short "$domain" | grep -v ";" | head -n 1)
                    
                    if [[ -n "$ip" ]]; then
                        echo "$domain,$ip" >> "$ips_file"
                    fi
                fi
            fi
            
            # Try HTTPS
            local https_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}")
            
            if [[ "$https_status" != "000" ]]; then
                echo "https://${domain}" >> "$output_file"
                log_message "Found alive host: https://${domain} (Status: $https_status)" "INFO"
            fi
        done < "$subdomains_file"
        
        # Create HTTP hosts file
        mkdir -p "${target_dir}/recon/http" 2>/dev/null
        cp "$output_file" "${target_dir}/recon/http/http_hosts.txt"
    fi
    
    # Check if we found any alive hosts
    if [[ -s "$output_file" ]]; then
        local host_count=$(wc -l < "$output_file")
        log_message "Alive hosts check completed. Found $host_count alive hosts." "SUCCESS"
        
        # Also check if we got IP addresses
        if [[ -s "$ips_file" ]]; then
            local ip_count=$(wc -l < "$ips_file")
            log_message "Resolved $ip_count IP addresses for the alive hosts." "INFO"
        else
            log_message "Could not resolve IP addresses for the alive hosts." "WARNING"
        fi
        
        end_function "alive_hosts" 0 "Alive hosts check completed successfully"
        return 0
    else
        log_message "No alive hosts found" "WARNING"
        echo "No alive hosts found" > "$output_file"
        end_function "alive_hosts" 0 "Alive hosts check completed - no alive hosts found"
        return 0
    fi
}

# Function to scrape URLs from websites
function url_scraping() {
    if is_completed "url_scraping"; then
        log_message "URL scraping already completed for $target" "INFO"
        return 0
    fi
    
    start_function "url_scraping" "Advanced URL Scraping & Web Archives for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/recon/urls" 2>/dev/null
    mkdir -p "${target_dir}/.tmp" 2>/dev/null
    local http_hosts="${target_dir}/recon/http/http_hosts.txt"
    local output_file="${target_dir}/recon/urls/all_urls.txt"
    local js_file="${target_dir}/recon/urls/js_urls.txt"
    local endpoints_file="${target_dir}/recon/urls/api_endpoints.txt"
    local archive_file="${target_dir}/recon/urls/archive_urls.txt"
    
    # Check if HTTP hosts file exists
    if [[ ! -f "$http_hosts" ]]; then
        log_message "No HTTP hosts file found. Running alive hosts check first." "WARNING"
        alive_hosts
    fi
    
    # Check again if HTTP hosts file exists and is not empty
    if [[ ! -f "$http_hosts" || ! -s "$http_hosts" ]]; then
        log_message "Still no HTTP hosts found. Using main target." "WARNING"
        mkdir -p "${target_dir}/recon/http" 2>/dev/null
        if is_valid_url "$target"; then
            echo "$target" > "$http_hosts"
        else
            echo "http://$target" > "$http_hosts"
        fi
    fi
    
    log_message "Starting enhanced URL scraping and web archive checks" "INFO"
    
    # Initialize output files
    > "$output_file"
    > "$js_file"
    > "$endpoints_file"
    > "$archive_file"
    
    # Check for API endpoints using custom wordlist
    log_message "Checking for common API endpoints" "INFO"
    local api_wordlist="${script_path}/modules/wordlists/api_endpoints.txt"
    
    if [[ -f "$api_wordlist" ]]; then
        log_message "Using custom API endpoints wordlist: $api_wordlist ($(wc -l < "$api_wordlist") entries)" "INFO"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            # Extract base domain without protocol
            local base_domain=$(echo "$host" | sed 's/https\?:\/\///')
            
            while read -r endpoint; do
                [[ -z "$endpoint" ]] && continue
                
                local test_url="${host%/}/${endpoint#/}"
                
                # Test the endpoint
                local status_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$test_url")
                
                # Consider 2xx, 3xx, and some 4xx codes as potentially valid
                if [[ "$status_code" =~ ^(2|3)[0-9]{2}$ || "$status_code" == "401" || "$status_code" == "403" ]]; then
                    echo "$test_url" >> "$endpoints_file"
                    echo "$test_url" >> "$output_file"
                    log_message "Found potential API endpoint: $test_url (Status: $status_code)" "INFO"
                fi
            done < "$api_wordlist"
        done < "$http_hosts"
    else
        log_message "API endpoints wordlist not found. Skipping API endpoint check." "WARNING"
    fi
    
    # Check web archives for additional URLs
    log_message "Checking web archives for historical URLs" "INFO"
    
    while read -r host; do
        [[ -z "$host" ]] && continue
        
        # Extract domain from URL
        local domain=$(echo "$host" | sed 's/https\?:\/\///' | sed 's/:.*//' | sed 's/\/.*//')
        
        log_message "Checking archive.org for $domain" "INFO"
        
        # Use curl to query the archive.org CDX API
        local archive_tmp="${target_dir}/.tmp/archive_${domain}.txt"
        curl -s "http://web.archive.org/cdx/search/cdx?url=${domain}/*&output=text&fl=original&collapse=urlkey" > "$archive_tmp"
        
        if [[ -s "$archive_tmp" ]]; then
            cat "$archive_tmp" >> "$archive_file"
            cat "$archive_tmp" >> "$output_file"
            log_message "Found $(wc -l < "$archive_tmp") URLs in web archives for $domain" "INFO"
        else
            log_message "No archived URLs found for $domain" "WARNING"
        fi
    done < "$http_hosts"
    
    # Determine which tool to use for URL scraping
    if command_exists "hakrawler"; then
        log_message "Using hakrawler for URL scraping" "INFO"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            log_message "Scraping URLs from $host" "INFO"
            execute_command "echo \"$host\" | hakrawler -plain -depth 2 -scope subs >> \"$output_file\"" "URL scraping with hakrawler" 300 2
        done < "$http_hosts"
        
    elif command_exists "gau" || command_exists "waybackurls"; then
        if command_exists "gau"; then
            log_message "Using gau for URL scraping" "INFO"
            
            while read -r host; do
                [[ -z "$host" ]] && continue
                
                # Extract domain from URL
                local domain=$(echo "$host" | sed 's/https\?:\/\///' | sed 's/:.*//' | sed 's/\/.*//')
                
                log_message "Scraping URLs from $domain" "INFO"
                execute_command "gau --subs $domain >> \"$output_file\"" "URL scraping with gau" 300 2
            done < "$http_hosts"
        fi
        
        if command_exists "waybackurls"; then
            log_message "Using waybackurls for URL scraping" "INFO"
            
            while read -r host; do
                [[ -z "$host" ]] && continue
                
                # Extract domain from URL
                local domain=$(echo "$host" | sed 's/https\?:\/\///' | sed 's/:.*//' | sed 's/\/.*//')
                
                log_message "Scraping URLs from $domain" "INFO"
                execute_command "waybackurls $domain >> \"$output_file\"" "URL scraping with waybackurls" 300 2
            done < "$http_hosts"
        fi
        
    else
        log_message "No specialized URL scraping tools found. Using basic curl and wget." "WARNING"
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            log_message "Basic scraping of $host" "INFO"
            
            # Create a temporary file for the HTML
            local tmp_html="${target_dir}/.tmp/$(echo "$host" | md5sum | cut -d' ' -f1).html"
            mkdir -p "${target_dir}/.tmp" 2>/dev/null
            
            # Download the HTML
            curl -s -L -m 10 "$host" > "$tmp_html"
            
            # Extract URLs from href attributes
            grep -o 'href="[^"]*"' "$tmp_html" | cut -d'"' -f2 | while read -r url; do
                # Handle relative URLs
                if [[ "$url" == /* ]]; then
                    # URL is relative to domain root
                    local domain=$(echo "$host" | grep -o 'https\?://[^/]*')
                    echo "${domain}${url}" >> "$output_file"
                elif [[ "$url" == http* ]]; then
                    # URL is already absolute
                    echo "$url" >> "$output_file"
                else
                    # URL is relative to current path
                    echo "${host%/}/${url}" >> "$output_file"
                fi
            done
            
            # Extract URLs from src attributes
            grep -o 'src="[^"]*"' "$tmp_html" | cut -d'"' -f2 | while read -r url; do
                # Handle relative URLs (same as above)
                if [[ "$url" == /* ]]; then
                    local domain=$(echo "$host" | grep -o 'https\?://[^/]*')
                    echo "${domain}${url}" >> "$output_file"
                elif [[ "$url" == http* ]]; then
                    echo "$url" >> "$output_file"
                else
                    echo "${host%/}/${url}" >> "$output_file"
                fi
            done
            
            # Clean up
            rm -f "$tmp_html" 2>/dev/null
        done < "$http_hosts"
    fi
    
    # Sort and deduplicate results
    if [[ -f "$output_file" ]]; then
        sort -u "$output_file" -o "$output_file"
        local url_count=$(wc -l < "$output_file")
        
        log_message "URL scraping completed. Found $url_count unique URLs." "SUCCESS"
        end_function "url_scraping" 0 "URL scraping completed successfully"
        return 0
    else
        log_message "URL scraping failed. No output file created." "ERROR"
        echo "URL scraping failed" > "$output_file"
        end_function "url_scraping" 1 "URL scraping failed"
        return 1
    fi
}

# Function to identify technologies used
function tech_detection() {
    if is_completed "tech_detection"; then
        log_message "Technology detection already completed for $target" "INFO"
        return 0
    fi
    
    start_function "tech_detection" "Technology Detection for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/recon/tech" 2>/dev/null
    local http_hosts="${target_dir}/recon/http/http_hosts.txt"
    local output_file="${target_dir}/recon/tech/technologies.txt"
    local json_output="${target_dir}/recon/tech/technologies.json"
    
    # Check if HTTP hosts file exists
    if [[ ! -f "$http_hosts" ]]; then
        log_message "No HTTP hosts file found. Running alive hosts check first." "WARNING"
        alive_hosts
    fi
    
    # Check again if HTTP hosts file exists and is not empty
    if [[ ! -f "$http_hosts" || ! -s "$http_hosts" ]]; then
        log_message "Still no HTTP hosts found. Using main target." "WARNING"
        mkdir -p "${target_dir}/recon/http" 2>/dev/null
        if is_valid_url "$target"; then
            echo "$target" > "$http_hosts"
        else
            echo "http://$target" > "$http_hosts"
        fi
    fi
    
    log_message "Starting technology detection" "INFO"
    
    # Initialize output files
    > "$output_file"
    echo "{" > "$json_output"
    echo "  \"technologies\": [" >> "$json_output"
    
    # Determine which tool to use for technology detection
    if command_exists "wappalyzer" && command_exists "node"; then
        log_message "Using Wappalyzer for technology detection" "INFO"
        
        local first_host=true
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            log_message "Detecting technologies on $host" "INFO"
            
            local tmp_json="${target_dir}/.tmp/$(echo "$host" | md5sum | cut -d' ' -f1).json"
            mkdir -p "${target_dir}/.tmp" 2>/dev/null
            
            execute_command "wappalyzer $host -P -j > \"$tmp_json\"" "Technology detection with Wappalyzer" 120 2
            
            if [[ -f "$tmp_json" && -s "$tmp_json" ]]; then
                # Extract technology names and append to text file
                jq -r '.technologies[].name' "$tmp_json" 2>/dev/null | sort -u > "${target_dir}/.tmp/tech_names.txt"
                
                if [[ -f "${target_dir}/.tmp/tech_names.txt" && -s "${target_dir}/.tmp/tech_names.txt" ]]; then
                    echo "Technologies detected on $host:" >> "$output_file"
                    cat "${target_dir}/.tmp/tech_names.txt" | sed 's/^/- /' >> "$output_file"
                    echo "" >> "$output_file"
                    
                    # Append to JSON output
                    if [[ "$first_host" == true ]]; then
                        first_host=false
                    else
                        echo "," >> "$json_output"
                    fi
                    
                    echo "    {" >> "$json_output"
                    echo "      \"host\": \"$host\"," >> "$json_output"
                    echo "      \"technologies\": [" >> "$json_output"
                    
                    local first_tech=true
                    while read -r tech; do
                        if [[ "$first_tech" == true ]]; then
                            echo "        \"$tech\"" >> "$json_output"
                            first_tech=false
                        else
                            echo "        ,\"$tech\"" >> "$json_output"
                        fi
                    done < "${target_dir}/.tmp/tech_names.txt"
                    
                    echo "      ]" >> "$json_output"
                    echo "    }" >> "$json_output"
                fi
            fi
        done < "$http_hosts"
        
    elif command_exists "whatweb"; then
        log_message "Using WhatWeb for technology detection" "INFO"
        
        local first_host=true
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            log_message "Detecting technologies on $host" "INFO"
            
            local tmp_output="${target_dir}/.tmp/$(echo "$host" | md5sum | cut -d' ' -f1).txt"
            mkdir -p "${target_dir}/.tmp" 2>/dev/null
            
            execute_command "whatweb -a 3 \"$host\" > \"$tmp_output\"" "Technology detection with WhatWeb" 120 2
            
            if [[ -f "$tmp_output" && -s "$tmp_output" ]]; then
                echo "Technologies detected on $host:" >> "$output_file"
                cat "$tmp_output" >> "$output_file"
                echo "" >> "$output_file"
                
                # Extract technologies for JSON output
                grep -o '\[[^]]*\]' "$tmp_output" | tr -d '[]' | tr ',' '\n' | sed 's/^ *//' | sort -u > "${target_dir}/.tmp/tech_names.txt"
                
                # Append to JSON output
                if [[ "$first_host" == true ]]; then
                    first_host=false
                else
                    echo "," >> "$json_output"
                fi
                
                echo "    {" >> "$json_output"
                echo "      \"host\": \"$host\"," >> "$json_output"
                echo "      \"technologies\": [" >> "$json_output"
                
                local first_tech=true
                while read -r tech; do
                    if [[ -n "$tech" ]]; then
                        if [[ "$first_tech" == true ]]; then
                            echo "        \"$tech\"" >> "$json_output"
                            first_tech=false
                        else
                            echo "        ,\"$tech\"" >> "$json_output"
                        fi
                    fi
                done < "${target_dir}/.tmp/tech_names.txt"
                
                echo "      ]" >> "$json_output"
                echo "    }" >> "$json_output"
            fi
        done < "$http_hosts"
        
    else
        log_message "No technology detection tools available. Using basic curl and header analysis." "WARNING"
        
        local first_host=true
        
        while read -r host; do
            [[ -z "$host" ]] && continue
            
            log_message "Basic technology detection on $host" "INFO"
            
            local tmp_headers="${target_dir}/.tmp/$(echo "$host" | md5sum | cut -d' ' -f1).headers"
            mkdir -p "${target_dir}/.tmp" 2>/dev/null
            
            # Get response headers
            curl -s -I -L -m 10 "$host" > "$tmp_headers"
            
            if [[ -f "$tmp_headers" && -s "$tmp_headers" ]]; then
                echo "Technologies detected on $host:" >> "$output_file"
                
                # Check for common technologies in headers
                local technologies=()
                
                # Server header
                local server=$(grep -i "^Server:" "$tmp_headers" | head -1 | cut -d' ' -f2-)
                if [[ -n "$server" ]]; then
                    technologies+=("$server")
                    echo "- Server: $server" >> "$output_file"
                fi
                
                # X-Powered-By header
                local powered_by=$(grep -i "^X-Powered-By:" "$tmp_headers" | head -1 | cut -d' ' -f2-)
                if [[ -n "$powered_by" ]]; then
                    technologies+=("$powered_by")
                    echo "- Powered By: $powered_by" >> "$output_file"
                fi
                
                # Content-Type header
                local content_type=$(grep -i "^Content-Type:" "$tmp_headers" | head -1 | cut -d' ' -f2-)
                if [[ -n "$content_type" ]]; then
                    echo "- Content Type: $content_type" >> "$output_file"
                fi
                
                # Check for common headers that indicate specific technologies
                grep -i "^X-AspNet-Version:" "$tmp_headers" && technologies+=("ASP.NET") && echo "- ASP.NET" >> "$output_file"
                grep -i "^X-Drupal" "$tmp_headers" && technologies+=("Drupal") && echo "- Drupal" >> "$output_file"
                grep -i "^X-Generator:" "$tmp_headers" | grep -i "WordPress" && technologies+=("WordPress") && echo "- WordPress" >> "$output_file"
                grep -i "^X-Shopify" "$tmp_headers" && technologies+=("Shopify") && echo "- Shopify" >> "$output_file"
                grep -i "^X-Magento" "$tmp_headers" && technologies+=("Magento") && echo "- Magento" >> "$output_file"
                grep -i "^X-Wix" "$tmp_headers" && technologies+=("Wix") && echo "- Wix" >> "$output_file"
                grep -i "^X-Joomla" "$tmp_headers" && technologies+=("Joomla") && echo "- Joomla" >> "$output_file"
                
                echo "" >> "$output_file"
                
                # Append to JSON output
                if [[ "$first_host" == true ]]; then
                    first_host=false
                else
                    echo "," >> "$json_output"
                fi
                
                echo "    {" >> "$json_output"
                echo "      \"host\": \"$host\"," >> "$json_output"
                echo "      \"technologies\": [" >> "$json_output"
                
                local first_tech=true
                for tech in "${technologies[@]}"; do
                    if [[ "$first_tech" == true ]]; then
                        echo "        \"$tech\"" >> "$json_output"
                        first_tech=false
                    else
                        echo "        ,\"$tech\"" >> "$json_output"
                    fi
                done
                
                echo "      ]" >> "$json_output"
                echo "    }" >> "$json_output"
            fi
        done < "$http_hosts"
    fi
    
    # Finalize JSON file
    echo "  ]" >> "$json_output"
    echo "}" >> "$json_output"
    
    # Check if we got any results
    if [[ -s "$output_file" ]]; then
        log_message "Technology detection completed successfully" "SUCCESS"
        end_function "tech_detection" 0 "Technology detection completed successfully"
        return 0
    else
        log_message "Technology detection completed but no technologies found" "WARNING"
        echo "No technologies detected" > "$output_file"
        echo "{\"technologies\": []}" > "$json_output"
        end_function "tech_detection" 0 "Technology detection completed - no technologies found"
        return 0
    fi
}

# Main recon function
function run_recon_module() {
    log_message "Starting reconnaissance module for $target" "INFO"
    
    # Create output directories
    mkdir -p "${target_dir}/recon" 2>/dev/null
    mkdir -p "${target_dir}/.tmp" 2>/dev/null
    
    # Create .called_fn directory with proper permissions
    CALLED_FN_DIR="${target_dir}/.called_fn"
    mkdir -p "$CALLED_FN_DIR" 2>/dev/null
    chmod 755 "$CALLED_FN_DIR" 2>/dev/null
    
    # Show banner
    show_recon_banner
    
    # Run recon functions in the most logical order
    subdomain_enum
    dns_enum
    alive_hosts
    url_scraping
    tech_detection
    
    # Clean up temp files
    rm -rf "${target_dir}/.tmp" 2>/dev/null
    
    log_message "Reconnaissance module completed for $target" "SUCCESS"
}

# Export functions
export -f subdomain_enum
export -f dns_enum
export -f alive_hosts
export -f url_scraping
export -f tech_detection
export -f run_recon_module