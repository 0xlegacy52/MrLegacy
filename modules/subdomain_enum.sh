#!/bin/bash
# MR Legacy - Subdomain Enumeration Module

# Function to run Sublist3r
run_sublist3r() {
    local domain="$1"
    local output_file="$2"
    local threads="$3"
    
    if is_tool_installed "sublist3r"; then
        log_message "Running Sublist3r on $domain..." "INFO"
        sublist3r -d "$domain" -t "$threads" -o "$output_file.sublist3r" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            log_message "Sublist3r completed successfully" "SUCCESS"
        else
            log_message "Sublist3r failed" "ERROR"
        fi
    else
        log_message "Sublist3r not found" "WARNING"
    fi
}

# Function to run Amass (enhanced with both passive and active modes)
run_amass() {
    local domain="$1"
    local output_file="$2"
    
    if is_tool_installed "amass"; then
        # Run in passive mode first
        log_message "Running Amass (passive mode) on $domain..." "INFO"
        amass enum --passive -d "$domain" -o "$output_file.amass_passive" > /dev/null 2>&1
        
        # Run in active mode if deep scan is enabled
        if [ "$DEEP" = true ]; then
            log_message "Running Amass (active mode) on $domain..." "INFO"
            amass enum -active -d "$domain" -o "$output_file.amass_active" > /dev/null 2>&1
            
            # Run with brute forcing if deep scan is enabled
            log_message "Running Amass (brute-force mode) on $domain..." "INFO"
            amass enum -active -brute -min-for-recursive 2 -d "$domain" -o "$output_file.amass_brute" > /dev/null 2>&1
        fi
        
        log_message "Amass completed successfully" "SUCCESS"
    else
        log_message "Amass not found" "WARNING"
    fi
}

# Function to run Subfinder (enhanced with recursive mode)
run_subfinder() {
    local domain="$1"
    local output_file="$2"
    local threads="$3"
    
    if is_tool_installed "subfinder"; then
        log_message "Running Subfinder on $domain..." "INFO"
        if [ "$DEEP" = true ]; then
            subfinder -d "$domain" -all -recursive -t "$threads" -o "$output_file.subfinder" > /dev/null 2>&1
        else
            subfinder -d "$domain" -t "$threads" -o "$output_file.subfinder" > /dev/null 2>&1
        fi
        
        if [ $? -eq 0 ]; then
            log_message "Subfinder completed successfully" "SUCCESS"
        else
            log_message "Subfinder failed" "ERROR"
        fi
    else
        log_message "Subfinder not found" "WARNING"
    fi
}

# Function to run Findomain
run_findomain() {
    local domain="$1"
    local output_file="$2"
    
    if is_tool_installed "findomain"; then
        log_message "Running Findomain on $domain..." "INFO"
        findomain -q -t "$domain" -o "$output_file.findomain" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            log_message "Findomain completed successfully" "SUCCESS"
        else
            log_message "Findomain failed" "ERROR"
        fi
    else
        log_message "Findomain not found" "WARNING"
    fi
}

# Function to run Assetfinder
run_assetfinder() {
    local domain="$1"
    local output_file="$2"
    
    if is_tool_installed "assetfinder"; then
        log_message "Running Assetfinder on $domain..." "INFO"
        assetfinder --subs-only "$domain" > "$output_file.assetfinder"
        if [ $? -eq 0 ]; then
            log_message "Assetfinder completed successfully" "SUCCESS"
        else
            log_message "Assetfinder failed" "ERROR"
        fi
    else
        log_message "Assetfinder not found" "WARNING"
    fi
}

# Function to query Certificate Transparency logs via crt.sh
run_crtsh() {
    local domain="$1"
    local output_file="$2"
    
    log_message "Querying Certificate Transparency logs (crt.sh)..." "INFO"
    
    # Use curl to fetch data from crt.sh
    if is_tool_installed "curl"; then
        if is_tool_installed "jq"; then
            # Method 1: Basic query
            curl -s "https://crt.sh/?q=$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "$output_file.crtsh"
            
            # Method 2: Wildcard query (finds more subdomains)
            if [ "$DEEP" = true ]; then
                curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> "$output_file.crtsh"
            fi
            
            log_message "Certificate Transparency logs query completed successfully" "SUCCESS"
        else
            # Fallback if jq is not installed
            curl -s "https://crt.sh/?q=$domain" | grep -oP '(?<=<TD>)[^<]*\.'$domain | sort -u > "$output_file.crtsh"
            log_message "Certificate Transparency logs query completed (limited without jq)" "WARNING"
        fi
    else
        log_message "curl not found, skipping Certificate Transparency logs query" "WARNING"
    fi
}

# Function to query Anubis (JLDC)
run_anubis() {
    local domain="$1"
    local output_file="$2"
    
    log_message "Querying Anubis (JLDC) for subdomains..." "INFO"
    
    if is_tool_installed "curl"; then
        curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$output_file.anubis"
        
        if [ $? -eq 0 ]; then
            log_message "Anubis query completed successfully" "SUCCESS"
        else
            log_message "Anubis query failed" "ERROR"
        fi
    else
        log_message "curl not found, skipping Anubis query" "WARNING"
    fi
}

# Function to query Certspotter API
run_certspotter() {
    local domain="$1"
    local output_file="$2"
    
    log_message "Querying Certspotter API for subdomains..." "INFO"
    
    if is_tool_installed "curl"; then
        if is_tool_installed "jq"; then
            curl -s "https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | grep -E "\.$domain$" | sort -u > "$output_file.certspotter"
            
            if [ $? -eq 0 ]; then
                log_message "Certspotter API query completed successfully" "SUCCESS"
            else
                log_message "Certspotter API query failed" "ERROR"
            fi
        else
            log_message "jq not found, skipping Certspotter API query" "WARNING"
        fi
    else
        log_message "curl not found, skipping Certspotter API query" "WARNING"
    fi
}

# Function to use TheHarvester for search engine based enumeration
run_theharvester() {
    local domain="$1"
    local output_file="$2"
    
    if is_tool_installed "theHarvester"; then
        log_message "Running TheHarvester on $domain..." "INFO"
        theHarvester -d "$domain" -l 500 -b all 2>/dev/null | grep -o -E "[a-zA-Z0-9._-]+\.$domain" > "$output_file.theharvester"
        
        if [ $? -eq 0 ]; then
            log_message "TheHarvester completed successfully" "SUCCESS"
        else
            log_message "TheHarvester failed" "ERROR"
        fi
    else
        log_message "TheHarvester not found" "WARNING"
    fi
}

# Function to use Gobuster for DNS brute-forcing
run_gobuster_dns() {
    local domain="$1"
    local output_file="$2"
    local threads="$3"
    
    if is_tool_installed "gobuster"; then
        log_message "Running Gobuster DNS brute-force on $domain..." "INFO"
        
        # Create a basic wordlist if none exists
        local wordlist="/tmp/basic_subdomains.txt"
        if [ ! -f "$wordlist" ]; then
            echo "www" > "$wordlist"
            echo "mail" >> "$wordlist"
            echo "remote" >> "$wordlist"
            echo "blog" >> "$wordlist"
            echo "webmail" >> "$wordlist"
            echo "server" >> "$wordlist"
            echo "ns1" >> "$wordlist"
            echo "ns2" >> "$wordlist"
            echo "smtp" >> "$wordlist"
            echo "secure" >> "$wordlist"
            echo "vpn" >> "$wordlist"
            echo "admin" >> "$wordlist"
            echo "intranet" >> "$wordlist"
            echo "dev" >> "$wordlist"
            echo "test" >> "$wordlist"
            echo "portal" >> "$wordlist"
            echo "api" >> "$wordlist"
            echo "stage" >> "$wordlist"
            echo "cdn" >> "$wordlist"
            echo "app" >> "$wordlist"
            log_message "Created basic subdomain wordlist" "INFO"
        fi
        
        # Run Gobuster DNS
        gobuster dns -d "$domain" -w "$wordlist" -t "$threads" -o "$output_file.gobuster" > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            log_message "Gobuster DNS brute-force completed successfully" "SUCCESS"
        else
            log_message "Gobuster DNS brute-force failed" "ERROR"
        fi
    else
        log_message "Gobuster not found" "WARNING"
    fi
}

# Function to check for common CMS-related subdomains
check_cms_subdomains() {
    local domain="$1"
    local output_file="$2"
    
    log_message "Checking for common CMS-related subdomains..." "INFO"
    
    # Common CMS-related subdomains
    local cms_subdomains=(
        "wp"
        "wordpress"
        "wp-admin"
        "blog"
        "weblog"
        "joomla"
        "drupal"
        "cpanel"
        "whm"
        "admin"
        "administration"
        "cms"
        "shop"
        "store"
        "woocommerce"
        "magento"
        "staging"
        "dev"
        "development"
        "test"
        "testing"
        "beta"
        "demo"
    )
    
    # Check each subdomain using host command
    for sub in "${cms_subdomains[@]}"; do
        if is_tool_installed "host"; then
            host "$sub.$domain" > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "$sub.$domain" >> "$output_file.cms"
            fi
        else
            # Fallback to ping if host is not available
            ping -c 1 "$sub.$domain" > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "$sub.$domain" >> "$output_file.cms"
            fi
        fi
    done
    
    if [ -f "$output_file.cms" ]; then
        log_message "CMS subdomain check completed successfully" "SUCCESS"
    else
        # Create empty file to avoid errors in merge process
        touch "$output_file.cms"
        log_message "No CMS-related subdomains found" "INFO"
    fi
}

# Function to merge and sort unique subdomains
merge_subdomains() {
    local output_dir="$1"
    local merged_file="$2"
    
    log_message "Merging subdomain results..." "INFO"
    
    # Create a temporary file for merging
    tmp_file=$(mktemp)
    
    # Find all subdomain files and merge them
    find "$output_dir" -name "*.sublist3r" -o -name "*.amass*" -o -name "*.subfinder" \
        -o -name "*.findomain" -o -name "*.assetfinder" -o -name "*.crtsh" \
        -o -name "*.anubis" -o -name "*.certspotter" -o -name "*.theharvester" \
        -o -name "*.gobuster" -o -name "*.cms" | xargs cat 2>/dev/null > "$tmp_file"
    
    # Sort unique entries
    sort -u "$tmp_file" > "$merged_file"
    
    # Count unique subdomains
    count=$(wc -l < "$merged_file")
    
    # Cleanup temporary file
    rm -f "$tmp_file"
    
    log_message "Found $count unique subdomains" "SUCCESS"
}

# Main function to run subdomain enumeration
run_subdomain_enum() {
    log_message "Starting subdomain enumeration on $target..." "INFO"
    
    # Setup Tor proxy if enabled
    setup_tor_proxy
    
    # Create output directory
    local output_dir="$target_dir/recon/subdomains"
    mkdir -p "$output_dir"
    
    # Extract base domain
    local domain=$(extract_domain "$target")
    
    # Temporary files for results
    local temp_file=$(mktemp)
    local merged_file="$output_dir/subdomains.txt"
    
    # Run traditional tool-based enumeration
    run_sublist3r "$domain" "$output_dir/subdomains" "$THREADS"
    run_amass "$domain" "$output_dir/subdomains"
    run_subfinder "$domain" "$output_dir/subdomains" "$THREADS"
    run_findomain "$domain" "$output_dir/subdomains"
    run_assetfinder "$domain" "$output_dir/subdomains"
    
    # Run API-based and passive techniques
    run_crtsh "$domain" "$output_dir/subdomains"
    run_anubis "$domain" "$output_dir/subdomains" 
    run_certspotter "$domain" "$output_dir/subdomains"
    run_theharvester "$domain" "$output_dir/subdomains"
    
    # Run brute-force techniques if deep scan is enabled
    if [ "$DEEP" = true ]; then
        run_gobuster_dns "$domain" "$output_dir/subdomains" "$THREADS"
    fi
    
    # Check for common CMS-related subdomains
    check_cms_subdomains "$domain" "$output_dir/subdomains"
    
    # Merge results
    merge_subdomains "$output_dir" "$merged_file"
    
    # Save results in different formats
    save_results "$merged_file" "$output_dir" "subdomains" "$OUTPUT_FORMAT"
    
    log_message "Subdomain enumeration completed" "SUCCESS"
    return 0
}
