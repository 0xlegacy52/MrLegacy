#!/bin/bash

# MR Legacy - OSINT (Open Source Intelligence) Module
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.1.0

# Source helper functions
if [[ -f "utils/helpers.sh" ]]; then
    source "utils/helpers.sh"
fi

# Create necessary variables to track module execution
CALLED_FN_DIR="${target_dir}/.called_fn"
mkdir -p "$CALLED_FN_DIR" 2>/dev/null
chmod 755 "$CALLED_FN_DIR" 2>/dev/null

# Function to display banner
function show_osint_banner() {
    echo -e "${BLUE}
  ____  _____ ___ _   _ _____   __  __  ___  ____  _   _ _     _____ 
 / __ \/ ____|_ _| \ | |_   _| |  \/  |/ _ \|  _ \| | | | |   | ____|
| |  | \\___ \| ||  \| | | |   | |\/| | | | | | | | | | | |   |  _|  
| |  | |___) | || |\  | | |   | |  | | |_| | |_| | |_| | |___| |___ 
 \____/|____/___|_| \_| |_|   |_|  |_|\___/|____/ \___/|_____|_____|
                                                                                              
${NC}"
    echo -e "${YELLOW}[+] OSINT Module - Gathering Intelligence${NC}"
    echo -e "${YELLOW}[+] Target: $target${NC}"
    echo "=============================================================="
}

# Function to search for email addresses with enhanced capabilities
function email_discovery() {
    if is_completed "email_discovery"; then
        log_message "Email discovery already completed for $target" "INFO"
        return 0
    fi
    
    start_function "email_discovery" "Enhanced Email Discovery for $target"
    
    mkdir -p "$target_dir/osint/emails" 2>/dev/null
    output_file="$target_dir/osint/emails/discovered_emails.txt"
    username_patterns="$target_dir/osint/emails/username_patterns.txt"
    domain_file="$target_dir/osint/emails/target_domains.txt"
    email_analysis="$target_dir/osint/emails/email_analysis.md"
    
    # Extract root domain and subdomains
    root_domain=$(echo "$target" | awk -F/ '{print $1}' | sed -E 's/^(www\.)?(.*)$/\2/')
    
    # Create list of target domains to search for emails
    echo "$root_domain" > "$domain_file"
    
    # Add subdomains if we have them
    if [[ -f "$target_dir/recon/subdomains.txt" ]]; then
        log_message "Including subdomains in email search" "INFO"
        cat "$target_dir/recon/subdomains.txt" >> "$domain_file"
    fi
    
    log_message "Searching for email addresses related to $target using multiple techniques" "INFO"
    
    # Initialize email collection
    touch "$output_file"
    
    # 1. Advanced Tool-Based Discovery
    if command_exists theHarvester; then
        log_message "Using theHarvester for email discovery (multiple data sources)" "INFO"
        theHarvester -d "$root_domain" -b all -f "$target_dir/osint/emails/harvester_output.html" > "$target_dir/osint/emails/harvester_raw.txt" 2>/dev/null
        
        # Extract emails from harvester output
        grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$target_dir/osint/emails/harvester_raw.txt" | sort -u >> "$output_file"
    else
        log_message "theHarvester not found, using alternative methods" "WARNING"
    fi
    
    # 2. DNS-based Email Discovery (MX records)
    log_message "Checking MX records for potential mail servers" "INFO"
    for domain in $(cat "$domain_file"); do
        dig +short MX "$domain" 2>/dev/null | sort -u > "$target_dir/osint/emails/mx_records.txt"
        
        # Look for common mail server patterns
        if grep -q "google\|gmail\|googlemail" "$target_dir/osint/emails/mx_records.txt"; then
            echo "[+] $domain likely uses Google Workspace for email" >> "$email_analysis"
        elif grep -q "outlook\|office365\|microsoft" "$target_dir/osint/emails/mx_records.txt"; then
            echo "[+] $domain likely uses Microsoft Office 365/Exchange for email" >> "$email_analysis"
        elif grep -q "protonmail" "$target_dir/osint/emails/mx_records.txt"; then
            echo "[+] $domain likely uses ProtonMail for email" >> "$email_analysis"
        fi
    done
    
    # 3. Web-based Discovery
    log_message "Performing targeted web scraping for email addresses" "INFO"
    
    # Common pages where emails might be found
    common_pages=("contact" "about" "team" "staff" "support" "help" "privacy" "legal" "careers")
    
    for domain in $(cat "$domain_file"); do
        # Check main website
        curl -s -L "https://$domain" | grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort -u >> "$output_file"
        
        # Check common pages where emails might be found
        for page in "${common_pages[@]}"; do
            curl -s -L "https://$domain/$page" 2>/dev/null | grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" | sort -u >> "$output_file"
        done
    done
    
    # 4. Common Email Pattern Generation
    log_message "Generating common email patterns" "INFO"
    
    # If we have found company/employee names, generate potential email patterns
    if [[ -f "$target_dir/osint/employees.txt" ]]; then
        # Initialize pattern file
        echo "# Common Email Patterns" > "$username_patterns"
        echo "The following email patterns are commonly used in organizations:" >> "$username_patterns"
        echo "1. firstname.lastname@domain" >> "$username_patterns"
        echo "2. firstinitial.lastname@domain" >> "$username_patterns"
        echo "3. firstname@domain" >> "$username_patterns"
        echo "4. firstinitiallastname@domain" >> "$username_patterns"
        echo "5. lastname.firstname@domain" >> "$username_patterns"
        echo "6. lastname@domain" >> "$username_patterns"
        echo "" >> "$username_patterns"
        echo "## Potential Email Addresses Based on Discovered Names" >> "$username_patterns"
        
        # Generate email addresses based on patterns
        while read -r fullname; do
            # Skip empty lines
            [[ -z "$fullname" ]] && continue
            
            # Extract first and last name
            firstname=$(echo "$fullname" | awk '{print tolower($1)}')
            lastname=$(echo "$fullname" | awk '{print tolower($NF)}')
            firstinitial="${firstname:0:1}"
            
            # Skip if names are too short (likely parsing errors)
            [[ ${#firstname} -lt 2 || ${#lastname} -lt 2 ]] && continue
            
            # Generate pattern examples for the first few employees
            echo "### $fullname" >> "$username_patterns"
            
            for domain in $(head -1 "$domain_file"); do
                echo "- ${firstname}.${lastname}@${domain}" >> "$username_patterns"
                echo "- ${firstinitial}.${lastname}@${domain}" >> "$username_patterns"
                echo "- ${firstinitial}${lastname}@${domain}" >> "$username_patterns"
                echo "- ${lastname}.${firstname}@${domain}" >> "$username_patterns"
            done
            echo "" >> "$username_patterns"
            
            # Add a few examples to validation list for verification
            for domain in $(head -1 "$domain_file"); do
                echo "${firstname}.${lastname}@${domain}" >> "$target_dir/osint/emails/generated_emails.txt"
                echo "${firstinitial}.${lastname}@${domain}" >> "$target_dir/osint/emails/generated_emails.txt"
                echo "${firstinitial}${lastname}@${domain}" >> "$target_dir/osint/emails/generated_emails.txt"
            done
        done < <(head -10 "$target_dir/osint/employees.txt" 2>/dev/null)
    fi
        rm -f "$target_dir/.tmp_harvester.txt" 2>/dev/null
    else
        log_message "No specialized email discovery tools found. Using basic methods." "WARNING"
        
        # Try to find email patterns from target website
        curl -s "https://$target" | grep -E -o "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sort -u > "$output_file"
        
        # Try to find email patterns from Google search results
        log_message "Searching for email addresses via web searches" "INFO"
        curl -s "https://www.google.com/search?q=email+%40$target" | grep -E -o "[a-zA-Z0-9._%+-]+@$target" | sort -u >> "$output_file"
    fi
    
    # Count the discovered emails
    email_count=$(wc -l < "$output_file")
    
    if [[ $email_count -gt 0 ]]; then
        log_message "Email discovery completed. Found $email_count email addresses." "SUCCESS"
    else
        log_message "No email addresses found." "WARNING"
        echo "No email addresses found." > "$output_file"
    fi
    
    end_function "email_discovery" $?
}

# Function to discover social media profiles
function social_media_discovery() {
    if is_completed "social_media_discovery"; then
        log_message "Social media discovery already completed for $target" "INFO"
        return 0
    fi
    
    start_function "social_media_discovery" "Social Media Discovery for $target"
    
    mkdir -p "$target_dir/osint/social_media" 2>/dev/null
    output_file="$target_dir/osint/social_media.txt"
    
    log_message "Searching for social media profiles related to $target" "INFO"
    
    # Define the list of social media platforms to check
    platforms=(
        "twitter.com"
        "facebook.com"
        "linkedin.com"
        "instagram.com"
        "github.com"
        "youtube.com"
        "medium.com"
        "pinterest.com"
        "reddit.com"
    )
    
    # Initialize output file
    echo "Social Media Profiles for $target" > "$output_file"
    echo "==============================================" >> "$output_file"
    echo "" >> "$output_file"
    
    # Function to check if webpage contains links to social media
    function check_social_media_links() {
        local url="$1"
        local content
        
        if [[ "$url" != http* ]]; then
            url="https://$url"
        fi
        
        content=$(curl -s "$url")
        
        for platform in "${platforms[@]}"; do
            if echo "$content" | grep -q "$platform"; then
                log_message "Found potential $platform profile" "INFO"
                echo "Potential $platform profile found on $url" >> "$output_file"
                
                # Extract links for the platform
                echo "$content" | grep -o "https://[^\"]*$platform[^\"]*" | sort -u >> "$target_dir/osint/social_media/$platform.txt"
            fi
        done
    }
    
    # Check main website for social media links
    log_message "Checking main website for social media links" "INFO"
    check_social_media_links "$target"
    
    # Check www subdomain if different
    if [[ "$target" != www.* ]]; then
        log_message "Checking www subdomain for social media links" "INFO"
        check_social_media_links "www.$target"
    fi
    
    # Consolidate results
    found_profiles=0
    for platform in "${platforms[@]}"; do
        if [[ -f "$target_dir/osint/social_media/$platform.txt" ]]; then
            platform_count=$(wc -l < "$target_dir/osint/social_media/$platform.txt")
            if [[ $platform_count -gt 0 ]]; then
                echo "" >> "$output_file"
                echo "$platform: Found $platform_count potential profiles" >> "$output_file"
                cat "$target_dir/osint/social_media/$platform.txt" >> "$output_file"
                ((found_profiles++))
            fi
        fi
    done
    
    if [[ $found_profiles -gt 0 ]]; then
        log_message "Social media discovery completed. Found profiles on $found_profiles platforms." "SUCCESS"
    else
        log_message "No social media profiles found." "WARNING"
        echo "No social media profiles found." >> "$output_file"
    fi
    
    end_function "social_media_discovery" $?
}

# Function to find company information
function company_info() {
    if is_completed "company_info"; then
        log_message "Company information discovery already completed for $target" "INFO"
        return 0
    fi
    
    start_function "company_info" "Company Information Discovery for $target"
    
    mkdir -p "$target_dir/osint" 2>/dev/null
    output_file="$target_dir/osint/company_info.txt"
    
    log_message "Searching for company information related to $target" "INFO"
    
    # Initialize output file
    echo "Company Information for $target" > "$output_file"
    echo "==============================================" >> "$output_file"
    echo "" >> "$output_file"
    
    # Get WHOIS information if available
    if command_exists whois; then
        log_message "Getting WHOIS information" "INFO"
        echo "WHOIS Information:" >> "$output_file"
        echo "----------------------------" >> "$output_file"
        whois "$target" | grep -iE "registrant|admin|tech|organization|address|phone|email" | grep -v "REDACTED" >> "$output_file"
        echo "" >> "$output_file"
    else
        log_message "whois command not available. Skipping WHOIS lookup." "WARNING"
        echo "WHOIS Information: Not available (whois command missing)" >> "$output_file"
        echo "" >> "$output_file"
    fi
    
    # Get DNS information
    log_message "Getting DNS information" "INFO"
    echo "DNS Information:" >> "$output_file"
    echo "----------------------------" >> "$output_file"
    
    if command_exists dig; then
        dig +short "$target" >> "$output_file"
        dig +short MX "$target" >> "$output_file"
        dig +short TXT "$target" >> "$output_file"
    elif command_exists nslookup; then
        nslookup "$target" | grep -v "^$" >> "$output_file"
        nslookup -type=MX "$target" | grep -v "^$" >> "$output_file"
        nslookup -type=TXT "$target" | grep -v "^$" >> "$output_file"
    else
        log_message "No DNS lookup tools available" "WARNING"
        echo "DNS Information: Not available (dig/nslookup missing)" >> "$output_file"
    fi
    
    echo "" >> "$output_file"
    
    # Look for SSL certificate information
    log_message "Getting SSL certificate information" "INFO"
    echo "SSL Certificate Information:" >> "$output_file"
    echo "----------------------------" >> "$output_file"
    
    ssl_info=$(curl -s --connect-timeout 5 --insecure -v "https://$target" 2>&1 | grep -i "subject\|issuer\|expire")
    
    if [[ -n "$ssl_info" ]]; then
        echo "$ssl_info" >> "$output_file"
    else
        echo "Could not retrieve SSL certificate information" >> "$output_file"
    fi
    
    echo "" >> "$output_file"
    
    log_message "Company information discovery completed" "SUCCESS"
    
    end_function "company_info" $?
}

# Function to find subdomains using OSINT methods
function osint_subdomains() {
    if is_completed "osint_subdomains"; then
        log_message "OSINT subdomain discovery already completed for $target" "INFO"
        return 0
    fi
    
    start_function "osint_subdomains" "OSINT Subdomain Discovery for $target"
    
    mkdir -p "$target_dir/osint" 2>/dev/null
    output_file="$target_dir/osint/subdomains.txt"
    
    log_message "Searching for subdomains using OSINT methods" "INFO"
    
    # Initialize output file
    > "$output_file"
    
    # Check for certificate transparency logs
    log_message "Checking certificate transparency logs" "INFO"
    
    if command_exists openssl; then
        openssl s_client -connect "$target:443" -showcerts </dev/null 2>/dev/null | grep -i "DNS:" | sed 's/DNS://g' | tr ',' '\n' | sort -u >> "$output_file"
    fi
    
    # Use crt.sh for certificate transparency logs if curl is available
    if command_exists curl; then
        log_message "Querying crt.sh for certificate transparency logs" "INFO"
        curl -s "https://crt.sh/?q=%25.$target" | grep -oP '(?<=<TD>)[^<]*\.'$target | sort -u >> "$output_file"
    fi
    
    # Query cloud providers for potential subdomains
    log_message "Checking common cloud subdomains" "INFO"
    
    # AWS S3 bucket naming pattern
    if command_exists curl; then
        curl -s -o /dev/null -w "%{http_code}" "https://$target.s3.amazonaws.com" | grep -q "200\|403" && echo "$target.s3.amazonaws.com" >> "$output_file"
    fi
    
    # Check common subdomains
    log_message "Checking common subdomains" "INFO"
    
    common_subdomains=(
        "www"
        "mail"
        "remote"
        "blog"
        "webmail"
        "server"
        "ns1"
        "ns2"
        "smtp"
        "secure"
        "vpn"
        "api"
        "dev"
        "staging"
        "test"
        "portal"
        "admin"
        "cdn"
        "cloud"
        "shop"
        "store"
        "support"
        "help"
        "login"
        "m"
        "mobile"
        "app"
        "docs"
        "status"
    )
    
    for subdomain in "${common_subdomains[@]}"; do
        if command_exists curl; then
            status_code=$(curl -s -o /dev/null -w "%{http_code}" "https://$subdomain.$target" 2>/dev/null)
            
            if [[ "$status_code" =~ ^[23] || "$status_code" == "401" || "$status_code" == "403" ]]; then
                echo "$subdomain.$target" >> "$output_file"
                log_message "Found potential subdomain: $subdomain.$target (Status: $status_code)" "INFO"
            fi
        fi
    done
    
    # Sort and remove duplicates
    if [[ -f "$output_file" ]]; then
        sort -u "$output_file" -o "$output_file"
        subdomain_count=$(wc -l < "$output_file")
        
        if [[ $subdomain_count -gt 0 ]]; then
            log_message "OSINT subdomain discovery completed. Found $subdomain_count potential subdomains." "SUCCESS"
        else
            log_message "No subdomains found via OSINT methods." "WARNING"
            echo "No subdomains found." > "$output_file"
        fi
    else
        log_message "No subdomains found via OSINT methods." "WARNING"
        echo "No subdomains found." > "$output_file"
    fi
    
    end_function "osint_subdomains" $?
}

# Function to find leaked credentials
function leaked_credentials() {
    if is_completed "leaked_credentials"; then
        log_message "Leaked credentials search already completed for $target" "INFO"
        return 0
    fi
    
    start_function "leaked_credentials" "Leaked Credentials Search for $target"
    
    mkdir -p "$target_dir/osint" 2>/dev/null
    output_file="$target_dir/osint/leaked_credentials.txt"
    
    log_message "Searching for potentially leaked credentials" "INFO"
    
    # Initialize output file
    echo "Potential Leaked Credentials for $target" > "$output_file"
    echo "==============================================" >> "$output_file"
    echo "" >> "$output_file"
    echo "NOTE: This data is for informational purposes only." >> "$output_file"
    echo "Do not attempt to use any credentials found." >> "$output_file"
    echo "Report any findings to the organization immediately." >> "$output_file"
    echo "" >> "$output_file"
    
    # Look for potential leaks in GitHub
    if command_exists curl; then
        log_message "Searching GitHub for potential leaks" "INFO"
        
        echo "GitHub Search Results:" >> "$output_file"
        echo "----------------------------" >> "$output_file"
        
        # Search for domain in GitHub
        github_domain_results=$(curl -s "https://api.github.com/search/code?q=$target" | grep -o '"html_url": "[^"]*"' | cut -d'"' -f4)
        
        if [[ -n "$github_domain_results" ]]; then
            echo "$github_domain_results" >> "$output_file"
            log_message "Found potential GitHub repositories mentioning the domain" "INFO"
        else
            echo "No GitHub repositories found mentioning the domain" >> "$output_file"
        fi
        
        echo "" >> "$output_file"
        
        # Search for potential password leaks
        echo "Potential Password/API Key Leaks:" >> "$output_file"
        echo "----------------------------" >> "$output_file"
        
        github_password_results=$(curl -s "https://api.github.com/search/code?q=$target+password" | grep -o '"html_url": "[^"]*"' | cut -d'"' -f4)
        github_apikey_results=$(curl -s "https://api.github.com/search/code?q=$target+apikey" | grep -o '"html_url": "[^"]*"' | cut -d'"' -f4)
        github_key_results=$(curl -s "https://api.github.com/search/code?q=$target+key" | grep -o '"html_url": "[^"]*"' | cut -d'"' -f4)
        
        combined_results="$github_password_results
$github_apikey_results
$github_key_results"
        
        if [[ -n "$combined_results" ]]; then
            echo "$combined_results" | sort -u >> "$output_file"
            log_message "Found potential repositories with sensitive keywords" "WARNING"
        else
            echo "No obvious GitHub leaks found" >> "$output_file"
        fi
    else
        log_message "curl not available. Skipping GitHub leak search." "WARNING"
        echo "GitHub Search: Not available (curl missing)" >> "$output_file"
    fi
    
    echo "" >> "$output_file"
    
    # Check for public paste sites
    log_message "Searching public paste sites for potential leaks" "INFO"
    
    echo "Public Paste Sites:" >> "$output_file"
    echo "----------------------------" >> "$output_file"
    
    if command_exists curl; then
        # Check Pastebin (note: this is a very basic check, Pastebin API would be better)
        pastebin_results=$(curl -s "https://www.google.com/search?q=site:pastebin.com+$target" | grep -o 'https://pastebin.com/[^"]*' | sort -u)
        
        if [[ -n "$pastebin_results" ]]; then
            echo "Potential Pastebin leaks:" >> "$output_file"
            echo "$pastebin_results" >> "$output_file"
            log_message "Found potential Pastebin leaks" "WARNING"
        else
            echo "No obvious Pastebin leaks found" >> "$output_file"
        fi
        
        echo "" >> "$output_file"
    else
        log_message "curl not available. Skipping public paste site search." "WARNING"
        echo "Public Paste Sites: Not available (curl missing)" >> "$output_file"
    fi
    
    log_message "Leaked credentials search completed" "SUCCESS"
    
    end_function "leaked_credentials" $?
}

# Function to summarize OSINT findings
function osint_summary() {
    if is_completed "osint_summary"; then
        log_message "OSINT summary already completed for $target" "INFO"
        return 0
    fi
    
    start_function "osint_summary" "OSINT Summary for $target"
    
    mkdir -p "$target_dir/osint" 2>/dev/null
    output_file="$target_dir/osint/summary.txt"
    
    log_message "Generating OSINT summary" "INFO"
    
    # Initialize output file
    echo "OSINT Summary for $target" > "$output_file"
    echo "==============================================" >> "$output_file"
    echo "Date: $(date)" >> "$output_file"
    echo "" >> "$output_file"
    
    # Email addresses
    if [[ -f "$target_dir/osint/emails.txt" ]]; then
        email_count=$(wc -l < "$target_dir/osint/emails.txt")
        echo "Email Addresses: $email_count" >> "$output_file"
    else
        echo "Email Addresses: Not checked" >> "$output_file"
    fi
    
    # Social media profiles
    if [[ -f "$target_dir/osint/social_media.txt" ]]; then
        profile_count=$(grep -c "profile found" "$target_dir/osint/social_media.txt")
        echo "Social Media Profiles: $profile_count" >> "$output_file"
    else
        echo "Social Media Profiles: Not checked" >> "$output_file"
    fi
    
    # Subdomains
    if [[ -f "$target_dir/osint/subdomains.txt" ]]; then
        subdomain_count=$(wc -l < "$target_dir/osint/subdomains.txt")
        echo "Subdomains (via OSINT): $subdomain_count" >> "$output_file"
    else
        echo "Subdomains (via OSINT): Not checked" >> "$output_file"
    fi
    
    # Potential leaks
    if [[ -f "$target_dir/osint/leaked_credentials.txt" ]]; then
        github_leak_count=$(grep -c "https://github.com/" "$target_dir/osint/leaked_credentials.txt")
        pastebin_leak_count=$(grep -c "https://pastebin.com/" "$target_dir/osint/leaked_credentials.txt")
        echo "Potential GitHub Leaks: $github_leak_count" >> "$output_file"
        echo "Potential Pastebin Leaks: $pastebin_leak_count" >> "$output_file"
    else
        echo "Potential Leaks: Not checked" >> "$output_file"
    fi
    
    echo "" >> "$output_file"
    echo "OSINT Recommendations:" >> "$output_file"
    echo "----------------------------" >> "$output_file"
    echo "1. Review all identified email addresses for potential phishing targets" >> "$output_file"
    echo "2. Monitor identified social media accounts for information leakage" >> "$output_file"
    echo "3. Verify all discovered subdomains are properly secured" >> "$output_file"
    echo "4. Investigate any potential credential leaks immediately" >> "$output_file"
    
    log_message "OSINT summary completed" "SUCCESS"
    
    end_function "osint_summary" $?
}

# Main function to run the OSINT module
function run_osint_module() {
    # Create necessary directories
    mkdir -p "$target_dir/osint" 2>/dev/null
    mkdir -p "$CALLED_FN_DIR" 2>/dev/null
    chmod 755 "$CALLED_FN_DIR" 2>/dev/null
    
    # Show banner
    show_osint_banner
    
    # Run OSINT functions
    email_discovery
    social_media_discovery
    company_info
    osint_subdomains
    leaked_credentials
    osint_summary
    
    log_message "OSINT module completed for $target" "SUCCESS"
}

# Export functions
export -f email_discovery
export -f social_media_discovery
export -f company_info
export -f osint_subdomains
export -f leaked_credentials
export -f osint_summary
export -f run_osint_module