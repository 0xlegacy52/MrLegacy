#!/bin/bash
# Subdomain Takeover Module for MR Legacy Bug Bounty Tool
# Author: Abdulrahman Muhammad (0xLegacy)
# This module performs checks for subdomain takeover vulnerabilities

# Load the common functions
if [[ -f "./utils/common.sh" ]]; then
    source "./utils/common.sh"
else
    echo "Error: common.sh not found"
    exit 1
fi

# Subdomain Takeover Banner
show_subdomain_takeover_banner() {
    echo '
███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
███████╗██║   ██║██████╔╝██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
████████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██╗   ██╗███████╗██████╗ 
╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗
   ██║   ███████║█████╔╝ █████╗  ██║   ██║██║   ██║█████╗  ██████╔╝
   ██║   ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
   ██║   ██║  ██║██║  ██╗███████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝
=========================================================================
  Subdomain Takeover Vulnerability Assessment
========================================================================='
}

# Function to extract subdomains from previous reconnaissance
extract_subdomains() {
    local target=$1
    local output_dir=$2
    local recon_dir="${target_dir}/recon"
    local subdomain_file="${output_dir}/subdomains.txt"
    
    log_message "Extracting subdomains from previous reconnaissance data" "INFO"
    
    # Initialize empty file
    > "${subdomain_file}"
    
    # Check various possible locations where subdomains might have been saved
    local potential_files=(
        "${recon_dir}/subdomains.txt"
        "${recon_dir}/subdomains_all.txt"
        "${recon_dir}/subfinder.txt"
        "${recon_dir}/amass.txt"
        "${recon_dir}/assetfinder.txt"
        "${recon_dir}/findomain.txt"
        "${recon_dir}/sublist3r.txt"
        "${target_dir}/enumeration/subdomains.txt"
        "${target_dir}/osint/subdomains.txt"
    )
    
    # Collect subdomains from all potential files
    for file in "${potential_files[@]}"; do
        if [[ -f "${file}" ]]; then
            log_message "Found subdomain file: ${file}" "DEBUG"
            cat "${file}" >> "${subdomain_file}"
        fi
    done
    
    # Sort and remove duplicates
    if [[ -s "${subdomain_file}" ]]; then
        sort -u "${subdomain_file}" -o "${subdomain_file}"
        local count=$(wc -l < "${subdomain_file}")
        log_message "Extracted ${count} unique subdomains" "INFO"
    else
        log_message "No subdomains found from previous reconnaissance" "WARNING"
        
        # If no subdomains were found, try to gather some basic ones
        # This is a fallback if no recon data is available
        log_message "Attempting to gather basic subdomains" "INFO"
        
        # Try using host command for common subdomains
        for sub in www mail ftp blog dev stage test app api admin portal; do
            local subdomain="${sub}.${target}"
            if host "${subdomain}" &>/dev/null; then
                echo "${subdomain}" >> "${subdomain_file}"
            fi
        done
        
        # If still empty, just add www subdomain
        if [[ ! -s "${subdomain_file}" ]]; then
            echo "www.${target}" >> "${subdomain_file}"
        fi
        
        local count=$(wc -l < "${subdomain_file}")
        log_message "Added ${count} basic subdomains for testing" "INFO"
    fi
    
    return 0
}

# Function to check for potential subdomain takeover vulnerabilities
check_subdomain_takeover() {
    local target=$1
    local output_dir=$2
    local subdomain_file="${output_dir}/subdomains.txt"
    local takeover_output="${output_dir}/takeover_vulnerabilities.txt"
    
    log_message "Checking for subdomain takeover vulnerabilities" "INFO"
    
    if [[ ! -f "${subdomain_file}" ]]; then
        log_message "No subdomain file found. Run extract_subdomains first." "ERROR"
        return 1
    fi
    
    echo "Subdomain Takeover Vulnerability Check for ${target}" > "${takeover_output}"
    echo "----------------------------------------" >> "${takeover_output}"
    
    # Common fingerprints for subdomain takeover vulnerabilities
    # Format: "Service Name|Fingerprint Pattern|CNAME Pattern"
    local fingerprints=(
        "AWS S3|NoSuchBucket|s3.amazonaws.com"
        "GitHub Pages|There isn't a GitHub Pages site here|github.io"
        "Heroku|No such app|herokuapp.com"
        "Shopify|Sorry, this shop is currently unavailable|shops.myshopify.com"
        "Fastly|Fastly error: unknown domain|fastly.net"
        "Pantheon|The gods are wise|pantheonsite.io"
        "Tumblr|There's nothing here|tumblr.com"
        "Wordpress|Do you want to register|wordpress.com"
        "Desk|This Zendesk has been suspended|desk.com"
        "Zendesk|Help Center Closed|zendesk.com"
        "Acquia|Web Site Not Found|acquia-sites.com"
        "Simplio|does not exist...|simplio.app"
        "Webflow|The domain has not been configured|webflow.io"
        "Wishpond|https://www.wishpond.com/404|cname.wishpond.com"
        "Aftership|Oops.|aftership.com"
        "Aha|There is no portal here|ideas.aha.io"
        "Tilda|Domain has been assigned|tilda.ws"
        "Unbounce|The requested URL was not found|unbounce.com"
        "Uptimerobot|page not found|stats.uptimerobot.com"
        "Surge|project not found|surge.sh"
        "Bitbucket|Repository not found|bitbucket.io"
        "Intercom|This page is reserved|custom.intercom.help"
        "Webserver|404 Not Found|NA"
        "Azure Web Apps|404 Web Site not found|azurewebsites.net"
        "Readme.io|Project doesnt exist|readme.io"
        "Ghost|Domain is not configured|ghost.io"
        "Freshdesk|Not found|freshdesk.com"
        "Campaign Monitor|Trying to access your account|createsend.com"
        "Pingdom|This public report page has not been activated|stats.pingdom.com"
        "Smartling|Domain is not configured|smartling.com"
        "Amplify|Repository not found|amplifyapp.com"
        "Vercel|The deployment could not be found|vercel.app"
        "Netlify|Not found|netlify.app"
    )
    
    # Initialize counters
    local total=0
    local vulnerable=0
    local potential=0
    
    # Check each subdomain for takeover vulnerabilities
    while IFS= read -r subdomain; do
        # Skip empty lines
        [[ -z "${subdomain}" ]] && continue
        
        # Increment total counter
        ((total++))
        
        log_message "Checking subdomain: ${subdomain}" "DEBUG"
        echo -e "\nChecking: ${subdomain}" >> "${takeover_output}"
        
        # Get CNAME record
        local cname=""
        if command_exists "dig"; then
            cname=$(dig +short CNAME "${subdomain}" 2>/dev/null)
        elif command_exists "host"; then
            cname=$(host -t CNAME "${subdomain}" 2>/dev/null | grep "alias for" | awk '{print $NF}' | sed 's/\.$//')
        elif command_exists "nslookup"; then
            cname=$(nslookup -type=CNAME "${subdomain}" 2>/dev/null | grep "canonical name" | awk '{print $NF}' | sed 's/\.$//')
        fi
        
        # Get HTTP response
        local http_code=""
        local http_content=""
        
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://${subdomain}" 2>/dev/null)
        http_content=$(curl -s -L "http://${subdomain}" 2>/dev/null)
        
        # Look for known fingerprints
        local vulnerable_service=""
        local is_vulnerable=false
        local is_potential=false
        
        # Check CNAME patterns first
        if [[ -n "${cname}" ]]; then
            echo "  CNAME: ${cname}" >> "${takeover_output}"
            
            for fingerprint in "${fingerprints[@]}"; do
                IFS='|' read -r service content_pattern cname_pattern <<< "${fingerprint}"
                
                if [[ "${cname_pattern}" != "NA" && "${cname}" =~ ${cname_pattern} ]]; then
                    echo "  [!] CNAME points to ${service} (${cname_pattern})" >> "${takeover_output}"
                    
                    # Now check if the content confirms a takeover opportunity
                    if [[ -n "${http_content}" && "${http_content}" =~ ${content_pattern} ]]; then
                        echo "  [!!] Vulnerable: Content matches fingerprint for ${service}" >> "${takeover_output}"
                        echo "  Fingerprint: ${content_pattern}" >> "${takeover_output}"
                        vulnerable_service="${service}"
                        is_vulnerable=true
                        ((vulnerable++))
                    else
                        echo "  [?] Potential: CNAME matches ${service} but content does not confirm vulnerability" >> "${takeover_output}"
                        is_potential=true
                        ((potential++))
                    fi
                    
                    break
                fi
            done
        else
            echo "  No CNAME record found" >> "${takeover_output}"
        fi
        
        # If not already found by CNAME, check content patterns
        if [[ "${is_vulnerable}" == false && -n "${http_content}" ]]; then
            for fingerprint in "${fingerprints[@]}"; do
                IFS='|' read -r service content_pattern cname_pattern <<< "${fingerprint}"
                
                if [[ "${http_content}" =~ ${content_pattern} ]]; then
                    echo "  [!] Content matches fingerprint for ${service}" >> "${takeover_output}"
                    echo "  Fingerprint: ${content_pattern}" >> "${takeover_output}"
                    
                    if [[ "${http_code}" =~ ^(404|503)$ ]]; then
                        echo "  [!!] Vulnerable: HTTP status ${http_code} and content matches fingerprint" >> "${takeover_output}"
                        vulnerable_service="${service}"
                        is_vulnerable=true
                        ((vulnerable++))
                    else
                        echo "  [?] Potential: Content matches but HTTP status is ${http_code}" >> "${takeover_output}"
                        is_potential=true
                        ((potential++))
                    fi
                    
                    break
                fi
            done
        fi
        
        # Check for other common signs of vulnerability
        if [[ "${is_vulnerable}" == false && "${is_potential}" == false ]]; then
            if [[ "${http_code}" == "404" || "${http_code}" == "503" ]]; then
                echo "  [?] Potential: HTTP status ${http_code} might indicate an unclaimed service" >> "${takeover_output}"
                is_potential=true
                ((potential++))
            elif [[ -z "${http_code}" ]]; then
                # Check if the hostname resolves but doesn't respond to HTTP
                if host "${subdomain}" &>/dev/null; then
                    echo "  [?] Potential: Hostname resolves but doesn't respond to HTTP" >> "${takeover_output}"
                    is_potential=true
                    ((potential++))
                fi
            fi
        fi
        
        # Add summary for this subdomain
        if [[ "${is_vulnerable}" == true ]]; then
            echo "  Result: VULNERABLE (${vulnerable_service})" >> "${takeover_output}"
        elif [[ "${is_potential}" == true ]]; then
            echo "  Result: POTENTIAL" >> "${takeover_output}"
        else
            echo "  Result: Not vulnerable" >> "${takeover_output}"
        fi
        
    done < "${subdomain_file}"
    
    # Generate summary
    echo -e "\n\nSubdomain Takeover Summary:" >> "${takeover_output}"
    echo "----------------------------------------" >> "${takeover_output}"
    echo "Total Subdomains Checked: ${total}" >> "${takeover_output}"
    echo "Vulnerable Subdomains: ${vulnerable}" >> "${takeover_output}"
    echo "Potentially Vulnerable Subdomains: ${potential}" >> "${takeover_output}"
    
    if [[ ${vulnerable} -gt 0 ]]; then
        log_message "Found ${vulnerable} vulnerable subdomains!" "WARNING"
    else
        log_message "No definite subdomain takeover vulnerabilities found" "INFO"
    fi
    
    if [[ ${potential} -gt 0 ]]; then
        log_message "Found ${potential} potentially vulnerable subdomains" "INFO"
    fi
    
    return 0
}

# Function to perform additional DNS checks for subdomain takeovers
perform_dns_checks() {
    local target=$1
    local output_dir=$2
    local subdomain_file="${output_dir}/subdomains.txt"
    local dns_output="${output_dir}/dns_checks.txt"
    
    log_message "Performing additional DNS checks" "INFO"
    
    if [[ ! -f "${subdomain_file}" ]]; then
        log_message "No subdomain file found. Run extract_subdomains first." "ERROR"
        return 1
    fi
    
    echo "Additional DNS Checks for ${target}" > "${dns_output}"
    echo "----------------------------------------" >> "${dns_output}"
    
    # Check dangling DNS records
    echo "Checking for dangling DNS records:" >> "${dns_output}"
    
    while IFS= read -r subdomain; do
        # Skip empty lines
        [[ -z "${subdomain}" ]] && continue
        
        echo -e "\nSubdomain: ${subdomain}" >> "${dns_output}"
        
        # Check if the subdomain has DNS records
        local has_a_record=false
        local has_cname_record=false
        local a_records=""
        local cname_record=""
        
        # Check A records
        if command_exists "dig"; then
            a_records=$(dig +short A "${subdomain}" 2>/dev/null)
        elif command_exists "host"; then
            a_records=$(host -t A "${subdomain}" 2>/dev/null | grep "has address" | awk '{print $NF}')
        fi
        
        if [[ -n "${a_records}" ]]; then
            has_a_record=true
            echo "  A Record(s):" >> "${dns_output}"
            echo "${a_records}" | sed 's/^/    /' >> "${dns_output}"
        else
            echo "  No A records found" >> "${dns_output}"
        fi
        
        # Check CNAME records
        if command_exists "dig"; then
            cname_record=$(dig +short CNAME "${subdomain}" 2>/dev/null)
        elif command_exists "host"; then
            cname_record=$(host -t CNAME "${subdomain}" 2>/dev/null | grep "alias for" | awk '{print $NF}' | sed 's/\.$//')
        fi
        
        if [[ -n "${cname_record}" ]]; then
            has_cname_record=true
            echo "  CNAME Record: ${cname_record}" >> "${dns_output}"
            
            # Check if the CNAME target resolves
            local cname_resolves=false
            
            if command_exists "dig"; then
                if [[ -n "$(dig +short A "${cname_record}" 2>/dev/null)" ]]; then
                    cname_resolves=true
                fi
            elif command_exists "host"; then
                if host "${cname_record}" 2>/dev/null | grep -q "has address"; then
                    cname_resolves=true
                fi
            fi
            
            if [[ "${cname_resolves}" == true ]]; then
                echo "  CNAME Target Status: Resolves" >> "${dns_output}"
            else
                echo "  CNAME Target Status: DOES NOT RESOLVE (Potential Dangling Record)" >> "${dns_output}"
                echo "  [!] VULNERABILITY: Dangling CNAME record detected" >> "${dns_output}"
            fi
        else
            echo "  No CNAME records found" >> "${dns_output}"
        fi
        
        # Check for other DNS records that might indicate vulnerability
        local ns_records=""
        local mx_records=""
        
        # Check NS records
        if command_exists "dig"; then
            ns_records=$(dig +short NS "${subdomain}" 2>/dev/null)
        elif command_exists "host"; then
            ns_records=$(host -t NS "${subdomain}" 2>/dev/null | grep "name server" | awk '{print $NF}' | sed 's/\.$//')
        fi
        
        if [[ -n "${ns_records}" ]]; then
            echo "  NS Record(s):" >> "${dns_output}"
            echo "${ns_records}" | sed 's/^/    /' >> "${dns_output}"
            
            # Check for delegation to third-party services
            if echo "${ns_records}" | grep -qiE 'aws|amazon|azure|google|heroku|github|netlify|vercel'; then
                echo "  [!] POTENTIAL VULNERABILITY: Delegated to a third-party service" >> "${dns_output}"
            fi
        fi
        
        # Check MX records
        if command_exists "dig"; then
            mx_records=$(dig +short MX "${subdomain}" 2>/dev/null)
        elif command_exists "host"; then
            mx_records=$(host -t MX "${subdomain}" 2>/dev/null | grep "mail is handled" | awk '{print $NF}' | sed 's/\.$//')
        fi
        
        if [[ -n "${mx_records}" ]]; then
            echo "  MX Record(s):" >> "${dns_output}"
            echo "${mx_records}" | sed 's/^/    /' >> "${dns_output}"
            
            # Check for delegation to third-party email services
            if echo "${mx_records}" | grep -qiE 'google|gmail|outlook|office365|zoho'; then
                echo "  INFO: Using third-party email service" >> "${dns_output}"
            fi
        fi
        
        # Summary for this subdomain
        echo "  DNS Vulnerability Assessment:" >> "${dns_output}"
        if [[ "${has_cname_record}" == true && "${cname_resolves}" == false ]]; then
            echo "    High: Dangling CNAME record detected" >> "${dns_output}"
        elif [[ "${has_a_record}" == false && "${has_cname_record}" == false ]]; then
            echo "    Medium: No A or CNAME records found, might be vulnerable to registration" >> "${dns_output}"
        else
            echo "    Low: No obvious DNS vulnerabilities detected" >> "${dns_output}"
        fi
        
    done < "${subdomain_file}"
    
    log_message "DNS checks completed" "INFO"
    return 0
}

# Function to test for cloud service takeovers
check_cloud_services() {
    local target=$1
    local output_dir=$2
    local subdomain_file="${output_dir}/subdomains.txt"
    local cloud_output="${output_dir}/cloud_service_checks.txt"
    
    log_message "Checking for cloud service takeover vulnerabilities" "INFO"
    
    if [[ ! -f "${subdomain_file}" ]]; then
        log_message "No subdomain file found. Run extract_subdomains first." "ERROR"
        return 1
    fi
    
    echo "Cloud Service Takeover Check for ${target}" > "${cloud_output}"
    echo "----------------------------------------" >> "${cloud_output}"
    
    # Define cloud service patterns
    # Format: "Service Name|Domain Pattern|Error Pattern"
    local cloud_services=(
        "AWS S3|s3.amazonaws.com|NoSuchBucket"
        "AWS CloudFront|cloudfront.net|The request could not be satisfied"
        "Microsoft Azure|azurewebsites.net|404 Web Site not found"
        "Microsoft Azure|cloudapp.net|404 Web Site not found"
        "Microsoft Azure|trafficmanager.net|The page you are looking for is not found"
        "Microsoft Azure|msappproxy.net|The server encountered an error"
        "Google Cloud|appspot.com|Error 404"
        "Google Firebase|firebaseapp.com|Site Not Found"
        "Heroku|herokuapp.com|No such app"
        "GitHub Pages|github.io|There isn't a GitHub Pages site here"
        "Fastly|fastly.net|Fastly error: unknown domain"
        "Shopify|myshopify.com|Sorry, this shop is currently unavailable"
        "Tumblr|tumblr.com|There's nothing here"
        "Squarespace|squarespace.com|Website Expired"
        "Wordpress|wordpress.com|doesn't exist"
        "Netlify|netlify.app|Not Found"
        "Netlify|netlify.com|Not Found"
        "Vercel|vercel.app|The deployment could not be found"
        "Pantheon|pantheonsite.io|The gods are wise"
        "Acquia|acquia-sites.com|Web Site Not Found"
        "Webflow|webflow.io|The domain has not been configured"
    )
    
    # Initialize counters
    local total=0
    local vulnerable=0
    
    # Check each subdomain for cloud service takeover vulnerabilities
    while IFS= read -r subdomain; do
        # Skip empty lines
        [[ -z "${subdomain}" ]] && continue
        
        # Increment total counter
        ((total++))
        
        log_message "Checking cloud services for: ${subdomain}" "DEBUG"
        echo -e "\nChecking Cloud Services: ${subdomain}" >> "${cloud_output}"
        
        # Get CNAME record
        local cname=""
        if command_exists "dig"; then
            cname=$(dig +short CNAME "${subdomain}" 2>/dev/null)
        elif command_exists "host"; then
            cname=$(host -t CNAME "${subdomain}" 2>/dev/null | grep "alias for" | awk '{print $NF}' | sed 's/\.$//')
        fi
        
        if [[ -z "${cname}" ]]; then
            echo "  No CNAME record found" >> "${cloud_output}"
            continue
        fi
        
        echo "  CNAME: ${cname}" >> "${cloud_output}"
        
        # Check for cloud service patterns in CNAME
        local is_cloud_service=false
        local cloud_service=""
        
        for service in "${cloud_services[@]}"; do
            IFS='|' read -r service_name domain_pattern error_pattern <<< "${service}"
            
            if [[ "${cname}" =~ ${domain_pattern} ]]; then
                is_cloud_service=true
                cloud_service="${service_name}"
                echo "  [!] Points to cloud service: ${service_name}" >> "${cloud_output}"
                
                # Check if the service is vulnerable
                local http_content=$(curl -s -L "http://${subdomain}" 2>/dev/null)
                
                if [[ -n "${http_content}" && "${http_content}" =~ ${error_pattern} ]]; then
                    echo "  [!!] VULNERABLE: Content matches error pattern for ${service_name}" >> "${cloud_output}"
                    echo "  Error Pattern: ${error_pattern}" >> "${cloud_output}"
                    ((vulnerable++))
                    
                    # Provide takeover guidance based on the service
                    echo "  Takeover Guidance:" >> "${cloud_output}"
                    case "${service_name}" in
                        "AWS S3")
                            echo "    - Create an S3 bucket with the exact name from the CNAME" >> "${cloud_output}"
                            echo "    - Ensure bucket is in the correct region" >> "${cloud_output}"
                            echo "    - Upload proof-of-concept file" >> "${cloud_output}"
                            ;;
                        "GitHub Pages")
                            echo "    - Create a GitHub repository with the name format: username.github.io" >> "${cloud_output}"
                            echo "    - Enable GitHub Pages in repository settings" >> "${cloud_output}"
                            echo "    - Create a CNAME file with the subdomain" >> "${cloud_output}"
                            ;;
                        "Heroku")
                            echo "    - Create a Heroku app with the name from the CNAME" >> "${cloud_output}"
                            echo "    - Add the custom domain in Heroku app settings" >> "${cloud_output}"
                            echo "    - Deploy a simple proof-of-concept application" >> "${cloud_output}"
                            ;;
                        *)
                            echo "    - Research specific takeover method for ${service_name}" >> "${cloud_output}"
                            echo "    - Create an account with the service provider" >> "${cloud_output}"
                            echo "    - Claim the exact resource name from the CNAME" >> "${cloud_output}"
                            echo "    - Configure to serve content under the subdomain" >> "${cloud_output}"
                            ;;
                    esac
                else
                    echo "  Not vulnerable: Service is active or error pattern not detected" >> "${cloud_output}"
                fi
                
                break
            fi
        done
        
        if [[ "${is_cloud_service}" == false ]]; then
            echo "  Not pointing to a known cloud service" >> "${cloud_output}"
        fi
        
    done < "${subdomain_file}"
    
    # Generate summary
    echo -e "\n\nCloud Service Takeover Summary:" >> "${cloud_output}"
    echo "----------------------------------------" >> "${cloud_output}"
    echo "Total Subdomains Checked: ${total}" >> "${cloud_output}"
    echo "Vulnerable Cloud Services: ${vulnerable}" >> "${cloud_output}"
    
    if [[ ${vulnerable} -gt 0 ]]; then
        log_message "Found ${vulnerable} vulnerable cloud service configurations!" "WARNING"
    else
        log_message "No cloud service takeover vulnerabilities found" "INFO"
    fi
    
    return 0
}

# Function to check for expired domains
check_expired_domains() {
    local target=$1
    local output_dir=$2
    local subdomain_file="${output_dir}/subdomains.txt"
    local expired_output="${output_dir}/expired_domains.txt"
    
    log_message "Checking for expired domains" "INFO"
    
    if [[ ! -f "${subdomain_file}" ]]; then
        log_message "No subdomain file found. Run extract_subdomains first." "ERROR"
        return 1
    fi
    
    echo "Expired Domain Check for ${target}" > "${expired_output}"
    echo "----------------------------------------" >> "${expired_output}"
    
    # Check for whois command
    if ! command_exists "whois"; then
        echo "The 'whois' command is not installed. Cannot check domain expiry." >> "${expired_output}"
        log_message "whois command not found, skipping expired domain checks" "WARNING"
        return 1
    fi
    
    # Initialize counters
    local total=0
    local expired=0
    local expiring_soon=0
    
    # Check each subdomain for expiration
    while IFS= read -r subdomain; do
        # Skip empty lines
        [[ -z "${subdomain}" ]] && continue
        
        # Extract the base domain (last two parts of the domain)
        local base_domain=$(extract_base_domain "${subdomain}")
        
        # Skip duplicates (we only need to check each base domain once)
        if grep -q "^Domain: ${base_domain}$" "${expired_output}"; then
            continue
        fi
        
        # Increment total counter
        ((total++))
        
        log_message "Checking domain expiry: ${base_domain}" "DEBUG"
        echo -e "\nDomain: ${base_domain}" >> "${expired_output}"
        
        # Get whois information
        local whois_info=$(whois "${base_domain}" 2>/dev/null)
        
        # Extract expiry date - try different patterns used by whois servers
        local expiry_date=$(echo "${whois_info}" | grep -iE 'Expiry Date:|Expiration Date:|Registry Expiry Date:|paid-till:' | head -1 | cut -d':' -f2- | xargs)
        
        if [[ -z "${expiry_date}" ]]; then
            echo "  Could not determine expiry date" >> "${expired_output}"
            continue
        fi
        
        echo "  Expiry Date: ${expiry_date}" >> "${expired_output}"
        
        # Try to convert the date to a format we can compare
        # This is challenging because whois servers use different date formats
        
        # Try to find a standardizable expiry timestamp
        local expiry_timestamp=0
        
        # Try common date formats
        if [[ "${expiry_date}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
            # Format: YYYY-MM-DD
            expiry_timestamp=$(date -d "${expiry_date}" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "${expiry_date:0:10}" +%s 2>/dev/null)
        elif [[ "${expiry_date}" =~ ^[0-9]{2}-[A-Za-z]{3}-[0-9]{4} ]]; then
            # Format: DD-MMM-YYYY
            expiry_timestamp=$(date -d "${expiry_date}" +%s 2>/dev/null || date -j -f "%d-%b-%Y" "${expiry_date:0:11}" +%s 2>/dev/null)
        elif [[ "${expiry_date}" =~ ^[0-9]{2}/[0-9]{2}/[0-9]{4} ]]; then
            # Format: MM/DD/YYYY
            expiry_timestamp=$(date -d "${expiry_date}" +%s 2>/dev/null || date -j -f "%m/%d/%Y" "${expiry_date:0:10}" +%s 2>/dev/null)
        else
            # Try a generic approach
            expiry_timestamp=$(date -d "${expiry_date}" +%s 2>/dev/null || echo 0)
        fi
        
        if [[ ${expiry_timestamp} -eq 0 ]]; then
            echo "  Could not parse expiry date for comparison" >> "${expired_output}"
            continue
        fi
        
        # Get current time
        local current_timestamp=$(date +%s)
        
        # Check if domain is expired
        if [[ ${expiry_timestamp} -lt ${current_timestamp} ]]; then
            echo "  [!!] EXPIRED: Domain has expired and may be available for registration" >> "${expired_output}"
            ((expired++))
        else
            # Check if domain is expiring soon (within 30 days)
            local days_until_expiry=$(( (expiry_timestamp - current_timestamp) / 86400 ))
            
            if [[ ${days_until_expiry} -le 30 ]]; then
                echo "  [!] EXPIRING SOON: Domain will expire in ${days_until_expiry} days" >> "${expired_output}"
                ((expiring_soon++))
            else
                echo "  Domain is valid for another ${days_until_expiry} days" >> "${expired_output}"
            fi
        fi
        
    done < "${subdomain_file}"
    
    # Generate summary
    echo -e "\n\nExpired Domain Summary:" >> "${expired_output}"
    echo "----------------------------------------" >> "${expired_output}"
    echo "Total Domains Checked: ${total}" >> "${expired_output}"
    echo "Expired Domains: ${expired}" >> "${expired_output}"
    echo "Domains Expiring Soon (30 days): ${expiring_soon}" >> "${expired_output}"
    
    if [[ ${expired} -gt 0 ]]; then
        log_message "Found ${expired} expired domains!" "WARNING"
    fi
    
    if [[ ${expiring_soon} -gt 0 ]]; then
        log_message "Found ${expiring_soon} domains expiring within 30 days" "INFO"
    fi
    
    return 0
}

# Function to generate an HTML report for subdomain takeover results
generate_takeover_report() {
    local target=$1
    local output_dir=$2
    local html_report="${output_dir}/subdomain_takeover_report.html"
    
    log_message "Generating subdomain takeover HTML report for ${target}" "INFO"
    
    # Create an HTML report
    cat > "${html_report}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subdomain Takeover Report for ${target}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: #f9f9f9;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .results {
            white-space: pre-wrap;
            font-family: monospace;
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .high {
            color: #c0392b;
            font-weight: bold;
        }
        .medium {
            color: #e67e22;
            font-weight: bold;
        }
        .low {
            color: #3498db;
            font-weight: bold;
        }
        .success {
            color: #27ae60;
            font-weight: bold;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .summary {
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Subdomain Takeover Vulnerability Report</h1>
        <p class="timestamp">Generated on $(date) for target: ${target}</p>
        
        <div class="summary section">
            <h2>Scan Summary</h2>
            <p>This report contains the results of subdomain takeover vulnerability checks performed on the target domain.</p>
            <table>
                <tr>
                    <th>Test Type</th>
                    <th>Status</th>
                </tr>
                <tr>
                    <td>Subdomain Takeover Check</td>
                    <td>$(if [[ -f "${output_dir}/takeover_vulnerabilities.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>DNS Checks</td>
                    <td>$(if [[ -f "${output_dir}/dns_checks.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Cloud Service Checks</td>
                    <td>$(if [[ -f "${output_dir}/cloud_service_checks.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Expired Domains Check</td>
                    <td>$(if [[ -f "${output_dir}/expired_domains.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Subdomain Takeover Vulnerabilities</h2>
            <div class="results">
$(if [[ -f "${output_dir}/takeover_vulnerabilities.txt" ]]; then
    # Highlight vulnerable and potential results
    cat "${output_dir}/takeover_vulnerabilities.txt" | sed 's/\[!!]/<span class="high">[!!]<\/span>/g' | sed 's/\[!]/<span class="medium">[!]<\/span>/g' | sed 's/\[?]/<span class="low">[?]<\/span>/g' | sed 's/Result: VULNERABLE/<span class="high">Result: VULNERABLE<\/span>/g' | sed 's/Result: POTENTIAL/<span class="medium">Result: POTENTIAL<\/span>/g' | sed 's/Result: Not vulnerable/<span class="success">Result: Not vulnerable<\/span>/g'
else
    echo "No subdomain takeover vulnerability check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>DNS Configuration Checks</h2>
            <div class="results">
$(if [[ -f "${output_dir}/dns_checks.txt" ]]; then
    # Highlight different risk levels
    cat "${output_dir}/dns_checks.txt" | sed 's/\[!]/<span class="high">[!]<\/span>/g' | sed 's/High:/<span class="high">High:<\/span>/g' | sed 's/Medium:/<span class="medium">Medium:<\/span>/g' | sed 's/Low:/<span class="low">Low:<\/span>/g'
else
    echo "No DNS configuration check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Cloud Service Takeover Checks</h2>
            <div class="results">
$(if [[ -f "${output_dir}/cloud_service_checks.txt" ]]; then
    # Highlight vulnerable results
    cat "${output_dir}/cloud_service_checks.txt" | sed 's/\[!!]/<span class="high">[!!]<\/span>/g' | sed 's/\[!]/<span class="medium">[!]<\/span>/g' | sed 's/VULNERABLE:/<span class="high">VULNERABLE:<\/span>/g'
else
    echo "No cloud service takeover check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Expired Domains Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/expired_domains.txt" ]]; then
    # Highlight expired and expiring domains
    cat "${output_dir}/expired_domains.txt" | sed 's/\[!!]/<span class="high">[!!]<\/span>/g' | sed 's/\[!]/<span class="medium">[!]<\/span>/g' | sed 's/EXPIRED:/<span class="high">EXPIRED:<\/span>/g' | sed 's/EXPIRING SOON:/<span class="medium">EXPIRING SOON:<\/span>/g'
else
    echo "No expired domain check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>What is Subdomain Takeover?</h2>
            <p>Subdomain takeover is a high severity vulnerability that occurs when a subdomain (e.g., subdomain.example.com) is pointing to a service (via a CNAME record) that has been deprovisioned or deleted. An attacker can set up the same service using the same name, effectively taking control of the subdomain.</p>
            <p>This vulnerability can lead to:</p>
            <ul>
                <li>Full subdomain control by an attacker</li>
                <li>Hosting of malicious content under the legitimate domain</li>
                <li>Cookie stealing and session hijacking</li>
                <li>Phishing attacks leveraging the trust of the main domain</li>
                <li>Circumvention of Content Security Policy</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                <li>Remove DNS records for services that are no longer in use</li>
                <li>Regularly audit all DNS records, especially CNAME records pointing to third-party services</li>
                <li>Implement proper decommissioning procedures when retiring services</li>
                <li>Maintain an inventory of all subdomains and their purposes</li>
                <li>Use subdomain monitoring services to detect potential takeover vulnerabilities</li>
                <li>For critical domains, consider domain registry locking to prevent unauthorized transfers</li>
                <li>Implement DNS security extensions (DNSSEC) to protect against DNS spoofing</li>
                <li>Set up automated alerts for domain expiration dates, especially for domains expiring within 30 days</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF
    
    log_message "Subdomain takeover HTML report generated: ${html_report}" "SUCCESS"
}

# Main function for subdomain takeover module
run_subdomain_takeover_module() {
    show_subdomain_takeover_banner
    
    # Check if a target is provided
    if [[ -z "${target}" ]]; then
        log_message "No target specified. Use -t or --target option." "ERROR"
        return 1
    fi
    
    # Create output directory for subdomain takeover results
    local takeover_dir="${target_dir}/subdomain_takeover"
    mkdir -p "${takeover_dir}"
    
    log_message "Starting Subdomain Takeover module for ${target}" "INFO"
    
    # Run the subdomain takeover functions in sequence
    extract_subdomains "${target}" "${takeover_dir}"
    check_subdomain_takeover "${target}" "${takeover_dir}"
    perform_dns_checks "${target}" "${takeover_dir}"
    check_cloud_services "${target}" "${takeover_dir}"
    check_expired_domains "${target}" "${takeover_dir}"
    
    # Generate HTML report
    generate_takeover_report "${target}" "${takeover_dir}"
    
    log_message "Subdomain Takeover module completed for ${target}" "SUCCESS"
    
    # Display summary
    echo "--------------------------------------------------"
    echo "Subdomain Takeover Check Summary for ${target}:"
    echo "--------------------------------------------------"
    echo "Checks performed:"
    echo "- Subdomain Takeover Vulnerability Check"
    echo "- DNS Configuration Check"
    echo "- Cloud Service Takeover Check"
    echo "- Expired Domains Check"
    echo "--------------------------------------------------"
    echo "HTML Report: ${takeover_dir}/subdomain_takeover_report.html"
    echo "--------------------------------------------------"
    
    return 0
}