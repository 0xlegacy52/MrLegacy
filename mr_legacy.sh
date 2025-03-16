#!/bin/bash

# MR Legacy - Bug Bounty Tool
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.2.0

# Default settings
VERBOSE=false
DEEP=false
TOR=false
AUTO=false
THREADS=10
OUTPUT_FORMAT="all"
target=""
target_dir=""

# Initialize variables
script_path=$(dirname "$(readlink -f "$0")")

# Source utility modules
source modules/recon.sh 2>/dev/null || source recon.sh 2>/dev/null || { echo "Error: Cannot find recon module."; exit 1; }
source modules/scanning.sh 2>/dev/null || source scanning.sh 2>/dev/null || { echo "Error: Cannot find scanning module."; exit 1; }
source modules/enumeration.sh 2>/dev/null || source enumeration.sh 2>/dev/null || { echo "Error: Cannot find enumeration module."; exit 1; }
source modules/vulnerability.sh 2>/dev/null || source vulnerability.sh 2>/dev/null || { echo "Error: Cannot find vulnerability module."; exit 1; }
source modules/exploitation.sh 2>/dev/null || source exploitation.sh 2>/dev/null || { echo "Error: Cannot find exploitation module."; exit 1; }
source modules/cloud.sh 2>/dev/null || source cloud.sh 2>/dev/null || { echo "Error: Cannot find cloud module."; exit 1; }
source modules/osint.sh 2>/dev/null || source osint.sh 2>/dev/null || echo "Warning: OSINT module not found. OSINT features will be skipped."
source modules/content_discovery.sh 2>/dev/null || source content_discovery.sh 2>/dev/null || echo "Warning: Content Discovery module not found. Content Discovery features will be skipped."
source modules/subdomain_takeover.sh 2>/dev/null || source subdomain_takeover.sh 2>/dev/null || echo "Warning: Subdomain Takeover module not found. Subdomain Takeover features will be skipped."
source modules/security_headers.sh 2>/dev/null || source security_headers.sh 2>/dev/null || echo "Warning: Security Headers module not found. Security Headers features will be skipped."
source modules/error_handling.sh 2>/dev/null || source error_handling.sh 2>/dev/null || echo "Warning: Error Handling module not found. Error Handling features will be skipped."
source modules/port_scanning.sh 2>/dev/null || source port_scanning.sh 2>/dev/null || echo "Warning: Port Scanning module not found. Port Scanning features will be skipped."
source modules/web_scanning.sh 2>/dev/null || source web_scanning.sh 2>/dev/null || echo "Warning: Web Scanning module not found. Web Scanning features will be skipped."
source modules/auth_testing.sh 2>/dev/null || source auth_testing.sh 2>/dev/null || echo "Warning: Authentication Testing module not found. Authentication Testing features will be skipped."
source utils/helpers.sh 2>/dev/null || source helpers.sh 2>/dev/null || { echo "Error: Cannot find helpers module."; exit 1; }
source utils/banners.sh 2>/dev/null || source banners.sh 2>/dev/null || { echo "Error: Cannot find banners module."; exit 1; }
source utils/toolcheck.sh 2>/dev/null || source toolcheck.sh 2>/dev/null || { echo "Error: Cannot find toolcheck module."; exit 1; }
source ai_helper/ai_assistant.py 2>/dev/null || source ai_assistant.py 2>/dev/null || echo "Warning: AI assistant module not found. AI analysis will be skipped."

# Parse command line arguments
function parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                target="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -T|--threads)
                THREADS="$2"
                shift 2
                ;;
            --tor)
                TOR=true
                shift
                ;;
            -a|--auto)
                AUTO=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--deep)
                DEEP=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$target" ]]; then
        echo "Error: Target domain is required."
        show_help
        exit 1
    fi
    
    # Validate output format
    case "$OUTPUT_FORMAT" in
        json|txt|html|all)
            # Valid format
            ;;
        *)
            echo "Error: Invalid output format '$OUTPUT_FORMAT'. Valid options are: json, txt, html, all"
            show_help
            exit 1
            ;;
    esac
    
    # Validate threads
    if ! [[ "$THREADS" =~ ^[0-9]+$ ]] || [[ "$THREADS" -lt 1 ]]; then
        echo "Error: Number of threads must be a positive integer."
        show_help
        exit 1
    fi
    
    # Set up target directory
    target_dir="results/$target"
    mkdir -p "$target_dir" 2>/dev/null || { echo "Error: Cannot create output directory: $target_dir"; exit 1; }
    
    # Export variables for use in other scripts
    export target
    export target_dir
    export VERBOSE
    export DEEP
    export TOR
    export AUTO
    export THREADS
    export OUTPUT_FORMAT
}

# Function to set up Tor proxy if needed
function setup_tor_proxy() {
    if [[ "$TOR" == true ]]; then
        log_message "Setting up Tor proxy..." "INFO"
        
        # Check if Tor is installed and running
        check_tor_proxy
        
        if [[ $? -ne 0 ]]; then
            log_message "Failed to set up Tor proxy. Will continue without it." "WARNING"
            TOR=false
            return 1
        fi
        
        # Set environment variables for tools that support proxy settings
        export HTTP_PROXY="socks5://127.0.0.1:9050"
        export HTTPS_PROXY="socks5://127.0.0.1:9050"
        export ALL_PROXY="socks5://127.0.0.1:9050"
        
        log_message "Tor proxy set up successfully" "SUCCESS"
        
        # Verify anonymity
        log_message "Verifying anonymity..." "INFO"
        local ip=$(curl -s --socks5 127.0.0.1:9050 https://api.ipify.org)
        log_message "Current IP address (via Tor): $ip" "INFO"
    fi
}

# Function to generate an auto-recon summary
function generate_reports() {
    log_message "Generating reports in $OUTPUT_FORMAT format..." "INFO"
    
    # Create reports directory
    mkdir -p "$target_dir/reports" 2>/dev/null
    
    # Generate TXT report
    if [[ "$OUTPUT_FORMAT" == "txt" || "$OUTPUT_FORMAT" == "all" ]]; then
        local txt_report="$target_dir/reports/report.txt"
        > "$txt_report"
        
        # Add header
        echo "MR LEGACY BUG BOUNTY TOOL - REPORT" >> "$txt_report"
        echo "=================================" >> "$txt_report"
        echo "Target: $target" >> "$txt_report"
        echo "Date: $(date)" >> "$txt_report"
        echo "--------------------------------" >> "$txt_report"
        echo "" >> "$txt_report"
        
        # Add reconnaissance results
        echo "1. Reconnaissance" >> "$txt_report"
        echo "----------------" >> "$txt_report"
        
        # Add subdomains
        echo "Subdomains:" >> "$txt_report"
        if [[ -f "$target_dir/recon/subdomains/subdomains.txt" ]]; then
            cat "$target_dir/recon/subdomains/subdomains.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No subdomain information available" >> "$txt_report"
        fi
        
        # Add live hosts
        echo "" >> "$txt_report"
        echo "Live Hosts:" >> "$txt_report"
        if [[ -f "$target_dir/recon/hosts/alive_hosts.txt" ]]; then
            cat "$target_dir/recon/hosts/alive_hosts.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No live host information available" >> "$txt_report"
        fi
        
        # Add technologies
        echo "" >> "$txt_report"
        echo "Technologies Detected:" >> "$txt_report"
        if [[ -f "$target_dir/recon/tech/technologies.txt" ]]; then
            cat "$target_dir/recon/tech/technologies.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No technology information available" >> "$txt_report"
        fi
        
        # Add scanning results
        echo "" >> "$txt_report"
        echo "2. Scanning" >> "$txt_report"
        echo "----------" >> "$txt_report"
        
        # Add port scanning results
        echo "Open Ports:" >> "$txt_report"
        if [[ -f "$target_dir/scanning/ports/open_ports.txt" ]]; then
            cat "$target_dir/scanning/ports/open_ports.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No port scanning information available" >> "$txt_report"
        fi
        
        # Add web fingerprinting results
        echo "" >> "$txt_report"
        echo "Web Fingerprinting:" >> "$txt_report"
        if [[ -f "$target_dir/scanning/web/fingerprinting.txt" ]]; then
            cat "$target_dir/scanning/web/fingerprinting.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No web fingerprinting information available" >> "$txt_report"
        fi
        
        # Add enumeration results
        echo "" >> "$txt_report"
        echo "3. Enumeration" >> "$txt_report"
        echo "-------------" >> "$txt_report"
        
        # Add directories
        echo "Directories Found:" >> "$txt_report"
        if [[ -d "$target_dir/enumeration/directories" ]]; then
            find "$target_dir/enumeration/directories" -type f -name "*_directories.txt" -exec cat {} \; 2>/dev/null >> "$txt_report"
        else
            echo "No directory enumeration information available" >> "$txt_report"
        fi
        
        # Add parameters
        echo "" >> "$txt_report"
        echo "Parameters Found:" >> "$txt_report"
        if [[ -f "$target_dir/enumeration/parameters/all_parameters.txt" ]]; then
            cat "$target_dir/enumeration/parameters/all_parameters.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No parameter discovery information available" >> "$txt_report"
        fi
        
        # Add JavaScript analysis
        echo "" >> "$txt_report"
        echo "JavaScript Analysis:" >> "$txt_report"
        if [[ -f "$target_dir/enumeration/js/endpoints.txt" ]]; then
            echo "Endpoints Found:" >> "$txt_report"
            cat "$target_dir/enumeration/js/endpoints.txt" 2>/dev/null >> "$txt_report"
            
            echo "" >> "$txt_report"
            echo "Potential Secrets:" >> "$txt_report"
            if [[ -f "$target_dir/enumeration/js/secrets.txt" ]]; then
                cat "$target_dir/enumeration/js/secrets.txt" 2>/dev/null >> "$txt_report"
            else
                echo "No secrets found" >> "$txt_report"
            fi
        else
            echo "No JavaScript analysis information available" >> "$txt_report"
        fi
        
        # Add cloud resources
        echo "" >> "$txt_report"
        echo "4. Cloud Resources" >> "$txt_report"
        echo "-----------------" >> "$txt_report"
        if [[ -f "$target_dir/cloud/cloud_resources.txt" ]]; then
            echo "Cloud Resources:" >> "$txt_report"
            cat "$target_dir/cloud/cloud_resources.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No cloud resources information available" >> "$txt_report"
        fi
        
        # Add vulnerability results
        echo "" >> "$txt_report"
        echo "5. Vulnerabilities" >> "$txt_report"
        echo "-----------------" >> "$txt_report"
        
        # Add Nuclei vulnerabilities
        echo "Nuclei Scan Results:" >> "$txt_report"
        if [[ -f "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" ]]; then
            cat "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No Nuclei scan information available" >> "$txt_report"
        fi
        
        # Add XSS vulnerabilities
        echo "" >> "$txt_report"
        echo "XSS Vulnerabilities:" >> "$txt_report"
        if [[ -f "$target_dir/vulnerabilities/xss_vulnerabilities.txt" ]]; then
            cat "$target_dir/vulnerabilities/xss_vulnerabilities.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No XSS vulnerabilities information available" >> "$txt_report"
        fi
        
        # Add SQLi vulnerabilities
        echo "" >> "$txt_report"
        echo "SQL Injection Vulnerabilities:" >> "$txt_report"
        if [[ -f "$target_dir/vulnerabilities/sqli_vulnerabilities.txt" ]]; then
            cat "$target_dir/vulnerabilities/sqli_vulnerabilities.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No SQL injection vulnerabilities information available" >> "$txt_report"
        fi
        
        # Add Open Redirect vulnerabilities
        echo "" >> "$txt_report"
        echo "Open Redirect Vulnerabilities:" >> "$txt_report"
        if [[ -f "$target_dir/vulnerabilities/openredirect_vulnerabilities.txt" ]]; then
            cat "$target_dir/vulnerabilities/openredirect_vulnerabilities.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No open redirect vulnerabilities information available" >> "$txt_report"
        fi
        
        # Add exploitation results
        echo "" >> "$txt_report"
        echo "6. Exploitation" >> "$txt_report"
        echo "--------------" >> "$txt_report"
        if [[ -f "$target_dir/exploitation/exploitation_summary.txt" ]]; then
            cat "$target_dir/exploitation/exploitation_summary.txt" 2>/dev/null >> "$txt_report"
        else
            echo "No exploitation information available" >> "$txt_report"
        fi
        
        # Add authentication testing results
        echo "" >> "$txt_report"
        echo "7. Authentication Testing" >> "$txt_report"
        echo "----------------------" >> "$txt_report"
        if [[ -d "$target_dir/auth_testing" ]]; then
            # Username enumeration
            echo "Username Enumeration:" >> "$txt_report"
            if [[ -f "$target_dir/auth_testing/username_enumeration.txt" ]]; then
                cat "$target_dir/auth_testing/username_enumeration.txt" 2>/dev/null >> "$txt_report"
            else
                echo "No username enumeration information available" >> "$txt_report"
            fi
            
            # Authentication bypass
            echo "" >> "$txt_report"
            echo "Authentication Bypass:" >> "$txt_report"
            if [[ -f "$target_dir/auth_testing/auth_bypass.txt" ]]; then
                cat "$target_dir/auth_testing/auth_bypass.txt" 2>/dev/null >> "$txt_report"
            else
                echo "No authentication bypass information available" >> "$txt_report"
            fi
            
            # Brute force protection
            echo "" >> "$txt_report"
            echo "Brute Force Protection:" >> "$txt_report"
            if [[ -f "$target_dir/auth_testing/brute_force_protection.txt" ]]; then
                cat "$target_dir/auth_testing/brute_force_protection.txt" 2>/dev/null >> "$txt_report"
            else
                echo "No brute force protection information available" >> "$txt_report"
            fi
            
            # Password reset
            echo "" >> "$txt_report"
            echo "Password Reset Security:" >> "$txt_report"
            if [[ -f "$target_dir/auth_testing/password_reset.txt" ]]; then
                cat "$target_dir/auth_testing/password_reset.txt" 2>/dev/null >> "$txt_report"
            else
                echo "No password reset security information available" >> "$txt_report"
            fi
            
            # JWT & token security
            echo "" >> "$txt_report"
            echo "JWT & Token Security:" >> "$txt_report"
            if [[ -f "$target_dir/auth_testing/jwt_token_security.txt" ]]; then
                cat "$target_dir/auth_testing/jwt_token_security.txt" 2>/dev/null >> "$txt_report"
            else
                echo "No JWT token security information available" >> "$txt_report"
            fi
            
            # Session management
            echo "" >> "$txt_report"
            echo "Session Management:" >> "$txt_report"
            if [[ -f "$target_dir/auth_testing/session_management.txt" ]]; then
                cat "$target_dir/auth_testing/session_management.txt" 2>/dev/null >> "$txt_report"
            else
                echo "No session management information available" >> "$txt_report"
            fi
        else
            echo "No authentication testing information available" >> "$txt_report"
        fi
        
        # Add AI Analysis results if available
        if [[ -f "$target_dir/ai_analysis.txt" ]]; then
            echo "" >> "$txt_report"
            echo "8. AI Analysis" >> "$txt_report"
            echo "-------------" >> "$txt_report"
            cat "$target_dir/ai_analysis.txt" 2>/dev/null >> "$txt_report"
        fi
        
        log_message "TXT report generated: $txt_report" "SUCCESS"
    fi
    
    # Generate JSON report
    if [[ "$OUTPUT_FORMAT" == "json" || "$OUTPUT_FORMAT" == "all" ]]; then
        local json_report="$target_dir/reports/report.json"
        
        # Start JSON structure
        echo "{" > "$json_report"
        echo "  \"target\": \"$target\"," >> "$json_report"
        echo "  \"date\": \"$(date)\"," >> "$json_report"
        
        # Add subdomains
        echo "  \"subdomains\": [" >> "$json_report"
        if [[ -f "$target_dir/recon/subdomains/subdomains.txt" ]]; then
            local first_item=true
            while read -r subdomain; do
                [[ -z "$subdomain" ]] && continue
                
                if [[ "$first_item" == true ]]; then
                    echo "    \"$subdomain\"" >> "$json_report"
                    first_item=false
                else
                    echo "    ,\"$subdomain\"" >> "$json_report"
                fi
            done < "$target_dir/recon/subdomains/subdomains.txt"
        fi
        echo "  ]," >> "$json_report"
        
        # Add live hosts
        echo "  \"live_hosts\": [" >> "$json_report"
        if [[ -f "$target_dir/recon/hosts/alive_hosts.txt" ]]; then
            local first_item=true
            while read -r host; do
                [[ -z "$host" ]] && continue
                
                if [[ "$first_item" == true ]]; then
                    echo "    \"$host\"" >> "$json_report"
                    first_item=false
                else
                    echo "    ,\"$host\"" >> "$json_report"
                fi
            done < "$target_dir/recon/hosts/alive_hosts.txt"
        fi
        echo "  ]," >> "$json_report"
        
        # Add technologies
        echo "  \"technologies\": " >> "$json_report"
        if [[ -f "$target_dir/recon/tech/technologies.json" ]]; then
            cat "$target_dir/recon/tech/technologies.json" >> "$json_report"
        else
            echo "[]" >> "$json_report"
        fi
        echo "  ," >> "$json_report"
        
        # Add port scanning results
        echo "  \"open_ports\": [" >> "$json_report"
        if [[ -f "$target_dir/scanning/ports/open_ports.txt" ]]; then
            local first_item=true
            while read -r port_line; do
                [[ -z "$port_line" ]] && continue
                
                if [[ "$first_item" == true ]]; then
                    echo "    \"$port_line\"" >> "$json_report"
                    first_item=false
                else
                    echo "    ,\"$port_line\"" >> "$json_report"
                fi
            done < "$target_dir/scanning/ports/open_ports.txt"
        fi
        echo "  ]," >> "$json_report"
        
        # Add directories
        echo "  \"directories\": [" >> "$json_report"
        if [[ -d "$target_dir/enumeration/directories" ]]; then
            local first_item=true
            for dir_file in "$target_dir/enumeration/directories"/*_directories.txt; do
                if [[ -f "$dir_file" ]]; then
                    while read -r dir_line; do
                        [[ -z "$dir_line" ]] && continue
                        
                        if [[ "$first_item" == true ]]; then
                            echo "    \"$dir_line\"" >> "$json_report"
                            first_item=false
                        else
                            echo "    ,\"$dir_line\"" >> "$json_report"
                        fi
                    done < "$dir_file"
                fi
            done
        fi
        echo "  ]," >> "$json_report"
        
        # Add parameters
        echo "  \"parameters\": [" >> "$json_report"
        if [[ -f "$target_dir/enumeration/parameters/all_parameters.txt" ]]; then
            local first_item=true
            while read -r param; do
                [[ -z "$param" ]] && continue
                
                if [[ "$first_item" == true ]]; then
                    echo "    \"$param\"" >> "$json_report"
                    first_item=false
                else
                    echo "    ,\"$param\"" >> "$json_report"
                fi
            done < "$target_dir/enumeration/parameters/all_parameters.txt"
        fi
        echo "  ]," >> "$json_report"
        
        # Add cloud resources
        echo "  \"cloud_resources\": [" >> "$json_report"
        if [[ -f "$target_dir/cloud/cloud_resources.txt" ]]; then
            local first_item=true
            while read -r resource; do
                [[ -z "$resource" ]] && continue
                
                if [[ "$first_item" == true ]]; then
                    echo "    \"$resource\"" >> "$json_report"
                    first_item=false
                else
                    echo "    ,\"$resource\"" >> "$json_report"
                fi
            done < "$target_dir/cloud/cloud_resources.txt"
        fi
        echo "  ]," >> "$json_report"
        
        # Add vulnerabilities
        echo "  \"vulnerabilities\": {" >> "$json_report"
        
        # Add Nuclei vulnerabilities
        echo "    \"nuclei\": [" >> "$json_report"
        if [[ -f "$target_dir/vulnerabilities/nuclei_results.json" ]]; then
            cat "$target_dir/vulnerabilities/nuclei_results.json" >> "$json_report"
        else
            echo "" >> "$json_report"
        fi
        echo "    ]," >> "$json_report"
        
        # Add XSS vulnerabilities
        echo "    \"xss\": [" >> "$json_report"
        if [[ -f "$target_dir/vulnerabilities/xss_vulnerabilities.txt" && $(grep -c -v "No XSS vulnerabilities" "$target_dir/vulnerabilities/xss_vulnerabilities.txt") -gt 0 ]]; then
            local first_item=true
            while read -r vuln_line; do
                [[ -z "$vuln_line" || "$vuln_line" == "No XSS"* ]] && continue
                
                if [[ "$vuln_line" == "Payload:"* ]]; then
                    # This is a payload line, add it to the current object
                    echo "        \"payload\": \"$(echo "$vuln_line" | cut -d' ' -f2-)\"" >> "$json_report"
                    echo "      }" >> "$json_report"
                else
                    # This is a URL line, start a new object
                    if [[ "$first_item" == true ]]; then
                        echo "      {" >> "$json_report"
                        first_item=false
                    else
                        echo "      ,{" >> "$json_report"
                    fi
                    echo "        \"url\": \"$vuln_line\"," >> "$json_report"
                fi
            done < "$target_dir/vulnerabilities/xss_vulnerabilities.txt"
        fi
        echo "    ]," >> "$json_report"
        
        # Add SQLi vulnerabilities
        echo "    \"sqli\": [" >> "$json_report"
        if [[ -f "$target_dir/vulnerabilities/sqli_vulnerabilities.txt" && $(grep -c -v "No SQL injection vulnerabilities" "$target_dir/vulnerabilities/sqli_vulnerabilities.txt") -gt 0 ]]; then
            local first_item=true
            local url=""
            local injection_point=""
            local injection_type=""
            
            while read -r line; do
                [[ -z "$line" || "$line" == "No SQL"* || "$line" == "---"* ]] && continue
                
                if [[ "$line" == "Vulnerable URL:"* ]]; then
                    url=$(echo "$line" | cut -d' ' -f3-)
                    
                    # If we already have a complete entry, add it to the report
                    if [[ "$first_item" == false && -n "$url" && -n "$injection_point" && -n "$injection_type" ]]; then
                        echo "      ,{" >> "$json_report"
                    else
                        echo "      {" >> "$json_report"
                        first_item=false
                    fi
                    
                    echo "        \"url\": \"$url\"," >> "$json_report"
                elif [[ "$line" == "Injection Point:"* ]]; then
                    injection_point=$(echo "$line" | cut -d' ' -f3-)
                    echo "        \"injection_point\": \"$injection_point\"," >> "$json_report"
                elif [[ "$line" == "Injection Type:"* ]]; then
                    injection_type=$(echo "$line" | cut -d' ' -f3-)
                    echo "        \"injection_type\": \"$injection_type\"" >> "$json_report"
                    echo "      }" >> "$json_report"
                fi
            done < "$target_dir/vulnerabilities/sqli_vulnerabilities.txt"
        fi
        echo "    ]," >> "$json_report"
        
        # Add open redirect vulnerabilities
        echo "    \"open_redirect\": [" >> "$json_report"
        if [[ -f "$target_dir/vulnerabilities/openredirect_vulnerabilities.txt" && $(grep -c -v "No open redirect vulnerabilities" "$target_dir/vulnerabilities/openredirect_vulnerabilities.txt") -gt 0 ]]; then
            local first_item=true
            local url=""
            local redirect=""
            
            while read -r line; do
                [[ -z "$line" || "$line" == "No open"* || "$line" == "---"* ]] && continue
                
                if [[ "$line" == "Vulnerable URL:"* ]]; then
                    url=$(echo "$line" | cut -d' ' -f3-)
                    
                    # If we already have a complete entry, add it to the report
                    if [[ "$first_item" == false && -n "$url" && -n "$redirect" ]]; then
                        echo "      ,{" >> "$json_report"
                    else
                        echo "      {" >> "$json_report"
                        first_item=false
                    fi
                    
                    echo "        \"url\": \"$url\"," >> "$json_report"
                elif [[ "$line" == "Redirects to:"* ]]; then
                    redirect=$(echo "$line" | cut -d' ' -f3-)
                    echo "        \"redirects_to\": \"$redirect\"" >> "$json_report"
                    echo "      }" >> "$json_report"
                fi
            done < "$target_dir/vulnerabilities/openredirect_vulnerabilities.txt"
        fi
        echo "    ]" >> "$json_report"
        
        echo "  }" >> "$json_report"
        
        # Close the JSON structure
        echo "}" >> "$json_report"
        
        log_message "JSON report generated: $json_report" "SUCCESS"
    fi
    
    # Generate HTML report
    if [[ "$OUTPUT_FORMAT" == "html" || "$OUTPUT_FORMAT" == "all" ]]; then
        local html_report="$target_dir/reports/report.html"
        
        # Start HTML structure
        cat > "$html_report" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MR Legacy Bug Bounty Report - $target</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #d9534f;
            border-bottom: 2px solid #d9534f;
            padding-bottom: 10px;
        }
        h2 {
            color: #d9534f;
            margin-top: 30px;
        }
        h3 {
            color: #337ab7;
            margin-top: 20px;
        }
        .info-box {
            background-color: #f8f9fa;
            border-left: 4px solid #5bc0de;
            padding: 15px;
            margin: 20px 0;
        }
        .vuln-high {
            background-color: #f2dede;
            border-left: 4px solid #d9534f;
            padding: 15px;
            margin: 10px 0;
        }
        .vuln-medium {
            background-color: #fcf8e3;
            border-left: 4px solid #f0ad4e;
            padding: 15px;
            margin: 10px 0;
        }
        .vuln-low {
            background-color: #dff0d8;
            border-left: 4px solid #5cb85c;
            padding: 15px;
            margin: 10px 0;
        }
        pre {
            background-color: #f5f5f5;
            padding: 15px;
            overflow-x: auto;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .url {
            word-break: break-all;
        }
        .footer {
            margin-top: 50px;
            border-top: 1px solid #ddd;
            padding-top: 10px;
            color: #777;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <h1>MR Legacy Bug Bounty Report</h1>
    
    <div class="info-box">
        <p><strong>Target:</strong> $target</p>
        <p><strong>Date:</strong> $(date)</p>
    </div>
    
    <h2>1. Reconnaissance</h2>
EOF
        
        # Add subdomains
        if [[ -f "$target_dir/recon/subdomains/subdomains.txt" ]]; then
            local subdomain_count=$(wc -l < "$target_dir/recon/subdomains/subdomains.txt")
            
            cat >> "$html_report" << EOF
    <h3>Subdomains (${subdomain_count})</h3>
    <pre>
EOF
            cat "$target_dir/recon/subdomains/subdomains.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
        else
            cat >> "$html_report" << EOF
    <h3>Subdomains</h3>
    <p>No subdomain information available</p>
EOF
        fi
        
        # Add live hosts
        if [[ -f "$target_dir/recon/hosts/alive_hosts.txt" ]]; then
            local host_count=$(wc -l < "$target_dir/recon/hosts/alive_hosts.txt")
            
            cat >> "$html_report" << EOF
    <h3>Live Hosts (${host_count})</h3>
    <pre>
EOF
            cat "$target_dir/recon/hosts/alive_hosts.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
        else
            cat >> "$html_report" << EOF
    <h3>Live Hosts</h3>
    <p>No live host information available</p>
EOF
        fi
        
        # Add technologies
        cat >> "$html_report" << EOF
    <h3>Technologies Detected</h3>
EOF
        
        if [[ -f "$target_dir/recon/tech/technologies.txt" ]]; then
            cat >> "$html_report" << EOF
    <pre>
EOF
            cat "$target_dir/recon/tech/technologies.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
        else
            cat >> "$html_report" << EOF
    <p>No technology information available</p>
EOF
        fi
        
        # Add scanning results
        cat >> "$html_report" << EOF
    <h2>2. Scanning</h2>
    <h3>Open Ports</h3>
EOF
        
        if [[ -f "$target_dir/scanning/ports/open_ports.txt" ]]; then
            cat >> "$html_report" << EOF
    <pre>
EOF
            cat "$target_dir/scanning/ports/open_ports.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
        else
            cat >> "$html_report" << EOF
    <p>No port scanning information available</p>
EOF
        fi
        
        # Add web fingerprinting
        cat >> "$html_report" << EOF
    <h3>Web Fingerprinting</h3>
EOF
        
        if [[ -f "$target_dir/scanning/web/fingerprinting.txt" ]]; then
            cat >> "$html_report" << EOF
    <pre>
EOF
            cat "$target_dir/scanning/web/fingerprinting.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
        else
            cat >> "$html_report" << EOF
    <p>No web fingerprinting information available</p>
EOF
        fi
        
        # Add enumeration results
        cat >> "$html_report" << EOF
    <h2>3. Enumeration</h2>
    <h3>Directories Found</h3>
EOF
        
        if [[ -d "$target_dir/enumeration/directories" ]]; then
            local dir_files=$(find "$target_dir/enumeration/directories" -type f -name "*_directories.txt" | wc -l)
            
            if [[ $dir_files -gt 0 ]]; then
                cat >> "$html_report" << EOF
    <pre>
EOF
                find "$target_dir/enumeration/directories" -type f -name "*_directories.txt" -exec cat {} \; >> "$html_report"
                echo "    </pre>" >> "$html_report"
            else
                cat >> "$html_report" << EOF
    <p>No directories found during enumeration</p>
EOF
            fi
        else
            cat >> "$html_report" << EOF
    <p>No directory enumeration information available</p>
EOF
        fi
        
        # Add parameters
        cat >> "$html_report" << EOF
    <h3>Parameters Found</h3>
EOF
        
        if [[ -f "$target_dir/enumeration/parameters/all_parameters.txt" ]]; then
            local param_count=$(wc -l < "$target_dir/enumeration/parameters/all_parameters.txt")
            
            cat >> "$html_report" << EOF
    <p>Found $param_count unique parameters:</p>
    <pre>
EOF
            cat "$target_dir/enumeration/parameters/all_parameters.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
        else
            cat >> "$html_report" << EOF
    <p>No parameter discovery information available</p>
EOF
        fi
        
        # Add JavaScript analysis
        cat >> "$html_report" << EOF
    <h3>JavaScript Analysis</h3>
EOF
        
        if [[ -f "$target_dir/enumeration/js/endpoints.txt" ]]; then
            local endpoint_count=$(wc -l < "$target_dir/enumeration/js/endpoints.txt")
            
            cat >> "$html_report" << EOF
    <p>Found $endpoint_count endpoints in JavaScript files:</p>
    <pre class="url">
EOF
            cat "$target_dir/enumeration/js/endpoints.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
            
            if [[ -f "$target_dir/enumeration/js/secrets.txt" ]]; then
                local secret_count=$(wc -l < "$target_dir/enumeration/js/secrets.txt")
                
                cat >> "$html_report" << EOF
    <p>Found $secret_count potential secrets in JavaScript files:</p>
    <pre>
EOF
                cat "$target_dir/enumeration/js/secrets.txt" >> "$html_report"
                echo "    </pre>" >> "$html_report"
            else
                cat >> "$html_report" << EOF
    <p>No secrets found in JavaScript files</p>
EOF
            fi
        else
            cat >> "$html_report" << EOF
    <p>No JavaScript analysis information available</p>
EOF
        fi
        
        # Add Cloud Resources
        cat >> "$html_report" << EOF
    <h2>4. Cloud Resources</h2>
EOF
        
        if [[ -f "$target_dir/cloud/cloud_resources.txt" ]]; then
            cat >> "$html_report" << EOF
    <h3>Cloud Resources</h3>
    <pre>
EOF
            cat "$target_dir/cloud/cloud_resources.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
        else
            cat >> "$html_report" << EOF
    <p>No cloud resources information available.</p>
EOF
        fi
        
        # Add vulnerability results
        cat >> "$html_report" << EOF
    <h2>5. Vulnerabilities</h2>
    <h3>Nuclei Scan Results</h3>
EOF
        
        if [[ -f "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" ]]; then
            # Count vulnerabilities more reliably by writing them to temp files first
            local critical_count=0
            local high_count=0 
            local medium_count=0
            local low_count=0
            local info_count=0
            local total_count=0
            
            # Simpler counting approach that doesn't rely on complex arithmetic
            if grep -q "\[critical\]" "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" 2>/dev/null; then
                grep "\[critical\]" "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" > /tmp/critical.tmp
                critical_count=$(wc -l < /tmp/critical.tmp)
                total_count=$((total_count + critical_count))
            fi
            
            if grep -q "\[high\]" "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" 2>/dev/null; then
                grep "\[high\]" "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" > /tmp/high.tmp
                high_count=$(wc -l < /tmp/high.tmp)
                total_count=$((total_count + high_count))
            fi
            
            if grep -q "\[medium\]" "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" 2>/dev/null; then
                grep "\[medium\]" "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" > /tmp/medium.tmp
                medium_count=$(wc -l < /tmp/medium.tmp)
                total_count=$((total_count + medium_count))
            fi
            
            if grep -q "\[low\]" "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" 2>/dev/null; then
                grep "\[low\]" "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" > /tmp/low.tmp
                low_count=$(wc -l < /tmp/low.tmp)
                total_count=$((total_count + low_count))
            fi
            
            if grep -q "\[info\]" "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" 2>/dev/null; then
                grep "\[info\]" "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" > /tmp/info.tmp
                info_count=$(wc -l < /tmp/info.tmp)
                total_count=$((total_count + info_count))
            fi
            
            cat >> "$html_report" << EOF
    <p>Found $total_count vulnerabilities: $critical_count critical, $high_count high, $medium_count medium, $low_count low, $info_count info</p>
    <pre>
EOF
            cat "$target_dir/vulnerabilities/nuclei_vulnerabilities.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
        else
            cat >> "$html_report" << EOF
    <p>No Nuclei scan information available</p>
EOF
        fi
        
        # Add XSS vulnerabilities
        cat >> "$html_report" << EOF
    <h3>XSS Vulnerabilities</h3>
EOF
        
        if [[ -f "$target_dir/vulnerabilities/xss_vulnerabilities.txt" && $(grep -c -v "No XSS vulnerabilities" "$target_dir/vulnerabilities/xss_vulnerabilities.txt") -gt 0 ]]; then
            local xss_count=$(grep -c -v "Payload:" "$target_dir/vulnerabilities/xss_vulnerabilities.txt")
            
            cat >> "$html_report" << EOF
    <p>Found $xss_count potential XSS vulnerabilities:</p>
EOF
            
            # Process each vulnerability
            local current_url=""
            local current_payload=""
            
            while read -r line; do
                [[ -z "$line" || "$line" == "No XSS"* || "$line" == "---"* ]] && continue
                
                if [[ "$line" == "Payload:"* ]]; then
                    current_payload=$(echo "$line" | cut -d' ' -f2-)
                    
                    cat >> "$html_report" << EOF
    <div class="vuln-high">
        <p><strong>URL:</strong> <span class="url">$current_url</span></p>
        <p><strong>Payload:</strong> <code>$current_payload</code></p>
    </div>
EOF
                else
                    current_url="$line"
                fi
            done < "$target_dir/vulnerabilities/xss_vulnerabilities.txt"
        else
            cat >> "$html_report" << EOF
    <p>No XSS vulnerabilities found</p>
EOF
        fi
        
        # Add SQLi vulnerabilities
        cat >> "$html_report" << EOF
    <h3>SQL Injection Vulnerabilities</h3>
EOF
        
        if [[ -f "$target_dir/vulnerabilities/sqli_vulnerabilities.txt" && $(grep -c -v "No SQL injection vulnerabilities" "$target_dir/vulnerabilities/sqli_vulnerabilities.txt") -gt 0 ]]; then
            local sqli_count=$(grep -c "Vulnerable URL:" "$target_dir/vulnerabilities/sqli_vulnerabilities.txt")
            
            cat >> "$html_report" << EOF
    <p>Found $sqli_count potential SQL injection vulnerabilities:</p>
EOF
            
            # Process each vulnerability
            local url=""
            local injection_point=""
            local injection_type=""
            
            while read -r line; do
                [[ -z "$line" || "$line" == "No SQL"* || "$line" == "---"* ]] && continue
                
                if [[ "$line" == "Vulnerable URL:"* ]]; then
                    url=$(echo "$line" | cut -d' ' -f3-)
                elif [[ "$line" == "Injection Point:"* ]]; then
                    injection_point=$(echo "$line" | cut -d' ' -f3-)
                elif [[ "$line" == "Injection Type:"* ]]; then
                    injection_type=$(echo "$line" | cut -d' ' -f3-)
                    
                    cat >> "$html_report" << EOF
    <div class="vuln-high">
        <p><strong>URL:</strong> <span class="url">$url</span></p>
        <p><strong>Injection Point:</strong> $injection_point</p>
        <p><strong>Injection Type:</strong> $injection_type</p>
    </div>
EOF
                fi
            done < "$target_dir/vulnerabilities/sqli_vulnerabilities.txt"
        else
            cat >> "$html_report" << EOF
    <p>No SQL injection vulnerabilities found</p>
EOF
        fi
        
        # Add open redirect vulnerabilities
        cat >> "$html_report" << EOF
    <h3>Open Redirect Vulnerabilities</h3>
EOF
        
        if [[ -f "$target_dir/vulnerabilities/openredirect_vulnerabilities.txt" && $(grep -c -v "No open redirect vulnerabilities" "$target_dir/vulnerabilities/openredirect_vulnerabilities.txt") -gt 0 ]]; then
            local redir_count=$(grep -c "Vulnerable URL:" "$target_dir/vulnerabilities/openredirect_vulnerabilities.txt")
            
            cat >> "$html_report" << EOF
    <p>Found $redir_count potential open redirect vulnerabilities:</p>
EOF
            
            # Process each vulnerability
            local url=""
            local redirect=""
            
            while read -r line; do
                [[ -z "$line" || "$line" == "No open"* || "$line" == "---"* ]] && continue
                
                if [[ "$line" == "Vulnerable URL:"* ]]; then
                    url=$(echo "$line" | cut -d' ' -f3-)
                elif [[ "$line" == "Redirects to:"* ]]; then
                    redirect=$(echo "$line" | cut -d' ' -f3-)
                    
                    cat >> "$html_report" << EOF
    <div class="vuln-medium">
        <p><strong>URL:</strong> <span class="url">$url</span></p>
        <p><strong>Redirects to:</strong> <span class="url">$redirect</span></p>
    </div>
EOF
                fi
            done < "$target_dir/vulnerabilities/openredirect_vulnerabilities.txt"
        else
            cat >> "$html_report" << EOF
    <p>No open redirect vulnerabilities found</p>
EOF
        fi
        
        # Add exploitation results
        cat >> "$html_report" << EOF
    <h2>6. Exploitation</h2>
EOF
        
        if [[ -f "$target_dir/exploitation/exploitation_summary.txt" ]]; then
            cat >> "$html_report" << EOF
    <pre>
EOF
            cat "$target_dir/exploitation/exploitation_summary.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
        else
            cat >> "$html_report" << EOF
    <p>No exploitation information available</p>
EOF
        fi
        
        # Add AI Analysis if available
        if [[ -f "$target_dir/ai_analysis.html" ]]; then
            cat >> "$html_report" << EOF
    <h2>7. AI Analysis</h2>
    <p>View the detailed AI analysis <a href="../ai_analysis.html" target="_blank">here</a>.</p>
EOF
        elif [[ -f "$target_dir/ai_analysis.txt" ]]; then
            cat >> "$html_report" << EOF
    <h2>7. AI Analysis</h2>
    <pre>
EOF
            cat "$target_dir/ai_analysis.txt" >> "$html_report"
            echo "    </pre>" >> "$html_report"
        fi
        
        # Add footer
        cat >> "$html_report" << EOF
    <div class="footer">
        <p>Report generated by MR Legacy Bug Bounty Tool v1.1.0</p>
        <p>Author: Abdulrahman Muhammad (0xLegacy)</p>
    </div>
</body>
</html>
EOF
        
        log_message "HTML report generated: $html_report" "SUCCESS"
    fi
}

# Function to clean up temporary files and set proper permissions
function cleanup() {
    log_message "Cleaning up..." "INFO"
    
    # Remove temporary files
    rm -rf "${target_dir}/.tmp" 2>/dev/null
    rm -f /tmp/critical.tmp /tmp/high.tmp /tmp/medium.tmp /tmp/low.tmp /tmp/info.tmp /tmp/debug.log 2>/dev/null
    
    # Set proper permissions for results directory
    find "$target_dir" -type d -exec chmod 755 {} \; 2>/dev/null
    find "$target_dir" -type f -exec chmod 644 {} \; 2>/dev/null
    
    log_message "Clean up complete" "SUCCESS"
}

# Main function
function main() {
    # Show banner
    show_banner
    
    # Parse command line arguments
    parse_args "$@"
    
    # Show start banner with information
    show_start_banner
    
    # Run tool checks
    run_tool_checks
    
    # Set up Tor proxy if needed
    if [[ "$TOR" == true ]]; then
        setup_tor_proxy
    fi
    
    # Run the modules based on user selection or AUTO mode
    if [[ "$AUTO" == true ]]; then
        log_message "Running Auto Recon for $target" "INFO"
        
        # Run modules in the most logical order
        run_recon_module
        run_scanning_module
        
        # Run port scanning module if available
        if type run_port_scanning_module &>/dev/null; then
            run_port_scanning_module
        fi
        
        run_enumeration_module
        
        # Run OSINT module if available
        if type run_osint_module &>/dev/null; then
            run_osint_module
        fi
        
        # Run content discovery module if available
        if type run_content_discovery_module &>/dev/null; then
            run_content_discovery_module
        fi
        
        # Run web scanning module if available
        if type run_web_scanning_module &>/dev/null; then
            run_web_scanning_module
        fi
        
        # Run subdomain takeover module if available
        if type run_subdomain_takeover_module &>/dev/null; then
            run_subdomain_takeover_module
        fi
        
        # Run security headers module if available
        if type run_security_headers_module &>/dev/null; then
            run_security_headers_module
        fi
        
        # Run error handling module if available
        if type run_error_handling_module &>/dev/null; then
            run_error_handling_module
        fi
        
        run_vulnerability_module
        run_exploitation_module
        run_cloud_module
        
        # Run AI analysis if available
        if command_exists "python3" && [[ -f "$script_path/ai_helper/ai_assistant.py" ]]; then
            log_message "Running AI analysis..." "INFO"
            python3 "$script_path/ai_helper/ai_assistant.py" --target "$target" --results-dir "$target_dir"
        fi
        
        # Generate reports
        show_reporting_banner
        generate_reports
        
        # Cleanup
        cleanup
        
        log_message "Auto Recon completed for $target" "SUCCESS"
    else
        # Display menu for interactive mode
        log_message "Interactive mode: Please select a module to run" "INFO"
        echo "1. Reconnaissance"
        echo "2. Scanning"
        echo "3. Port Scanning"
        echo "4. Enumeration"
        echo "5. Vulnerability Scanning"
        echo "6. Web Application Scanning"
        echo "7. Exploitation"
        echo "8. OSINT (Open Source Intelligence)"
        echo "9. Content Discovery (Hidden Files & Dirs)"
        echo "10. Subdomain Takeover Checks"
        echo "11. Security Headers Analysis"
        echo "12. Error Handling & Debug Info Checks"
        echo "13. Authentication Testing"
        echo "14. Cloud Resources"
        echo "15. Generate Reports"
        echo "16. Run All (Auto Recon)"
        echo "17. Exit"
        
        read -p "Enter your choice (1-17): " choice
        
        case "$choice" in
            1) run_recon_module ;;
            2) run_scanning_module ;;
            3) 
                # Run Port Scanning module
                if type run_port_scanning_module &>/dev/null; then
                    run_port_scanning_module
                else
                    log_message "Port Scanning module not found" "ERROR"
                fi
                ;;
            4) run_enumeration_module ;;
            5) run_vulnerability_module ;;
            6) 
                # Run Web Application Scanning module
                if type run_web_scanning_module &>/dev/null; then
                    run_web_scanning_module
                else
                    log_message "Web Application Scanning module not found" "ERROR"
                fi
                ;;
            7) run_exploitation_module ;;
            8) 
                # Run OSINT module
                if type run_osint_module &>/dev/null; then
                    run_osint_module
                else
                    log_message "OSINT module not found" "ERROR"
                fi
                ;;
            9)
                # Run Content Discovery module
                if type run_content_discovery_module &>/dev/null; then
                    run_content_discovery_module
                else
                    log_message "Content Discovery module not found" "ERROR"
                fi
                ;;
            10)
                # Run Subdomain Takeover module
                if type run_subdomain_takeover_module &>/dev/null; then
                    run_subdomain_takeover_module
                else
                    log_message "Subdomain Takeover module not found" "ERROR"
                fi
                ;;
            11)
                # Run Security Headers module
                if type run_security_headers_module &>/dev/null; then
                    run_security_headers_module
                else
                    log_message "Security Headers module not found" "ERROR"
                fi
                ;;
            12)
                # Run Error Handling module
                if type run_error_handling_module &>/dev/null; then
                    run_error_handling_module
                else
                    log_message "Error Handling module not found" "ERROR"
                fi
                ;;
            13)
                # Run Authentication Testing module
                if type run_auth_testing_module &>/dev/null; then
                    run_auth_testing_module
                else
                    log_message "Authentication Testing module not found" "ERROR"
                fi
                ;;
            14) run_cloud_module ;;
            15) 
                show_reporting_banner
                generate_reports
                cleanup
                ;;
            16)
                # Run Auto Recon (all modules)
                log_message "Running Auto Recon for $target" "INFO"
                
                # Run modules in the most logical order
                run_recon_module
                run_scanning_module
                
                # Run port scanning module if available
                if type run_port_scanning_module &>/dev/null; then
                    run_port_scanning_module
                fi
                
                run_enumeration_module
                
                # Run OSINT module if available
                if type run_osint_module &>/dev/null; then
                    run_osint_module
                fi
                
                # Run content discovery module if available
                if type run_content_discovery_module &>/dev/null; then
                    run_content_discovery_module
                fi
                
                # Run web scanning module if available
                if type run_web_scanning_module &>/dev/null; then
                    run_web_scanning_module
                fi
                
                # Run subdomain takeover module if available
                if type run_subdomain_takeover_module &>/dev/null; then
                    run_subdomain_takeover_module
                fi
                
                # Run security headers module if available
                if type run_security_headers_module &>/dev/null; then
                    run_security_headers_module
                fi
                
                # Run error handling module if available
                if type run_error_handling_module &>/dev/null; then
                    run_error_handling_module
                fi
                
                # Run authentication testing module if available
                if type run_auth_testing_module &>/dev/null; then
                    run_auth_testing_module
                fi
                
                run_vulnerability_module
                run_exploitation_module
                run_cloud_module
                
                # Run AI analysis if available
                if command_exists "python3" && [[ -f "$script_path/ai_helper/ai_assistant.py" ]]; then
                    log_message "Running AI analysis..." "INFO"
                    python3 "$script_path/ai_helper/ai_assistant.py" --target "$target" --results-dir "$target_dir"
                fi
                
                show_reporting_banner
                generate_reports
                cleanup
                
                log_message "Auto Recon completed for $target" "SUCCESS"
                ;;
            17) 
                log_message "Exiting MR Legacy Bug Bounty Tool" "INFO"
                exit 0
                ;;
            *)
                log_message "Invalid choice. Exiting." "ERROR"
                exit 1
                ;;
        esac
    fi
}

# Run the main function with all arguments
main "$@"