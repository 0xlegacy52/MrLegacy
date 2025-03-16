#!/bin/bash
# Port Scanning Module for MR Legacy Bug Bounty Tool
# Author: Abdulrahman Muhammad (0xLegacy)
# This module performs comprehensive port scanning and service detection

# Load the common functions
if [[ -f "./utils/common.sh" ]]; then
    source "./utils/common.sh"
else
    echo "Error: common.sh not found"
    exit 1
fi

# Port Scanning Banner
show_port_scanning_banner() {
    echo '
██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║
██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
================================================================================
  Advanced Port Scanning & Service Detection
================================================================================'
}

# Function to run an enhanced quick port scan
run_quick_port_scan() {
    local target=$1
    local output_dir=$2
    local nmap_quick_output="${output_dir}/port_scan/nmap_quick_scan.txt"
    local json_output="${output_dir}/port_scan/port_scan_results.json"
    local html_report="${output_dir}/port_scan/port_scan_report.html"
    local summary_file="${output_dir}/port_scan/port_scan_summary.md"
    
    # Create directory structure
    mkdir -p "${output_dir}/port_scan" 2>/dev/null
    
    log_message "Starting enhanced port scan on ${target}" "INFO"
    
    # Initialize JSON output
    echo '{' > "${json_output}"
    echo '  "target": "'${target}'", ' >> "${json_output}"
    echo '  "scan_date": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'", ' >> "${json_output}"
    echo '  "scan_type": "quick", ' >> "${json_output}"
    echo '  "ports": [' >> "${json_output}"
    
    # Initialize summary file
    echo "# Port Scan Summary for ${target}" > "${summary_file}"
    echo "## Scan Date: $(date)" >> "${summary_file}"
    echo "" >> "${summary_file}"
    
    if command_exists "nmap"; then
        log_message "Using nmap for comprehensive port scanning" "INFO"
        
        # First do a quick scan of common ports to get fast results
        log_message "Phase 1: Scanning common ports" "INFO"
        nmap -sS -T4 --min-rate=1000 --open -oN "${output_dir}/port_scan/common_ports.txt" ${target} 2>/dev/null
        
        # Then do a full port scan with increased intensity
        log_message "Phase 2: Full port range scan" "INFO"
        nmap -sS -T4 --min-rate=1000 -p- --open ${target} -oN "${nmap_quick_output}" 2>/dev/null
        
        # Get service versions for open ports
        open_ports=$(grep "^[0-9]" "${nmap_quick_output}" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
        
        if [[ -n "${open_ports}" ]]; then
            log_message "Phase 3: Service version detection on open ports" "INFO"
            nmap -sV -p ${open_ports} ${target} -oN "${output_dir}/port_scan/service_detection.txt" 2>/dev/null
        fi
        
        log_message "Enhanced port scan completed" "SUCCESS"
        
        # Process the results and categorize ports by security relevance
        echo "## Open Ports and Services" >> "${summary_file}"
        echo "" >> "${summary_file}"
        echo "| Port | Service | Version | Security Relevance |" >> "${summary_file}"
        echo "|------|---------|---------|-------------------|" >> "${summary_file}"
        
        # Define high-value ports with security implications
        declare -A security_relevance
        security_relevance[21]="File Transfer (FTP) - Often has authentication weaknesses"
        security_relevance[22]="SSH - Check for outdated versions vulnerable to user enumeration"
        security_relevance[23]="Telnet - Cleartext protocol, critical security risk"
        security_relevance[25]="SMTP - Email server, check for open relay or SMTP user enumeration"
        security_relevance[53]="DNS - Potential for zone transfers or cache poisoning"
        security_relevance[80]="HTTP - Web server, primary attack surface for web vulnerabilities"
        security_relevance[110]="POP3 - Email retrieval, potential for cleartext auth"
        security_relevance[111]="RPC - Remote Procedure Call, often vulnerable"
        security_relevance[135]="MSRPC - Windows RPC, potential for remote exploits"
        security_relevance[139]="NetBIOS - Windows file sharing, often misconfigured"
        security_relevance[143]="IMAP - Email access, check for cleartext auth"
        security_relevance[389]="LDAP - Directory services, potential for information disclosure"
        security_relevance[443]="HTTPS - Secure web, check for SSL/TLS issues"
        security_relevance[445]="SMB - Windows file sharing, high-value target"
        security_relevance[1433]="MSSQL - Database, check for weak authentication"
        security_relevance[1521]="Oracle DB - Database, often has default credentials"
        security_relevance[3306]="MySQL - Database, check for weak credentials"
        security_relevance[3389]="RDP - Remote Desktop, brute force target"
        security_relevance[5432]="PostgreSQL - Database, check for weak credentials"
        security_relevance[5900]="VNC - Remote access, often poorly secured"
        security_relevance[8080]="HTTP-Alt - Alternative web server, often for admin interfaces"
        security_relevance[8443]="HTTPS-Alt - Alternative secure web, check for dev environments"
        security_relevance[27017]="MongoDB - NoSQL database, often unsecured"
        security_relevance[6379]="Redis - In-memory data store, often unprotected"
        
        # Parse nmap output
        local first_port=true
        grep "^[0-9]" "${output_dir}/port_scan/service_detection.txt" | while read -r line; do
            port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
            protocol=$(echo "$line" | awk '{print $1}' | cut -d'/' -f2)
            state=$(echo "$line" | awk '{print $2}')
            service=$(echo "$line" | awk '{print $3}')
            version=""
            
            # Extract version information if available
            if [[ "$line" == *"VERSION"* ]]; then
                version=$(echo "$line" | grep -oP '(?<=VERSION:)[^,]+' | tr -d ' ')
            fi
            
            # Get security relevance
            relevance="${security_relevance[$port]}"
            if [[ -z "$relevance" ]]; then
                relevance="Standard service, verify secure configuration"
            fi
            
            # Add to summary
            echo "| $port | $service | $version | $relevance |" >> "${summary_file}"
            
            # Add to JSON
            if [ "$first_port" = true ]; then
                first_port=false
            else
                echo "  ," >> "${json_output}"
            fi
            
            echo "  {" >> "${json_output}"
            echo "    \"port\": $port," >> "${json_output}"
            echo "    \"protocol\": \"$protocol\"," >> "${json_output}"
            echo "    \"state\": \"$state\"," >> "${json_output}"
            echo "    \"service\": \"$service\"," >> "${json_output}"
            echo "    \"version\": \"$version\"," >> "${json_output}"
            echo "    \"security_relevance\": \"${relevance}\"" >> "${json_output}"
            echo "  }" >> "${json_output}"
        done
        
        # Add recommendations based on findings
        echo "" >> "${summary_file}"
        echo "## Security Recommendations" >> "${summary_file}"
        echo "" >> "${summary_file}"
        
        # Check for high-risk ports
        if grep -q "^21/\|^23/\|^135/\|^139/\|^445/\|^3389/" "${nmap_quick_output}"; then
            echo "- **HIGH RISK**: High-risk services detected. Immediate attention recommended." >> "${summary_file}"
        fi
        
        # Check for database ports
        if grep -q "^1433/\|^3306/\|^5432/\|^27017/\|^6379/" "${nmap_quick_output}"; then
            echo "- **Database Exposure**: Database services are exposed. Ensure they require authentication and are not accessible from unauthorized networks." >> "${summary_file}"
        fi
        
        # Web servers
        if grep -q "^80/\|^443/\|^8080/\|^8443/" "${nmap_quick_output}"; then
            echo "- **Web Security**: Web services detected. Consider running a web vulnerability scan and implement proper security headers." >> "${summary_file}"
        fi
        
    else
        log_message "Nmap not found, using enhanced netcat fallback for port scanning" "WARNING"
        
        # Define common ports with descriptions for the fallback method
        declare -A port_descriptions
        port_descriptions[21]="FTP"
        port_descriptions[22]="SSH"
        port_descriptions[23]="Telnet"
        port_descriptions[25]="SMTP"
        port_descriptions[53]="DNS"
        port_descriptions[80]="HTTP"
        port_descriptions[110]="POP3"
        port_descriptions[111]="RPC"
        port_descriptions[135]="MSRPC"
        port_descriptions[139]="NetBIOS"
        port_descriptions[143]="IMAP"
        port_descriptions[389]="LDAP"
        port_descriptions[443]="HTTPS"
        port_descriptions[445]="SMB"
        port_descriptions[1433]="MSSQL"
        port_descriptions[1521]="Oracle"
        port_descriptions[3306]="MySQL"
        port_descriptions[3389]="RDP"
        port_descriptions[5432]="PostgreSQL"
        port_descriptions[5900]="VNC"
        port_descriptions[8080]="HTTP-Alt"
        port_descriptions[8443]="HTTPS-Alt"
        port_descriptions[27017]="MongoDB"
        port_descriptions[6379]="Redis"
        
        # Initialize the quick output file
        > "${nmap_quick_output}"
        
        # Table header in summary
        echo "## Open Ports (Limited Scan)" >> "${summary_file}"
        echo "" >> "${summary_file}"
        echo "| Port | Service | Status |" >> "${summary_file}"
        echo "|------|---------|--------|" >> "${summary_file}"
        
        # Track if we've added any ports to JSON
        local first_port=true
        
        # Extended port list for netcat
        for port in 21 22 23 25 53 80 110 111 135 139 143 389 443 445 1433 1521 3306 3389 5432 5900 8080 8443 27017 6379; do
            log_message "Checking port ${port}" "DEBUG"
            service="${port_descriptions[$port]}"
            
            # Use timeout to avoid hanging
            if timeout 2 nc -z -v -w1 "${target}" "${port}" &>/dev/null; then
                status="open"
                echo "Port ${port} (${service}) is open" >> "${nmap_quick_output}"
                echo "| ${port} | ${service} | OPEN |" >> "${summary_file}"
                
                # Add to JSON
                if [ "$first_port" = true ]; then
                    first_port=false
                else
                    echo "  ," >> "${json_output}"
                fi
                
                echo "  {" >> "${json_output}"
                echo "    \"port\": $port," >> "${json_output}"
                echo "    \"protocol\": \"tcp\"," >> "${json_output}"
                echo "    \"state\": \"open\"," >> "${json_output}"
                echo "    \"service\": \"$service\"," >> "${json_output}"
                echo "    \"version\": \"unknown\"," >> "${json_output}"
                echo "    \"security_relevance\": \"${security_relevance[$port]}\"" >> "${json_output}"
                echo "  }" >> "${json_output}"
            fi
        done
        
        log_message "Enhanced basic port scan completed with netcat" "INFO"
    fi
    
    # Finish JSON file
    echo ']' >> "${json_output}"
    echo '}' >> "${json_output}"
    
    # If no ports were found, make sure JSON is valid
    if grep -q "\"ports\": \[]" "${json_output}"; then
        sed -i 's/"ports": \[/"ports": [/' "${json_output}"
    fi
    
    # Extract open ports from the scan results
    if [[ -f "${nmap_quick_output}" ]]; then
        grep -E "open|succeeded" "${nmap_quick_output}" > "${output_dir}/open_ports.txt"
    fi
}

# Function to perform service detection on open ports
run_service_detection() {
    local target=$1
    local output_dir=$2
    local open_ports_file="${output_dir}/open_ports.txt"
    local service_output="${output_dir}/service_detection.txt"
    
    if [[ ! -f "${open_ports_file}" ]]; then
        log_message "No open ports file found. Run a port scan first." "WARNING"
        return 1
    fi
    
    log_message "Starting service detection on open ports for ${target}" "INFO"
    
    if command_exists "nmap"; then
        # Extract port numbers from the open ports file
        local ports=$(grep -oP '\d+/(?:tcp|udp)' "${open_ports_file}" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
        
        if [[ -n "${ports}" ]]; then
            nmap -sV -p${ports} ${target} -oN "${service_output}" 2>/dev/null
            log_message "Service detection completed" "SUCCESS"
        else
            log_message "No ports extracted from open ports file" "WARNING"
        fi
    else
        log_message "Nmap not found, cannot perform accurate service detection" "ERROR"
    fi
}

# Function to check for SSL/TLS vulnerabilities
check_ssl_vulnerabilities() {
    local target=$1
    local output_dir=$2
    local ssl_output="${output_dir}/ssl_vulnerabilities.txt"
    
    log_message "Checking SSL/TLS vulnerabilities for ${target}" "INFO"
    
    if command_exists "sslscan"; then
        sslscan --no-failed ${target} > "${ssl_output}" 2>/dev/null
        log_message "SSL vulnerability scan completed with sslscan" "SUCCESS"
    elif command_exists "nmap"; then
        nmap --script ssl-enum-ciphers -p 443 ${target} -oN "${ssl_output}" 2>/dev/null
        log_message "SSL cipher enumeration completed with nmap" "INFO"
    else
        log_message "No SSL scanning tools found. Install sslscan or nmap for better results." "WARNING"
        echo "SSL/TLS scanning requires sslscan or nmap with NSE scripts." > "${ssl_output}"
    fi
}

# Function to scan for common vulnerable services
scan_vulnerable_services() {
    local target=$1
    local output_dir=$2
    local vuln_services_output="${output_dir}/vulnerable_services.txt"
    
    log_message "Scanning for potentially vulnerable services on ${target}" "INFO"
    
    if command_exists "nmap"; then
        # Run nmap NSE scripts to check for vulnerable services
        nmap -sV --script vuln -p21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 ${target} -oN "${vuln_services_output}" 2>/dev/null
        log_message "Vulnerability scan completed with nmap NSE scripts" "SUCCESS"
    else
        log_message "Nmap not found, cannot scan for vulnerable services" "ERROR"
        echo "Nmap with NSE scripts is required for vulnerability scanning." > "${vuln_services_output}"
    fi
}

# Function to check for UDP services
scan_udp_services() {
    local target=$1
    local output_dir=$2
    local udp_output="${output_dir}/udp_services.txt"
    
    log_message "Scanning for UDP services on ${target}" "INFO"
    
    if command_exists "nmap"; then
        # Run UDP scan on common ports
        nmap -sU -T4 --top-ports 100 ${target} -oN "${udp_output}" 2>/dev/null
        log_message "UDP service scan completed" "SUCCESS"
    else
        log_message "Nmap not found, cannot scan for UDP services" "ERROR"
        echo "Nmap is required for UDP service scanning." > "${udp_output}"
    fi
}

# Function to gather service banners
gather_service_banners() {
    local target=$1
    local output_dir=$2
    local banners_output="${output_dir}/service_banners.txt"
    
    log_message "Gathering service banners from ${target}" "INFO"
    
    if command_exists "nmap"; then
        nmap -sV --script=banner -p21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 ${target} -oN "${banners_output}" 2>/dev/null
        log_message "Service banner collection completed" "SUCCESS"
    else
        log_message "Nmap not found, cannot collect service banners effectively" "ERROR"
        echo "Nmap is required for effective service banner collection." > "${banners_output}"
    fi
}

# Function to perform more aggressive timing options if deep scan is enabled
deep_port_scan() {
    local target=$1
    local output_dir=$2
    local deep_scan_output="${output_dir}/deep_port_scan.txt"
    
    log_message "Starting deep port scan on ${target} (this may take a while)" "INFO"
    
    if command_exists "nmap"; then
        # More aggressive scan with increased timing
        nmap -sS -T5 -A -p- --min-rate=10000 ${target} -oN "${deep_scan_output}" 2>/dev/null
        log_message "Deep port scan completed" "SUCCESS"
    else
        log_message "Nmap not found, cannot perform deep port scan" "ERROR"
        echo "Nmap is required for deep port scanning." > "${deep_scan_output}"
    fi
}

# Function to check for proxies and open ports that might indicate proxy services
check_proxy_services() {
    local target=$1
    local output_dir=$2
    local proxy_output="${output_dir}/proxy_services.txt"
    
    log_message "Checking for proxy services on ${target}" "INFO"
    
    if command_exists "nmap"; then
        # Check common proxy ports
        nmap -sV -p 80,443,808,1080,3128,8080,8081,8118,8888,9090 ${target} -oN "${proxy_output}" 2>/dev/null
        log_message "Proxy service check completed" "SUCCESS"
    else
        log_message "Nmap not found, cannot check for proxy services effectively" "WARNING"
        
        # Fallback to simple connection test with netcat
        echo "Checking common proxy ports with netcat:" > "${proxy_output}"
        for port in 80 443 808 1080 3128 8080 8081 8118 8888 9090; do
            (nc -z -v -w1 ${target} ${port} 2>&1 | grep -E "open|succeeded") >> "${proxy_output}" &
        done
        wait
        log_message "Basic proxy port check completed with netcat" "INFO"
    fi
}

# Function to create a well-formatted HTML report for port scanning results
generate_port_scan_report() {
    local target=$1
    local output_dir=$2
    local html_report="${output_dir}/port_scan_report.html"
    
    log_message "Generating port scan HTML report for ${target}" "INFO"
    
    # Create a simple HTML report
    cat > "${html_report}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Scanning Report for ${target}</title>
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
        .open-port {
            color: #27ae60;
            font-weight: bold;
        }
        .warning {
            color: #e67e22;
            font-weight: bold;
        }
        .danger {
            color: #c0392b;
            font-weight: bold;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Port Scanning Report for ${target}</h1>
        <p class="timestamp">Generated on $(date)</p>
        
        <div class="section">
            <h2>Open Ports Summary</h2>
            <div class="results">
$(if [[ -f "${output_dir}/open_ports.txt" ]]; then
    cat "${output_dir}/open_ports.txt"
else
    echo "No open ports data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Service Detection</h2>
            <div class="results">
$(if [[ -f "${output_dir}/service_detection.txt" ]]; then
    cat "${output_dir}/service_detection.txt"
else
    echo "No service detection data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>SSL/TLS Vulnerabilities</h2>
            <div class="results">
$(if [[ -f "${output_dir}/ssl_vulnerabilities.txt" ]]; then
    cat "${output_dir}/ssl_vulnerabilities.txt"
else
    echo "No SSL/TLS vulnerability data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Potentially Vulnerable Services</h2>
            <div class="results">
$(if [[ -f "${output_dir}/vulnerable_services.txt" ]]; then
    cat "${output_dir}/vulnerable_services.txt"
else
    echo "No vulnerable services data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>UDP Services</h2>
            <div class="results">
$(if [[ -f "${output_dir}/udp_services.txt" ]]; then
    cat "${output_dir}/udp_services.txt"
else
    echo "No UDP services data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Service Banners</h2>
            <div class="results">
$(if [[ -f "${output_dir}/service_banners.txt" ]]; then
    cat "${output_dir}/service_banners.txt"
else
    echo "No service banner data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Proxy Services</h2>
            <div class="results">
$(if [[ -f "${output_dir}/proxy_services.txt" ]]; then
    cat "${output_dir}/proxy_services.txt"
else
    echo "No proxy services data available."
fi)
            </div>
        </div>
        
        $(if [[ -f "${output_dir}/deep_port_scan.txt" ]]; then
        echo '<div class="section">
            <h2>Deep Port Scan Results</h2>
            <div class="results">
'"$(cat "${output_dir}/deep_port_scan.txt")"'
            </div>
        </div>'
        fi)
    </div>
</body>
</html>
EOF
    
    log_message "Port scan HTML report generated: ${html_report}" "SUCCESS"
}

# Main function for port scanning module
run_port_scanning_module() {
    show_port_scanning_banner
    
    # Check if a target is provided
    if [[ -z "${target}" ]]; then
        log_message "No target specified. Use -t or --target option." "ERROR"
        return 1
    fi
    
    # Create output directory for port scanning results
    local port_scan_dir="${target_dir}/port_scanning"
    mkdir -p "${port_scan_dir}"
    
    log_message "Starting Port Scanning module for ${target}" "INFO"
    
    # Run the port scanning functions in sequence
    run_quick_port_scan "${target}" "${port_scan_dir}"
    run_service_detection "${target}" "${port_scan_dir}"
    check_ssl_vulnerabilities "${target}" "${port_scan_dir}"
    scan_vulnerable_services "${target}" "${port_scan_dir}"
    scan_udp_services "${target}" "${port_scan_dir}"
    gather_service_banners "${target}" "${port_scan_dir}"
    check_proxy_services "${target}" "${port_scan_dir}"
    
    # If deep scan is enabled, run a more thorough scan
    if [[ "${deep_scan}" == true ]]; then
        deep_port_scan "${target}" "${port_scan_dir}"
    fi
    
    # Generate HTML report
    generate_port_scan_report "${target}" "${port_scan_dir}"
    
    log_message "Port Scanning module completed for ${target}" "SUCCESS"
    
    # Display summary of findings
    echo "--------------------------------------------------"
    echo "Port Scanning Summary for ${target}:"
    echo "--------------------------------------------------"
    if [[ -f "${port_scan_dir}/open_ports.txt" ]]; then
        echo "Open Ports:"
        cat "${port_scan_dir}/open_ports.txt"
    else
        echo "No open ports detected."
    fi
    echo "--------------------------------------------------"
    
    return 0
}