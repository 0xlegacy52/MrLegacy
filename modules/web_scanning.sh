#!/bin/bash
# Web Application Scanning Module for MR Legacy Bug Bounty Tool
# Author: Abdulrahman Muhammad (0xLegacy)
# This module performs comprehensive web application scanning and analysis

# Load the common functions
if [[ -f "./utils/common.sh" ]]; then
    source "./utils/common.sh"
else
    echo "Error: common.sh not found"
    exit 1
fi

# Web Application Scanning Banner
show_web_scanning_banner() {
    echo '
██╗    ██╗███████╗██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██║    ██║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║ █╗ ██║█████╗  ██████╔╝    ███████╗██║     ███████║██╔██╗ ██║
██║███╗██║██╔══╝  ██╔══██╗    ╚════██║██║     ██╔══██║██║╚██╗██║
╚███╔███╔╝███████╗██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚══╝╚══╝ ╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
================================================================================
  Web Application Security Scanning & Analysis
================================================================================'
}

# Function to scan for common web vulnerabilities with Nikto
run_nikto_scan() {
    local target=$1
    local output_dir=$2
    local nikto_output="${output_dir}/nikto_scan.txt"
    
    log_message "Starting Nikto web vulnerability scan on ${target}" "INFO"
    
    if command_exists "nikto"; then
        nikto -h ${target} -o "${nikto_output}" 2>/dev/null
        log_message "Nikto scan completed" "SUCCESS"
    else
        log_message "Nikto not found, skipping comprehensive web vulnerability scan" "WARNING"
        echo "Nikto is required for comprehensive web vulnerability scanning." > "${nikto_output}"
    fi
}

# Function to perform a basic XSS check
check_xss_vulnerabilities() {
    local target=$1
    local output_dir=$2
    local xss_output="${output_dir}/xss_check.txt"
    
    log_message "Checking for potential XSS vulnerabilities on ${target}" "INFO"
    
    # Basic XSS check using curl and grep
    echo "Basic XSS Vulnerability Check for ${target}" > "${xss_output}"
    echo "----------------------------------------" >> "${xss_output}"
    
    # Get all forms from the target
    local forms=$(curl -s "${target}" | grep -i "<form" || echo "")
    
    if [[ -n "${forms}" ]]; then
        echo "Forms found on the target that could potentially be vulnerable to XSS:" >> "${xss_output}"
        echo "${forms}" >> "${xss_output}"
        
        # Check for lack of proper encoding in responses
        local unsafe_outputs=$(curl -s "${target}" | grep -i "document.write" || echo "")
        if [[ -n "${unsafe_outputs}" ]]; then
            echo -e "\nPotentially unsafe JavaScript outputs found:" >> "${xss_output}"
            echo "${unsafe_outputs}" >> "${xss_output}"
        fi
    else
        echo "No forms found on the main page. Consider deeper scanning with specialized tools." >> "${xss_output}"
    fi
    
    log_message "Basic XSS check completed" "INFO"
}

# Function to check for SQL injection vulnerabilities
check_sqli_vulnerabilities() {
    local target=$1
    local output_dir=$2
    local sqli_output="${output_dir}/sqli_check.txt"
    
    log_message "Checking for potential SQL injection vulnerabilities on ${target}" "INFO"
    
    # Basic SQLi check using curl to find potential injection points
    echo "Basic SQL Injection Vulnerability Check for ${target}" > "${sqli_output}"
    echo "----------------------------------------" >> "${sqli_output}"
    
    # Get parameters from the URL and forms
    local urls=$(curl -s "${target}" | grep -o 'href="[^"]*' | sed 's/href="//' | grep "?" || echo "")
    
    if [[ -n "${urls}" ]]; then
        echo "URL parameters found that could potentially be vulnerable to SQL injection:" >> "${sqli_output}"
        echo "${urls}" >> "${sqli_output}"
        
        # Test a few basic SQLi payloads on each URL parameter
        echo -e "\nTesting basic SQLi payloads (non-invasive):" >> "${sqli_output}"
        for url in ${urls}; do
            if [[ "${url}" == *"="* ]]; then
                local base_url="${url%%\?*}"
                local params="${url#*\?}"
                IFS='&' read -ra param_array <<< "${params}"
                
                for param in "${param_array[@]}"; do
                    local param_name="${param%%=*}"
                    local test_url="${base_url}?${param_name}=%27"
                    echo "Testing: ${test_url}" >> "${sqli_output}"
                    
                    # Look for SQL error messages in the response
                    local response=$(curl -s "${test_url}" | grep -i "sql syntax\|mysql\|error\|syntax error" || echo "")
                    if [[ -n "${response}" ]]; then
                        echo "Possible SQL injection vulnerability found in parameter: ${param_name}" >> "${sqli_output}"
                        echo "Error response: ${response}" >> "${sqli_output}"
                    fi
                done
            fi
        done
    else
        echo "No URL parameters found on the main page. Consider deeper scanning with specialized tools." >> "${sqli_output}"
    fi
    
    log_message "Basic SQL injection check completed" "INFO"
}

# Function to check for CSRF vulnerabilities
check_csrf_vulnerabilities() {
    local target=$1
    local output_dir=$2
    local csrf_output="${output_dir}/csrf_check.txt"
    
    log_message "Checking for potential CSRF vulnerabilities on ${target}" "INFO"
    
    # Basic CSRF check
    echo "Basic CSRF Vulnerability Check for ${target}" > "${csrf_output}"
    echo "----------------------------------------" >> "${csrf_output}"
    
    # Get all forms from the target
    local forms=$(curl -s "${target}" | grep -i "<form" || echo "")
    
    if [[ -n "${forms}" ]]; then
        echo "Forms found on the target:" >> "${csrf_output}"
        echo "${forms}" >> "${csrf_output}"
        
        # Check for CSRF tokens in forms
        local csrf_tokens=$(curl -s "${target}" | grep -i -E 'csrf|token|nonce' || echo "")
        
        if [[ -n "${csrf_tokens}" ]]; then
            echo -e "\nPotential CSRF protection mechanisms found:" >> "${csrf_output}"
            echo "${csrf_tokens}" >> "${csrf_output}"
        else
            echo -e "\nWARNING: No CSRF tokens found in forms. The application might be vulnerable to CSRF attacks." >> "${csrf_output}"
        fi
    else
        echo "No forms found on the main page. Consider deeper scanning with specialized tools." >> "${csrf_output}"
    fi
    
    log_message "Basic CSRF check completed" "INFO"
}

# Function to check for file inclusion vulnerabilities
check_file_inclusion() {
    local target=$1
    local output_dir=$2
    local fi_output="${output_dir}/file_inclusion_check.txt"
    
    log_message "Checking for potential file inclusion vulnerabilities on ${target}" "INFO"
    
    # Basic file inclusion check
    echo "Basic File Inclusion Vulnerability Check for ${target}" > "${fi_output}"
    echo "----------------------------------------" >> "${fi_output}"
    
    # Look for parameters that might be vulnerable to file inclusion
    local urls=$(curl -s "${target}" | grep -o 'href="[^"]*' | sed 's/href="//' | grep -E "file=|path=|include=|require=|location=" || echo "")
    
    if [[ -n "${urls}" ]]; then
        echo "URL parameters found that could potentially be vulnerable to file inclusion:" >> "${fi_output}"
        echo "${urls}" >> "${fi_output}"
        
        # Test basic LFI payloads (non-invasive)
        echo -e "\nTesting basic LFI payloads (non-invasive):" >> "${fi_output}"
        for url in ${urls}; do
            if [[ "${url}" == *"="* ]]; then
                local param_name="${url##*=}"
                local base_url="${url%%=*}"
                local test_url="${base_url}=../../../etc/passwd"
                
                echo "Testing: ${test_url}" >> "${fi_output}"
                
                # Look for signs of successful file inclusion
                local response=$(curl -s "${test_url}" | grep -i "root:x:" || echo "")
                if [[ -n "${response}" ]]; then
                    echo "Possible LFI vulnerability found in parameter: ${param_name}" >> "${fi_output}"
                    echo "Response contains system file contents" >> "${fi_output}"
                fi
            fi
        done
    else
        echo "No suspicious file-related parameters found on the main page. Consider deeper scanning with specialized tools." >> "${fi_output}"
    fi
    
    log_message "Basic file inclusion check completed" "INFO"
}

# Function to check for sensitive information disclosure
check_information_disclosure() {
    local target=$1
    local output_dir=$2
    local info_output="${output_dir}/information_disclosure.txt"
    
    log_message "Checking for information disclosure on ${target}" "INFO"
    
    # Basic information disclosure check
    echo "Information Disclosure Check for ${target}" > "${info_output}"
    echo "----------------------------------------" >> "${info_output}"
    
    # Check for common sensitive files
    echo "Checking for sensitive files:" >> "${info_output}"
    local sensitive_files=(
        "/robots.txt"
        "/.git/HEAD"
        "/.env"
        "/backup"
        "/phpinfo.php"
        "/server-status"
        "/wp-config.php"
        "/config.php"
        "/.htaccess"
        "/.svn/"
        "/.DS_Store"
        "/credentials.txt"
    )
    
    for file in "${sensitive_files[@]}"; do
        local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${target}${file}")
        echo "Checking ${target}${file} - Status Code: ${response_code}" >> "${info_output}"
        
        if [[ "${response_code}" == "200" ]]; then
            echo "FOUND: ${target}${file} - This file might contain sensitive information" >> "${info_output}"
            # Get the first few lines of the file to check its content (but don't save full sensitive content)
            curl -s "${target}${file}" | head -n 5 >> "${info_output}"
            echo "[...content truncated for security...]" >> "${info_output}"
        fi
    done
    
    # Check for exposed version information
    echo -e "\nChecking for exposed version information:" >> "${info_output}"
    local response_headers=$(curl -s -I "${target}")
    echo "${response_headers}" | grep -i "server\|x-powered-by\|version" >> "${info_output}"
    
    # Check HTML comments for potential sensitive information
    echo -e "\nChecking HTML comments for potential sensitive information:" >> "${info_output}"
    curl -s "${target}" | grep -o '<!--.*-->' >> "${info_output}"
    
    log_message "Information disclosure check completed" "INFO"
}

# Function to check for server configuration issues
check_server_configuration() {
    local target=$1
    local output_dir=$2
    local config_output="${output_dir}/server_configuration.txt"
    
    log_message "Checking for server configuration issues on ${target}" "INFO"
    
    # Server configuration check
    echo "Server Configuration Check for ${target}" > "${config_output}"
    echo "----------------------------------------" >> "${config_output}"
    
    # Check HTTP headers
    echo "HTTP Headers Analysis:" >> "${config_output}"
    local headers=$(curl -s -I "${target}")
    echo "${headers}" >> "${config_output}"
    
    # Check for missing security headers
    echo -e "\nMissing Security Headers Check:" >> "${config_output}"
    local security_headers=(
        "Strict-Transport-Security"
        "Content-Security-Policy"
        "X-Content-Type-Options"
        "X-Frame-Options"
        "X-XSS-Protection"
        "Referrer-Policy"
        "Feature-Policy"
        "Permissions-Policy"
    )
    
    for header in "${security_headers[@]}"; do
        if ! echo "${headers}" | grep -q "${header}"; then
            echo "WARNING: Missing security header: ${header}" >> "${config_output}"
        fi
    done
    
    # Check for HTTPS support
    echo -e "\nHTTPS Support Check:" >> "${config_output}"
    if [[ "${target}" == http://* ]]; then
        local https_target="${target/http:/https:}"
        local https_code=$(curl -s -o /dev/null -w "%{http_code}" "${https_target}")
        
        if [[ "${https_code}" == "200" || "${https_code}" == "301" || "${https_code}" == "302" ]]; then
            echo "HTTPS is supported on ${https_target}" >> "${config_output}"
        else
            echo "WARNING: HTTPS might not be properly configured on ${target}" >> "${config_output}"
        fi
    else
        echo "Target is already using HTTPS: ${target}" >> "${config_output}"
    fi
    
    log_message "Server configuration check completed" "INFO"
}

# Function to run a directory brute force scan
run_directory_scan() {
    local target=$1
    local output_dir=$2
    local dirb_output="${output_dir}/directory_scan.txt"
    
    log_message "Starting directory brute force scan on ${target}" "INFO"
    
    if command_exists "dirb"; then
        dirb "${target}" -o "${dirb_output}" 2>/dev/null
        log_message "Directory brute force scan completed with dirb" "SUCCESS"
    elif command_exists "gobuster"; then
        gobuster dir -u "${target}" -w /usr/share/wordlists/dirb/common.txt -o "${dirb_output}" 2>/dev/null
        log_message "Directory brute force scan completed with gobuster" "SUCCESS"
    else
        log_message "No directory scanning tools found (dirb, gobuster). Trying basic approach." "WARNING"
        
        # Very basic directory enumeration as fallback
        echo "Basic Directory Enumeration for ${target}" > "${dirb_output}"
        echo "----------------------------------------" >> "${dirb_output}"
        
        local common_dirs=(
            "/admin"
            "/login"
            "/backup"
            "/config"
            "/dashboard"
            "/wp-admin"
            "/phpinfo.php"
            "/test"
            "/tmp"
            "/upload"
            "/uploads"
            "/images"
            "/img"
            "/css"
            "/js"
            "/api"
            "/v1"
            "/v2"
            "/docs"
            "/documentation"
        )
        
        for dir in "${common_dirs[@]}"; do
            local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${target}${dir}")
            if [[ "${response_code}" == "200" || "${response_code}" == "301" || "${response_code}" == "302" ]]; then
                echo "FOUND: ${target}${dir} (Status: ${response_code})" >> "${dirb_output}"
            fi
        done
        
        log_message "Basic directory enumeration completed" "INFO"
    fi
}

# Function to check for open redirects
check_open_redirects() {
    local target=$1
    local output_dir=$2
    local redirect_output="${output_dir}/open_redirects.txt"
    
    log_message "Checking for open redirect vulnerabilities on ${target}" "INFO"
    
    # Open redirect check
    echo "Open Redirect Vulnerability Check for ${target}" > "${redirect_output}"
    echo "----------------------------------------" >> "${redirect_output}"
    
    # Look for parameters that might be vulnerable to open redirects
    local urls=$(curl -s "${target}" | grep -o 'href="[^"]*' | sed 's/href="//' | grep -E "redirect=|url=|return=|next=|goto=|to=|link=|location=" || echo "")
    
    if [[ -n "${urls}" ]]; then
        echo "URL parameters found that could potentially be vulnerable to open redirects:" >> "${redirect_output}"
        echo "${urls}" >> "${redirect_output}"
        
        # Test a basic open redirect payload
        echo -e "\nTesting basic open redirect payloads (non-invasive):" >> "${redirect_output}"
        for url in ${urls}; do
            if [[ "${url}" == *"="* ]]; then
                local param_name="${url##*=}"
                local base_url="${url%%=*}"
                local test_url="${base_url}=https://example.com"
                
                echo "Testing: ${test_url}" >> "${redirect_output}"
                
                local redirect_headers=$(curl -s -I "${test_url}")
                if echo "${redirect_headers}" | grep -q 'example.com'; then
                    echo "Possible open redirect vulnerability found in parameter: ${param_name}" >> "${redirect_output}"
                    echo "${redirect_headers}" | grep -i "location" >> "${redirect_output}"
                fi
            fi
        done
    else
        echo "No redirect-related parameters found on the main page. Consider deeper scanning with specialized tools." >> "${redirect_output}"
    fi
    
    log_message "Open redirect check completed" "INFO"
}

# Function to generate an HTML report for web application scanning results
generate_web_scan_report() {
    local target=$1
    local output_dir=$2
    local html_report="${output_dir}/web_scan_report.html"
    
    log_message "Generating web application scan HTML report for ${target}" "INFO"
    
    # Create a comprehensive HTML report
    cat > "${html_report}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Application Security Scan Report for ${target}</title>
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
        .vulnerability {
            color: #c0392b;
            font-weight: bold;
        }
        .warning {
            color: #e67e22;
            font-weight: bold;
        }
        .secure {
            color: #27ae60;
            font-weight: bold;
        }
        .info {
            color: #3498db;
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
        <h1>Web Application Security Scan Report</h1>
        <p class="timestamp">Generated on $(date) for target: ${target}</p>
        
        <div class="summary section">
            <h2>Scan Summary</h2>
            <p>This report contains the results of various web application security tests performed on the target.</p>
            <table>
                <tr>
                    <th>Test Type</th>
                    <th>Status</th>
                </tr>
                <tr>
                    <td>Nikto Web Vulnerability Scan</td>
                    <td>$(if [[ -f "${output_dir}/nikto_scan.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>XSS Vulnerability Check</td>
                    <td>$(if [[ -f "${output_dir}/xss_check.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>SQL Injection Check</td>
                    <td>$(if [[ -f "${output_dir}/sqli_check.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>CSRF Vulnerability Check</td>
                    <td>$(if [[ -f "${output_dir}/csrf_check.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>File Inclusion Check</td>
                    <td>$(if [[ -f "${output_dir}/file_inclusion_check.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Information Disclosure Check</td>
                    <td>$(if [[ -f "${output_dir}/information_disclosure.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Server Configuration Check</td>
                    <td>$(if [[ -f "${output_dir}/server_configuration.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Directory Scan</td>
                    <td>$(if [[ -f "${output_dir}/directory_scan.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Open Redirect Check</td>
                    <td>$(if [[ -f "${output_dir}/open_redirects.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Nikto Web Vulnerability Scan</h2>
            <div class="results">
$(if [[ -f "${output_dir}/nikto_scan.txt" ]]; then
    cat "${output_dir}/nikto_scan.txt"
else
    echo "No Nikto scan data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>XSS Vulnerability Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/xss_check.txt" ]]; then
    cat "${output_dir}/xss_check.txt"
else
    echo "No XSS check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>SQL Injection Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/sqli_check.txt" ]]; then
    cat "${output_dir}/sqli_check.txt"
else
    echo "No SQL injection check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>CSRF Vulnerability Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/csrf_check.txt" ]]; then
    cat "${output_dir}/csrf_check.txt"
else
    echo "No CSRF check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>File Inclusion Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/file_inclusion_check.txt" ]]; then
    cat "${output_dir}/file_inclusion_check.txt"
else
    echo "No file inclusion check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Information Disclosure Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/information_disclosure.txt" ]]; then
    cat "${output_dir}/information_disclosure.txt"
else
    echo "No information disclosure check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Server Configuration Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/server_configuration.txt" ]]; then
    cat "${output_dir}/server_configuration.txt"
else
    echo "No server configuration check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Directory Scan</h2>
            <div class="results">
$(if [[ -f "${output_dir}/directory_scan.txt" ]]; then
    cat "${output_dir}/directory_scan.txt"
else
    echo "No directory scan data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Open Redirect Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/open_redirects.txt" ]]; then
    cat "${output_dir}/open_redirects.txt"
else
    echo "No open redirect check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                <li>Implement proper input validation for all user-supplied data</li>
                <li>Use appropriate output encoding to prevent XSS attacks</li>
                <li>Implement prepared statements for database queries to prevent SQL injection</li>
                <li>Use CSRF tokens for all forms and state-changing operations</li>
                <li>Apply security headers like Content-Security-Policy and X-Frame-Options</li>
                <li>Use HTTPS with proper certificate configuration</li>
                <li>Implement proper error handling to prevent information disclosure</li>
                <li>Regularly update all software and dependencies</li>
                <li>Implement proper access controls and authentication mechanisms</li>
                <li>Consider using a Web Application Firewall (WAF) for additional protection</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF
    
    log_message "Web application scan HTML report generated: ${html_report}" "SUCCESS"
}

# Main function for web application scanning module
run_web_scanning_module() {
    show_web_scanning_banner
    
    # Check if a target is provided
    if [[ -z "${target}" ]]; then
        log_message "No target specified. Use -t or --target option." "ERROR"
        return 1
    fi
    
    # Create output directory for web scanning results
    local web_scan_dir="${target_dir}/web_scanning"
    mkdir -p "${web_scan_dir}"
    
    log_message "Starting Web Application Scanning module for ${target}" "INFO"
    
    # Ensure the target has the protocol
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
        log_message "Added http:// prefix to target: ${target}" "INFO"
    fi
    
    # Run the web scanning functions in sequence
    run_nikto_scan "${target}" "${web_scan_dir}"
    check_xss_vulnerabilities "${target}" "${web_scan_dir}"
    check_sqli_vulnerabilities "${target}" "${web_scan_dir}"
    check_csrf_vulnerabilities "${target}" "${web_scan_dir}"
    check_file_inclusion "${target}" "${web_scan_dir}"
    check_information_disclosure "${target}" "${web_scan_dir}"
    check_server_configuration "${target}" "${web_scan_dir}"
    run_directory_scan "${target}" "${web_scan_dir}"
    check_open_redirects "${target}" "${web_scan_dir}"
    
    # Generate HTML report
    generate_web_scan_report "${target}" "${web_scan_dir}"
    
    log_message "Web Application Scanning module completed for ${target}" "SUCCESS"
    
    # Display summary
    echo "--------------------------------------------------"
    echo "Web Application Scanning Summary for ${target}:"
    echo "--------------------------------------------------"
    echo "Scans performed:"
    echo "- Nikto Web Vulnerability Scan"
    echo "- XSS Vulnerability Check"
    echo "- SQL Injection Check"
    echo "- CSRF Vulnerability Check"
    echo "- File Inclusion Check"
    echo "- Information Disclosure Check"
    echo "- Server Configuration Check"
    echo "- Directory Scan"
    echo "- Open Redirect Check"
    echo "--------------------------------------------------"
    echo "HTML Report: ${web_scan_dir}/web_scan_report.html"
    echo "--------------------------------------------------"
    
    return 0
}