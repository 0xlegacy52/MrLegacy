#!/bin/bash
# Error Handling Debug Information Module for MR Legacy Bug Bounty Tool
# Author: Abdulrahman Muhammad (0xLegacy)
# This module performs checks for improper error handling and debugging info leakage

# Load the common functions
if [[ -f "./utils/common.sh" ]]; then
    source "./utils/common.sh"
else
    echo "Error: common.sh not found"
    exit 1
fi

# Error Handling Banner
show_error_handling_banner() {
    echo '
███████╗██████╗ ██████╗  ██████╗ ██████╗     ██╗  ██╗███╗   ██╗██████╗ ██╗     
██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗    ██║  ██║████╗  ██║██╔══██╗██║     
█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝    ███████║██╔██╗ ██║██║  ██║██║     
██╔══╝  ██╔══██╗██╔══██╗██║   ██║██╔══██╗    ██╔══██║██║╚██╗██║██║  ██║██║     
███████╗██║  ██║██║  ██║╚██████╔╝██║  ██║    ██║  ██║██║ ╚████║██████╔╝███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝
================================================================================
  Error Handling & Debug Information Analysis
================================================================================'
}

# Function to check for verbose error messages
check_verbose_errors() {
    local target=$1
    local output_dir=$2
    local errors_output="${output_dir}/verbose_errors.txt"
    
    log_message "Checking for verbose error messages on ${target}" "INFO"
    
    # Basic error disclosure check
    echo "Verbose Error Messages Check for ${target}" > "${errors_output}"
    echo "----------------------------------------" >> "${errors_output}"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    # List of common error-triggering payloads
    local error_payloads=(
        "?id=1'"
        "?id=1\""
        "?id=1/0"
        "?page=../../../etc/passwd"
        "?file=non_existent_file.php"
        "/non-existent-page"
        "/%00"
        "/index.php~"
        "/.htaccess"
        "/?error=1"
        "/?debug=1"
        "/?test=1"
        "/config.php"
    )
    
    # Try payloads to trigger errors
    for payload in "${error_payloads[@]}"; do
        local test_url="${target}${payload}"
        log_message "Testing URL: ${test_url}" "DEBUG"
        
        echo "Testing URL: ${test_url}" >> "${errors_output}"
        
        local response=$(curl -s "${test_url}")
        
        # Look for common error patterns
        local error_found=false
        
        # PHP errors
        if echo "${response}" | grep -q -i -E "warning:|fatal error:|notice:|deprecated:|syntax error|stack trace|exception|on line [0-9]+"; then
            echo "  [!] PHP error detected" >> "${errors_output}"
            # Extract small portion of the error message for reporting
            local error_msg=$(echo "${response}" | grep -o -E "warning:.*|fatal error:.*|notice:.*|deprecated:.*|syntax error.*|exception.*|on line [0-9]+" | head -3)
            echo "  Error snippet: ${error_msg}" >> "${errors_output}"
            error_found=true
        fi
        
        # SQL errors
        if echo "${response}" | grep -q -i -E "sql syntax|mysql error|sql error|odbc|oledb|oracle error|syntax error"; then
            echo "  [!] SQL error detected" >> "${errors_output}"
            local error_msg=$(echo "${response}" | grep -o -E "sql syntax.*|mysql error.*|sql error.*|syntax error.*" | head -3)
            echo "  Error snippet: ${error_msg}" >> "${errors_output}"
            error_found=true
        fi
        
        # Framework errors
        if echo "${response}" | grep -q -i -E "application error|server error|framework error|rails application|django|laravel|symfony|zend"; then
            echo "  [!] Framework error detected" >> "${errors_output}"
            local error_msg=$(echo "${response}" | grep -o -E "application error.*|server error.*|framework error.*" | head -3)
            echo "  Error snippet: ${error_msg}" >> "${errors_output}"
            error_found=true
        fi
        
        # .NET/IIS errors
        if echo "${response}" | grep -q -i -E "server error in|aspx error|\.net error|microsoft|iis|aspnet|runtime error"; then
            echo "  [!] .NET/IIS error detected" >> "${errors_output}"
            local error_msg=$(echo "${response}" | grep -o -E "server error in.*|aspx error.*|\.net error.*|runtime error.*" | head -3)
            echo "  Error snippet: ${error_msg}" >> "${errors_output}"
            error_found=true
        fi
        
        # Java errors
        if echo "${response}" | grep -q -i -E "java\.(lang|io|sql)\.|\bspring\b|jakarta|tomcat|glassfish|jboss"; then
            echo "  [!] Java error detected" >> "${errors_output}"
            local error_msg=$(echo "${response}" | grep -o -E "java\.(lang|io|sql)\..*|spring.*|jakarta.*|tomcat.*" | head -3)
            echo "  Error snippet: ${error_msg}" >> "${errors_output}"
            error_found=true
        fi
        
        # System path disclosure
        if echo "${response}" | grep -q -i -E "/home/|/var/www/|/usr/local/|c:\\\\|d:\\\\|e:\\\\|/opt/|/etc/"; then
            echo "  [!] System path disclosure detected" >> "${errors_output}"
            local error_msg=$(echo "${response}" | grep -o -E "/home/.*|/var/www/.*|/usr/local/.*|c:\\\\.*|d:\\\\.*|e:\\\\.*|/opt/.*|/etc/.*" | head -3)
            echo "  Path snippet: ${error_msg}" >> "${errors_output}"
            error_found=true
        fi
        
        if [ "$error_found" = false ]; then
            echo "  No common errors detected for this payload" >> "${errors_output}"
        fi
        
        echo "" >> "${errors_output}"
    done
    
    log_message "Verbose error messages check completed" "INFO"
}

# Function to check for debug endpoints
check_debug_endpoints() {
    local target=$1
    local output_dir=$2
    local debug_output="${output_dir}/debug_endpoints.txt"
    
    log_message "Checking for debug endpoints on ${target}" "INFO"
    
    # Debug endpoints check
    echo "Debug Endpoints Check for ${target}" > "${debug_output}"
    echo "----------------------------------------" >> "${debug_output}"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    # List of common debug endpoints
    local debug_endpoints=(
        "/debug"
        "/debug/vars"
        "/debug/pprof"
        "/debug.php"
        "/debug.jsp"
        "/debug.aspx"
        "/phpinfo.php"
        "/info.php"
        "/server-info"
        "/server-status"
        "/status"
        "/stats"
        "/admin/metrics"
        "/metrics"
        "/probe"
        "/health"
        "/actuator"
        "/actuator/health"
        "/actuator/info"
        "/actuator/env"
        "/actuator/trace"
        "/actuator/mappings"
        "/.env"
        "/config"
        "/configuration"
        "/console"
        "/admin/console"
        "/api/debug"
        "/dev"
        "/test"
        "/dev.php"
        "/test.php"
        "/tmp"
    )
    
    # Check each debug endpoint
    for endpoint in "${debug_endpoints[@]}"; do
        local test_url="${target}${endpoint}"
        local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${test_url}")
        
        echo "Checking ${test_url} - Status Code: ${response_code}" >> "${debug_output}"
        
        if [[ "${response_code}" == "200" || "${response_code}" == "302" || "${response_code}" == "401" ]]; then
            echo "  [!] Potentially accessible debug endpoint detected: ${endpoint}" >> "${debug_output}"
            
            # If it's a 200, check the content for sensitive information patterns
            if [[ "${response_code}" == "200" ]]; then
                local response=$(curl -s "${test_url}")
                
                if echo "${response}" | grep -q -i -E "password|credential|token|secret|api key|configuration|database|connection string|admin|root"; then
                    echo "  [!!] CRITICAL: Response may contain sensitive information" >> "${debug_output}"
                fi
                
                # Save the first few lines to give context without capturing too much sensitive data
                echo "  Content preview:" >> "${debug_output}"
                echo "${response}" | head -10 | sed 's/^/    /' >> "${debug_output}"
                echo "    [content truncated for security]" >> "${debug_output}"
            fi
        fi
        
        echo "" >> "${debug_output}"
    done
    
    log_message "Debug endpoints check completed" "INFO"
}

# Function to check for source code disclosure
check_source_code_disclosure() {
    local target=$1
    local output_dir=$2
    local source_output="${output_dir}/source_code_disclosure.txt"
    
    log_message "Checking for source code disclosure on ${target}" "INFO"
    
    # Source code disclosure check
    echo "Source Code Disclosure Check for ${target}" > "${source_output}"
    echo "----------------------------------------" >> "${source_output}"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    # List of extensions to check for source code disclosure
    local extensions=(
        ".php" ".php~" ".php.bak" ".php.old" ".php.swp" ".phps"
        ".asp" ".asp~" ".asp.bak" ".asp.old"
        ".aspx" ".aspx~" ".aspx.bak" ".aspx.old"
        ".jsp" ".jsp~" ".jsp.bak" ".jsp.old"
        ".rb" ".rb~" ".rb.bak" ".rb.old"
        ".py" ".py~" ".py.bak" ".py.old"
        ".java" ".java~" ".java.bak" ".class"
        ".config" ".config.bak" ".conf"
        ".inc"
    )
    
    # Try to discover files with different extensions
    for ext in "${extensions[@]}"; do
        # Try some common file paths
        for base in "index" "main" "default" "home" "admin" "login" "user" "api" "config"; do
            local test_url="${target}/${base}${ext}"
            local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${test_url}")
            
            if [[ "${response_code}" == "200" ]]; then
                echo "Checking ${test_url} - Status Code: ${response_code}" >> "${source_output}"
                
                # Get the response and check if it looks like source code
                local response=$(curl -s "${test_url}")
                
                if echo "${response}" | grep -q -i -E "^<\?(php)?|^import|^function|^class|^def|^public|^private|^protected|^\s*\/\/|#include|package|using namespace"; then
                    echo "  [!] Potential source code disclosure detected" >> "${source_output}"
                    echo "  Content preview:" >> "${source_output}"
                    echo "${response}" | head -10 | sed 's/^/    /' >> "${source_output}"
                    echo "    [content truncated for security]" >> "${source_output}"
                fi
                
                echo "" >> "${source_output}"
            fi
        done
    done
    
    # Also check for common version control directories
    local vcs_paths=(
        "/.git/"
        "/.svn/"
        "/.hg/"
        "/.bzr/"
        "/CVS/"
    )
    
    for vcs in "${vcs_paths[@]}"; do
        local test_url="${target}${vcs}"
        local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${test_url}")
        
        echo "Checking ${test_url} - Status Code: ${response_code}" >> "${source_output}"
        
        if [[ "${response_code}" == "200" || "${response_code}" == "403" ]]; then
            echo "  [!] Potential version control directory found: ${vcs}" >> "${source_output}"
            
            # Try to access some specific files within the VCS directory
            if [[ "${vcs}" == "/.git/" ]]; then
                local git_files=("HEAD" "config" "index" "COMMIT_EDITMSG")
                for file in "${git_files[@]}"; do
                    local git_file_url="${target}/.git/${file}"
                    local git_response_code=$(curl -s -o /dev/null -w "%{http_code}" "${git_file_url}")
                    
                    if [[ "${git_response_code}" == "200" ]]; then
                        echo "    Found accessible Git file: ${file} (Status: ${git_response_code})" >> "${source_output}"
                    fi
                done
            fi
        fi
        
        echo "" >> "${source_output}"
    done
    
    log_message "Source code disclosure check completed" "INFO"
}

# Function to check for debugging parameters
check_debug_parameters() {
    local target=$1
    local output_dir=$2
    local debug_params_output="${output_dir}/debug_parameters.txt"
    
    log_message "Checking for debugging parameters on ${target}" "INFO"
    
    # Debug parameters check
    echo "Debug Parameters Check for ${target}" > "${debug_params_output}"
    echo "----------------------------------------" >> "${debug_params_output}"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    # List of common debug parameters
    local debug_params=(
        "debug=true" "debug=1" "debug=on" "debug=yes"
        "test=true" "test=1" "test=on" "test=yes"
        "dev=true" "dev=1" "dev=on" "dev=yes"
        "development=true" "development=1"
        "show_errors=true" "show_errors=1"
        "display_errors=true" "display_errors=1"
        "verbose=true" "verbose=1"
        "trace=true" "trace=1"
        "log=true" "log=1"
        "env=development" "env=dev" "env=test"
    )
    
    # Try each debug parameter
    for param in "${debug_params[@]}"; do
        local test_url="${target}/?${param}"
        
        echo "Testing URL: ${test_url}" >> "${debug_params_output}"
        
        local normal_response=$(curl -s "${target}")
        local debug_response=$(curl -s "${test_url}")
        
        # Compare the two responses to see if they're different
        if [[ "${normal_response}" != "${debug_response}" ]]; then
            echo "  [!] Response changed with parameter: ${param}" >> "${debug_params_output}"
            
            # Check if the debug response contains potential debug information
            if echo "${debug_response}" | grep -q -i -E "debug|error|warning|notice|stack trace|exception|verbose|trace|log"; then
                echo "  [!!] Debug information likely exposed" >> "${debug_params_output}"
                
                # Extract some debug-related lines for context
                echo "  Debug information snippets:" >> "${debug_params_output}"
                echo "${debug_response}" | grep -i -E "debug|error|warning|notice|stack trace|exception|verbose|trace|log" | head -5 | sed 's/^/    /' >> "${debug_params_output}"
                echo "    [content truncated for security]" >> "${debug_params_output}"
            fi
        else
            echo "  No visible change in response with this parameter" >> "${debug_params_output}"
        fi
        
        echo "" >> "${debug_params_output}"
    done
    
    log_message "Debug parameters check completed" "INFO"
}

# Function to check for error-based information disclosure
check_error_based_info() {
    local target=$1
    local output_dir=$2
    local error_info_output="${output_dir}/error_based_info.txt"
    
    log_message "Checking for error-based information disclosure on ${target}" "INFO"
    
    # Error-based information disclosure check
    echo "Error-based Information Disclosure Check for ${target}" > "${error_info_output}"
    echo "----------------------------------------" >> "${error_info_output}"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    # List of special error-triggering payloads
    local info_payloads=(
        "?id=1'%20OR%201=1%20--%20"
        "?id=1)%20OR%201=1%20--%20"
        "?id=1%20UNION%20SELECT%201,2,3%20--%20"
        "?file=/etc/passwd"
        "?file=../../../../../../../etc/passwd"
        "?page=php://filter/convert.base64-encode/resource=index"
    )
    
    # Try each info disclosure payload
    for payload in "${info_payloads[@]}"; do
        local test_url="${target}${payload}"
        
        echo "Testing URL: ${test_url}" >> "${error_info_output}"
        
        local response=$(curl -s "${test_url}")
        
        # Check for various types of information disclosure
        local info_found=false
        
        # System information disclosure
        if echo "${response}" | grep -q -i -E "system32|windows|linux|ubuntu|centos|debian|fedora"; then
            echo "  [!] Operating system information disclosed" >> "${error_info_output}"
            local info=$(echo "${response}" | grep -o -E "system32.*|windows.*|linux.*|ubuntu.*|centos.*|debian.*|fedora.*" | head -3)
            echo "  OS info: ${info}" >> "${error_info_output}"
            info_found=true
        fi
        
        # Database information disclosure
        if echo "${response}" | grep -q -i -E "mysql|postgresql|sqlserver|oracle|database|mariadb|mysqli"; then
            echo "  [!] Database information disclosed" >> "${error_info_output}"
            local info=$(echo "${response}" | grep -o -E "mysql.*|postgresql.*|sqlserver.*|oracle.*|database.*|mariadb.*|mysqli.*" | head -3)
            echo "  DB info: ${info}" >> "${error_info_output}"
            info_found=true
        fi
        
        # Server information disclosure
        if echo "${response}" | grep -q -i -E "apache|nginx|iis|tomcat|weblogic|websphere|jboss"; then
            echo "  [!] Web server information disclosed" >> "${error_info_output}"
            local info=$(echo "${response}" | grep -o -E "apache.*|nginx.*|iis.*|tomcat.*|weblogic.*|websphere.*|jboss.*" | head -3)
            echo "  Server info: ${info}" >> "${error_info_output}"
            info_found=true
        fi
        
        # Framework information disclosure
        if echo "${response}" | grep -q -i -E "php|laravel|symfony|django|rails|asp.net|spring|node.js|express"; then
            echo "  [!] Framework information disclosed" >> "${error_info_output}"
            local info=$(echo "${response}" | grep -o -E "php.*|laravel.*|symfony.*|django.*|rails.*|asp.net.*|spring.*|node.js.*|express.*" | head -3)
            echo "  Framework info: ${info}" >> "${error_info_output}"
            info_found=true
        fi
        
        # IP address disclosure
        if echo "${response}" | grep -q -E "([0-9]{1,3}\.){3}[0-9]{1,3}"; then
            echo "  [!] IP address disclosed" >> "${error_info_output}"
            local info=$(echo "${response}" | grep -o -E "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -3)
            echo "  IP addresses: ${info}" >> "${error_info_output}"
            info_found=true
        fi
        
        # Email address disclosure
        if echo "${response}" | grep -q -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"; then
            echo "  [!] Email address disclosed" >> "${error_info_output}"
            local info=$(echo "${response}" | grep -o -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | head -3)
            echo "  Email addresses: ${info}" >> "${error_info_output}"
            info_found=true
        fi
        
        if [ "$info_found" = false ]; then
            echo "  No information disclosure detected for this payload" >> "${error_info_output}"
        fi
        
        echo "" >> "${error_info_output}"
    done
    
    log_message "Error-based information disclosure check completed" "INFO"
}

# Function to generate an HTML report for error handling scan results
generate_error_handling_report() {
    local target=$1
    local output_dir=$2
    local html_report="${output_dir}/error_handling_report.html"
    
    log_message "Generating error handling HTML report for ${target}" "INFO"
    
    # Create an HTML report
    cat > "${html_report}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error Handling & Debug Information Report for ${target}</title>
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
        .critical {
            color: #c0392b;
            font-weight: bold;
        }
        .warning {
            color: #e67e22;
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
        <h1>Error Handling & Debug Information Report</h1>
        <p class="timestamp">Generated on $(date) for target: ${target}</p>
        
        <div class="summary section">
            <h2>Scan Summary</h2>
            <p>This report contains the results of error handling and debug information checks performed on the target.</p>
            <table>
                <tr>
                    <th>Test Type</th>
                    <th>Status</th>
                </tr>
                <tr>
                    <td>Verbose Error Messages Check</td>
                    <td>$(if [[ -f "${output_dir}/verbose_errors.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Debug Endpoints Check</td>
                    <td>$(if [[ -f "${output_dir}/debug_endpoints.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Source Code Disclosure Check</td>
                    <td>$(if [[ -f "${output_dir}/source_code_disclosure.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Debug Parameters Check</td>
                    <td>$(if [[ -f "${output_dir}/debug_parameters.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Error-based Information Disclosure Check</td>
                    <td>$(if [[ -f "${output_dir}/error_based_info.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Verbose Error Messages Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/verbose_errors.txt" ]]; then
    cat "${output_dir}/verbose_errors.txt"
else
    echo "No verbose error messages check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Debug Endpoints Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/debug_endpoints.txt" ]]; then
    cat "${output_dir}/debug_endpoints.txt"
else
    echo "No debug endpoints check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Source Code Disclosure Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/source_code_disclosure.txt" ]]; then
    cat "${output_dir}/source_code_disclosure.txt"
else
    echo "No source code disclosure check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Debug Parameters Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/debug_parameters.txt" ]]; then
    cat "${output_dir}/debug_parameters.txt"
else
    echo "No debug parameters check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Error-based Information Disclosure Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/error_based_info.txt" ]]; then
    cat "${output_dir}/error_based_info.txt"
else
    echo "No error-based information disclosure check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                <li>Implement centralized error handling with custom error pages</li>
                <li>Avoid displaying technical error messages to users</li>
                <li>Log errors server-side for debugging, not client-side</li>
                <li>Remove or disable debug endpoints in production</li>
                <li>Disable development/debug modes in production environments</li>
                <li>Use debug parameters that require authentication</li>
                <li>Ensure source code is not accessible directly</li>
                <li>Configure web server to hide version information</li>
                <li>Implement proper error handling for all user inputs</li>
                <li>Apply secure coding practices to prevent information leakage</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF
    
    log_message "Error handling HTML report generated: ${html_report}" "SUCCESS"
}

# Main function for error handling module
run_error_handling_module() {
    show_error_handling_banner
    
    # Check if a target is provided
    if [[ -z "${target}" ]]; then
        log_message "No target specified. Use -t or --target option." "ERROR"
        return 1
    fi
    
    # Create output directory for error handling results
    local error_handling_dir="${target_dir}/error_handling"
    mkdir -p "${error_handling_dir}"
    
    log_message "Starting Error Handling module for ${target}" "INFO"
    
    # Run the error handling functions in sequence
    check_verbose_errors "${target}" "${error_handling_dir}"
    check_debug_endpoints "${target}" "${error_handling_dir}"
    check_source_code_disclosure "${target}" "${error_handling_dir}"
    check_debug_parameters "${target}" "${error_handling_dir}"
    check_error_based_info "${target}" "${error_handling_dir}"
    
    # Generate HTML report
    generate_error_handling_report "${target}" "${error_handling_dir}"
    
    log_message "Error Handling module completed for ${target}" "SUCCESS"
    
    # Display summary
    echo "--------------------------------------------------"
    echo "Error Handling Check Summary for ${target}:"
    echo "--------------------------------------------------"
    echo "Checks performed:"
    echo "- Verbose Error Messages Check"
    echo "- Debug Endpoints Check"
    echo "- Source Code Disclosure Check"
    echo "- Debug Parameters Check"
    echo "- Error-based Information Disclosure Check"
    echo "--------------------------------------------------"
    echo "HTML Report: ${error_handling_dir}/error_handling_report.html"
    echo "--------------------------------------------------"
    
    return 0
}