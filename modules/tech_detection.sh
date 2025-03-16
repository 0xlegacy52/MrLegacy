#!/bin/bash
# MR Legacy - Technology Detection Module

# Function to run WhatWeb
run_whatweb() {
    local target="$1"
    local output_file="$2"
    
    if is_tool_installed "whatweb"; then
        log_message "Running WhatWeb on $target..." "INFO"
        
        whatweb -v "$target" > "$output_file.whatweb" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log_message "WhatWeb scan completed successfully" "SUCCESS"
            
            # Extract interesting information
            grep -E "Title|Server|X-|Cookie|Meta" "$output_file.whatweb" > "$output_file"
        else
            log_message "WhatWeb scan failed" "ERROR"
        fi
    else
        log_message "WhatWeb not found" "WARNING"
    fi
}

# Function to run Wappalyzer CLI
run_wappalyzer() {
    local target="$1"
    local output_file="$2"
    
    if is_tool_installed "wappalyzer"; then
        log_message "Running Wappalyzer on $target..." "INFO"
        
        wappalyzer "$target" > "$output_file.wappalyzer" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log_message "Wappalyzer scan completed successfully" "SUCCESS"
        else
            log_message "Wappalyzer scan failed" "ERROR"
        fi
    elif is_tool_installed "npx"; then
        log_message "Running Wappalyzer via npx on $target..." "INFO"
        
        npx wappalyzer "$target" > "$output_file.wappalyzer" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            log_message "Wappalyzer (npx) scan completed successfully" "SUCCESS"
        else
            log_message "Wappalyzer (npx) scan failed" "ERROR"
        fi
    else
        log_message "Wappalyzer not found" "WARNING"
    fi
}

# Function to check HTTP security headers
check_security_headers() {
    local target="$1"
    local output_file="$2"
    
    log_message "Checking security headers for $target..." "INFO"
    
    # List of important security headers
    local headers=(
        "Strict-Transport-Security"
        "Content-Security-Policy"
        "X-Content-Type-Options"
        "X-Frame-Options"
        "X-XSS-Protection"
        "Referrer-Policy"
        "Feature-Policy"
        "Permissions-Policy"
    )
    
    # Fetch headers
    curl -s -I "$target" > "$output_file.headers" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "Security Headers Analysis for $target" > "$output_file"
        echo "----------------------------------------" >> "$output_file"
        echo "" >> "$output_file"
        
        # Check for each security header
        for header in "${headers[@]}"; do
            if grep -i "^$header:" "$output_file.headers" > /dev/null; then
                value=$(grep -i "^$header:" "$output_file.headers" | sed 's/^[^:]*: //')
                echo "[+] $header: $value" >> "$output_file"
            else
                echo "[-] $header: Not present" >> "$output_file"
            fi
        done
        
        log_message "Security headers check completed" "SUCCESS"
    else
        log_message "Failed to fetch headers from $target" "ERROR"
    fi
}

# Function to detect JavaScript libraries and frameworks
detect_js_libraries() {
    local target="$1"
    local output_file="$2"
    
    log_message "Detecting JavaScript libraries for $target..." "INFO"
    
    # Fetch the HTML content
    curl -s "$target" > "$output_file.html" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "JavaScript Libraries Detection for $target" > "$output_file"
        echo "----------------------------------------" >> "$output_file"
        echo "" >> "$output_file"
        
        # Common JavaScript libraries and their detection patterns
        declare -A libraries=(
            ["jQuery"]="jquery"
            ["React"]="react"
            ["Angular"]="angular"
            ["Vue.js"]="vue"
            ["Bootstrap"]="bootstrap"
            ["Lodash"]="lodash"
            ["Moment.js"]="moment"
            ["D3.js"]="d3"
            ["Three.js"]="three"
            ["Axios"]="axios"
            ["Socket.io"]="socket.io"
        )
        
        # Check for each library
        for lib in "${!libraries[@]}"; do
            pattern="${libraries[$lib]}"
            if grep -i "$pattern" "$output_file.html" > /dev/null; then
                echo "[+] $lib detected" >> "$output_file"
            fi
        done
        
        log_message "JavaScript libraries detection completed" "SUCCESS"
    else
        log_message "Failed to fetch HTML content from $target" "ERROR"
    fi
}

# Function to create technology report
create_tech_report() {
    local output_dir="$1"
    local target="$2"
    local report_file="$3"
    
    log_message "Creating technology report..." "INFO"
    
    # Create HTML header
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MR Legacy - Technology Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1, h2 {
            color: #2c3e50;
        }
        h1 {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            margin-top: 30px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
        }
        .section {
            margin-bottom: 30px;
        }
        .header {
            color: #3498db;
            font-weight: bold;
        }
        .present {
            color: #27ae60;
        }
        .missing {
            color: #e74c3c;
        }
        pre {
            background-color: #f9f9f9;
            padding: 10px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #3498db;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            font-size: 0.8em;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>MR Legacy - Technology Report</h1>
        <div class="info">
            <p>Target: $target</p>
            <p>Date: $(date +"%Y-%m-%d %H:%M:%S")</p>
        </div>
EOF
    
    # Add WhatWeb results if available
    if [ -f "$output_dir/whatweb.txt" ]; then
        cat >> "$report_file" << EOF
        <div class="section">
            <h2>WhatWeb Results</h2>
            <pre>$(cat "$output_dir/whatweb.txt")</pre>
        </div>
EOF
    fi
    
    # Add Wappalyzer results if available
    if [ -f "$output_dir/wappalyzer.txt" ]; then
        cat >> "$report_file" << EOF
        <div class="section">
            <h2>Wappalyzer Results</h2>
            <pre>$(cat "$output_dir/wappalyzer.txt")</pre>
        </div>
EOF
    fi
    
    # Add security headers if available
    if [ -f "$output_dir/security_headers.txt" ]; then
        cat >> "$report_file" << EOF
        <div class="section">
            <h2>Security Headers</h2>
            <table>
                <thead>
                    <tr>
                        <th>Header</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
EOF
        
        # Parse security headers
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ $line =~ ^\[([\+\-])\]\ (.+):\ (.+)$ ]]; then
                status="${BASH_REMATCH[1]}"
                header="${BASH_REMATCH[2]}"
                value="${BASH_REMATCH[3]}"
                
                if [ "$status" = "+" ]; then
                    class="present"
                    status_text="Present"
                else
                    class="missing"
                    status_text="Missing"
                fi
                
                cat >> "$report_file" << EOF
                    <tr>
                        <td>$header</td>
                        <td class="$class">$value</td>
                    </tr>
EOF
            fi
        done < "$output_dir/security_headers.txt"
        
        cat >> "$report_file" << EOF
                </tbody>
            </table>
        </div>
EOF
    fi
    
    # Add JavaScript libraries if available
    if [ -f "$output_dir/js_libraries.txt" ]; then
        cat >> "$report_file" << EOF
        <div class="section">
            <h2>JavaScript Libraries</h2>
            <ul>
EOF
        
        # Parse JavaScript libraries
        grep "^\[\+\]" "$output_dir/js_libraries.txt" | while read -r line; do
            lib=$(echo "$line" | sed 's/\[\+\] //')
            echo "                <li>$lib</li>" >> "$report_file"
        done
        
        cat >> "$report_file" << EOF
            </ul>
        </div>
EOF
    fi
    
    # Add footer
    cat >> "$report_file" << EOF
        <div class="footer">
            <p>Generated by MR Legacy - Bug Bounty Hunting Tool</p>
            <p>Author: Abdulrahman Muhammad (0xLegacy)</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log_message "Technology report created at $report_file" "SUCCESS"
}

# Main function to run technology detection
run_tech_detection() {
    log_message "Starting technology detection on $target..." "INFO"
    
    # Setup Tor proxy if enabled
    setup_tor_proxy
    
    # Create output directory
    local output_dir="$target_dir/tech"
    mkdir -p "$output_dir"
    
    # Run technology detection tools
    run_whatweb "$target" "$output_dir/whatweb"
    run_wappalyzer "$target" "$output_dir/wappalyzer"
    check_security_headers "$target" "$output_dir/security_headers"
    detect_js_libraries "$target" "$output_dir/js_libraries"
    
    # Create technology report
    create_tech_report "$output_dir" "$target" "$output_dir/tech_report.html"
    
    # Save results in different formats
    for file in "$output_dir/whatweb.txt" "$output_dir/security_headers.txt" "$output_dir/js_libraries.txt"; do
        if [ -f "$file" ]; then
            file_base=$(basename "$file" .txt)
            save_results "$file" "$output_dir" "$file_base" "$output_format"
        fi
    done
    
    log_message "Technology detection completed" "SUCCESS"
    return 0
}
