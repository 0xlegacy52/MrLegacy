#!/bin/bash
# Security Headers Module for MR Legacy Bug Bounty Tool
# Author: Abdulrahman Muhammad (0xLegacy)
# This module performs security header analysis

# Load the common functions
if [[ -f "./utils/common.sh" ]]; then
    source "./utils/common.sh"
else
    echo "Error: common.sh not found"
    exit 1
fi

# Security Headers Banner
show_security_headers_banner() {
    echo '
███████╗███████╗ ██████╗    ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗
██╔════╝██╔════╝██╔════╝    ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝
███████╗█████╗  ██║         ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗
╚════██║██╔══╝  ██║         ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║
███████║███████╗╚██████╗    ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║
╚══════╝╚══════╝ ╚═════╝    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝
====================================================================================
  Security Headers Analysis & Protection Mechanisms
===================================================================================='
}

# Function to check security headers for a target with enhanced capabilities
check_security_headers() {
    local target=$1
    local output_dir=$2
    local headers_output="${output_dir}/security_headers.txt"
    local headers_json="${output_dir}/security_headers.json"
    local headers_html="${output_dir}/security_headers_report.html"
    local missing_headers=()
    local total_score=0
    local max_score=100
    local grade=""
    
    log_message "Performing enhanced security headers analysis for ${target}" "INFO"
    
    # Initialize the headers output file
    echo "# Security Headers Analysis for ${target}" > "${headers_output}"
    echo "## Generated on: $(date)" >> "${headers_output}"
    echo "----------------------------------------" >> "${headers_output}"
    
    # Initialize JSON output
    echo "{" > "${headers_json}"
    echo "  \"target\": \"${target}\"," >> "${headers_json}"
    echo "  \"scan_date\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"," >> "${headers_json}"
    echo "  \"headers\": {" >> "${headers_json}"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    # Get the HTTP headers
    local headers=$(curl -s -I -L "${target}")
    echo "HTTP Headers:" >> "${headers_output}"
    echo "${headers}" >> "${headers_output}"
    echo "" >> "${headers_output}"
    
    # List of important security headers to check
    declare -A security_headers
    
    # Default header descriptions
    local default_descriptions=(
        ["Strict-Transport-Security"]="Helps prevent SSL/TLS downgrade attacks. Instructs browsers to only use HTTPS."
        ["Content-Security-Policy"]="Prevents XSS and data injection attacks by controlling which resources can be loaded."
        ["X-Content-Type-Options"]="Prevents MIME type sniffing which can lead to security vulnerabilities."
        ["X-Frame-Options"]="Provides clickjacking protection by not allowing the page to be embedded in a frame."
        ["X-XSS-Protection"]="Enables browser-level XSS filters to prevent reflected XSS attacks."
        ["Referrer-Policy"]="Controls how much referrer information should be included with requests."
        ["Permissions-Policy"]="Controls which browser features and APIs can be used in the browser."
        ["Feature-Policy"]="Legacy of Permissions-Policy, controls which browser features can be used."
        ["Cache-Control"]="Controls how pages are cached. Can prevent sensitive data from being cached."
        ["Clear-Site-Data"]="Clears browsing data (cookies, storage, cache) associated with the website."
    )
    
    # Load headers from wordlist if available
    local headers_wordlist="${script_path}/modules/wordlists/security_headers.txt"
    if [[ -f "${headers_wordlist}" ]]; then
        log_message "Using security headers wordlist from ${headers_wordlist}" "DEBUG"
        
        while IFS= read -r header || [[ -n "$header" ]]; do
            # Skip comments and empty lines
            [[ "${header}" =~ ^#.*$ || -z "${header}" ]] && continue
            
            # Get description from default or use a generic one
            local description="${default_descriptions[$header]}"
            if [[ -z "${description}" ]]; then
                description="Security header that enhances the security posture of the application."
            fi
            
            security_headers["${header}"]="${description}"
        done < "${headers_wordlist}"
    else
        log_message "Security headers wordlist not found. Using default headers list." "WARNING"
        
        # Use default headers if wordlist not available
        for header in "${!default_descriptions[@]}"; do
            security_headers["${header}"]="${default_descriptions[$header]}"
        done
    fi
    
    echo "Security Headers Analysis:" >> "${headers_output}"
    echo "----------------------------------------" >> "${headers_output}"
    
    local missing_headers=()
    local present_headers=()
    
    # Check each security header
    for header in "${!security_headers[@]}"; do
        local description="${security_headers[$header]}"
        
        if echo "${headers}" | grep -qi "^${header}:"; then
            # Header is present
            local value=$(echo "${headers}" | grep -i "^${header}:" | head -1 | sed "s/^${header}://i" | tr -d '\r' | xargs)
            echo "[+] ${header}: ${value}" >> "${headers_output}"
            echo "    Description: ${description}" >> "${headers_output}"
            echo "    Status: Present" >> "${headers_output}"
            
            # Analyze header value for common issues
            analyze_header_value "${header}" "${value}" "${headers_output}"
            
            present_headers+=("${header}")
        else
            # Header is missing
            echo "[-] ${header}: Not Present" >> "${headers_output}"
            echo "    Description: ${description}" >> "${headers_output}"
            echo "    Status: Missing" >> "${headers_output}"
            echo "    Recommendation: Implement this header for improved security" >> "${headers_output}"
            
            missing_headers+=("${header}")
        fi
        
        echo "" >> "${headers_output}"
    done
    
    # Generate summary
    echo "Security Headers Summary:" >> "${headers_output}"
    echo "----------------------------------------" >> "${headers_output}"
    echo "Total Headers Checked: ${#security_headers[@]}" >> "${headers_output}"
    echo "Present Headers: ${#present_headers[@]}" >> "${headers_output}"
    echo "Missing Headers: ${#missing_headers[@]}" >> "${headers_output}"
    
    # Calculate security score (simplified)
    local score=$(( 100 * ${#present_headers[@]} / ${#security_headers[@]} ))
    echo "Security Score: ${score}%" >> "${headers_output}"
    
    # Security rating based on score
    if [[ ${score} -ge 80 ]]; then
        echo "Security Rating: Good" >> "${headers_output}"
    elif [[ ${score} -ge 50 ]]; then
        echo "Security Rating: Moderate" >> "${headers_output}"
    else
        echo "Security Rating: Poor" >> "${headers_output}"
    fi
    
    log_message "Security headers check completed" "INFO"
}

# Analyze the value of a security header for common issues
analyze_header_value() {
    local header="$1"
    local value="$2"
    local output_file="$3"
    
    case "${header}" in
        "Strict-Transport-Security")
            # Check for max-age and includeSubDomains
            if [[ ! "${value}" =~ max-age= ]]; then
                echo "    Warning: No max-age directive found" >> "${output_file}"
            elif [[ "${value}" =~ max-age=([0-9]+) ]] && [[ ${BASH_REMATCH[1]} -lt 31536000 ]]; then
                echo "    Warning: max-age is less than 1 year (31536000 seconds). Value: ${BASH_REMATCH[1]}" >> "${output_file}"
            fi
            
            if [[ ! "${value}" =~ includeSubDomains ]]; then
                echo "    Recommendation: Consider adding 'includeSubDomains' directive" >> "${output_file}"
            fi
            
            if [[ ! "${value}" =~ preload ]]; then
                echo "    Recommendation: Consider adding 'preload' directive for extra security" >> "${output_file}"
            fi
            ;;
            
        "Content-Security-Policy")
            # Check for unsafe-inline, unsafe-eval, and default-src 'none'
            if [[ "${value}" =~ unsafe-inline ]]; then
                echo "    Warning: 'unsafe-inline' detected which can weaken XSS protection" >> "${output_file}"
            fi
            
            if [[ "${value}" =~ unsafe-eval ]]; then
                echo "    Warning: 'unsafe-eval' detected which can weaken XSS protection" >> "${output_file}"
            fi
            
            if [[ ! "${value}" =~ default-src ]]; then
                echo "    Recommendation: Add 'default-src' directive as a fallback" >> "${output_file}"
            fi
            
            # Check for proper frame-ancestors (clickjacking protection)
            if [[ ! "${value}" =~ frame-ancestors ]]; then
                echo "    Recommendation: Add 'frame-ancestors' directive to prevent clickjacking" >> "${output_file}"
            fi
            ;;
            
        "X-Content-Type-Options")
            # Should be 'nosniff'
            if [[ "${value}" != "nosniff" ]]; then
                echo "    Warning: Value should be 'nosniff'" >> "${output_file}"
            fi
            ;;
            
        "X-Frame-Options")
            # Should be DENY or SAMEORIGIN
            if [[ "${value}" != "DENY" && "${value}" != "SAMEORIGIN" ]]; then
                echo "    Warning: Value should be 'DENY' or 'SAMEORIGIN'" >> "${output_file}"
            fi
            ;;
            
        "X-XSS-Protection")
            # Should be 1; mode=block
            if [[ "${value}" != "1; mode=block" ]]; then
                echo "    Recommendation: Value should be '1; mode=block' for best protection" >> "${output_file}"
            fi
            ;;
            
        "Referrer-Policy")
            # Check for secure values
            if [[ "${value}" == "unsafe-url" || "${value}" == "no-referrer-when-downgrade" ]]; then
                echo "    Recommendation: Consider using a more secure value like 'same-origin', 'strict-origin' or 'no-referrer'" >> "${output_file}"
            fi
            ;;
            
        "Cache-Control")
            # Check for sensitive pages caching
            if [[ ! "${value}" =~ (private|no-store) ]]; then
                echo "    Recommendation: Consider adding 'private' and 'no-store' directives for sensitive pages" >> "${output_file}"
            fi
            ;;
    esac
}

# Function to check cookie security
check_cookie_security() {
    local target=$1
    local output_dir=$2
    local cookies_output="${output_dir}/cookie_security.txt"
    
    log_message "Checking cookie security for ${target}" "INFO"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    # Get cookies using curl
    local cookies=$(curl -s -i "${target}" | grep -i '^set-cookie:')
    
    echo "Cookie Security Check for ${target}" > "${cookies_output}"
    echo "----------------------------------------" >> "${cookies_output}"
    
    if [[ -z "${cookies}" ]]; then
        echo "No cookies found" >> "${cookies_output}"
    else
        echo "Cookies Found:" >> "${cookies_output}"
        echo "${cookies}" >> "${cookies_output}"
        echo "" >> "${cookies_output}"
        
        echo "Cookie Security Analysis:" >> "${cookies_output}"
        echo "----------------------------------------" >> "${cookies_output}"
        
        # Check each cookie for security flags
        echo "${cookies}" | while read -r cookie_line; do
            local cookie_name=$(echo "${cookie_line}" | sed -n 's/.*Set-Cookie: \([^=]*\)=.*/\1/ip')
            echo "Cookie: ${cookie_name}" >> "${cookies_output}"
            
            # Check for HttpOnly flag
            if echo "${cookie_line}" | grep -qi 'httponly'; then
                echo "  [+] HttpOnly: Yes" >> "${cookies_output}"
            else
                echo "  [-] HttpOnly: No (Recommendation: Add HttpOnly flag to prevent client-side script access)" >> "${cookies_output}"
            fi
            
            # Check for Secure flag
            if echo "${cookie_line}" | grep -qi 'secure'; then
                echo "  [+] Secure: Yes" >> "${cookies_output}"
            else
                echo "  [-] Secure: No (Recommendation: Add Secure flag to ensure cookie is only sent over HTTPS)" >> "${cookies_output}"
            fi
            
            # Check for SameSite attribute
            if echo "${cookie_line}" | grep -qi 'samesite'; then
                local samesite_value=$(echo "${cookie_line}" | grep -oi 'samesite=[^ ;]*' | cut -d'=' -f2)
                echo "  [+] SameSite: ${samesite_value}" >> "${cookies_output}"
                
                # Analyze SameSite value
                if [[ "${samesite_value,,}" == "none" ]]; then
                    echo "      Warning: SameSite=None allows cross-site requests" >> "${cookies_output}"
                fi
            else
                echo "  [-] SameSite: Not set (Recommendation: Add SameSite=Lax or SameSite=Strict to protect against CSRF)" >> "${cookies_output}"
            fi
            
            # Check for Expires/Max-Age
            if echo "${cookie_line}" | grep -qiE '(expires|max-age)'; then
                echo "  [+] Expiration: Set" >> "${cookies_output}"
            else
                echo "  [i] Expiration: Not set (This is a session cookie)" >> "${cookies_output}"
            fi
            
            echo "" >> "${cookies_output}"
        done
    fi
    
    log_message "Cookie security check completed" "INFO"
}

# Function to check TLS/SSL configuration
check_tls_configuration() {
    local target=$1
    local output_dir=$2
    local tls_output="${output_dir}/tls_configuration.txt"
    
    log_message "Checking TLS/SSL configuration for ${target}" "INFO"
    
    # Extract domain from target (remove protocol if present)
    local domain="${target#http://}"
    domain="${domain#https://}"
    domain="${domain%%/*}"
    
    echo "TLS/SSL Configuration Check for ${domain}" > "${tls_output}"
    echo "----------------------------------------" >> "${tls_output}"
    
    # Check if the domain has HTTPS enabled
    local https_response=$(curl -s -o /dev/null -w "%{http_code}" "https://${domain}" 2>/dev/null)
    
    if [[ "${https_response}" =~ ^[23] ]]; then
        echo "[+] HTTPS: Enabled (Status Code: ${https_response})" >> "${tls_output}"
    else
        echo "[-] HTTPS: Not properly configured or not enabled" >> "${tls_output}"
        echo "    Recommendation: Implement HTTPS for all web traffic" >> "${tls_output}"
    fi
    
    echo "" >> "${tls_output}"
    
    # Check TLS version support using openssl (if available)
    if command_exists "openssl"; then
        echo "TLS Version Support:" >> "${tls_output}"
        
        # Check TLS 1.0 (deprecated)
        if echo | openssl s_client -connect "${domain}:443" -tls1 2>/dev/null | grep -q "Secure Renegotiation IS supported"; then
            echo "[-] TLS 1.0: Supported (deprecated, should be disabled)" >> "${tls_output}"
        else
            echo "[+] TLS 1.0: Not supported (good)" >> "${tls_output}"
        fi
        
        # Check TLS 1.1 (deprecated)
        if echo | openssl s_client -connect "${domain}:443" -tls1_1 2>/dev/null | grep -q "Secure Renegotiation IS supported"; then
            echo "[-] TLS 1.1: Supported (deprecated, should be disabled)" >> "${tls_output}"
        else
            echo "[+] TLS 1.1: Not supported (good)" >> "${tls_output}"
        fi
        
        # Check TLS 1.2
        if echo | openssl s_client -connect "${domain}:443" -tls1_2 2>/dev/null | grep -q "Secure Renegotiation IS supported"; then
            echo "[+] TLS 1.2: Supported" >> "${tls_output}"
        else
            echo "[-] TLS 1.2: Not supported (should be enabled)" >> "${tls_output}"
        fi
        
        # Check TLS 1.3
        if echo | openssl s_client -connect "${domain}:443" -tls1_3 2>/dev/null | grep -q "Protocol.*TLSv1.3"; then
            echo "[+] TLS 1.3: Supported" >> "${tls_output}"
        else
            echo "[i] TLS 1.3: Not supported (recommended but not essential)" >> "${tls_output}"
        fi
        
        echo "" >> "${tls_output}"
        
        # Check certificate information
        echo "Certificate Information:" >> "${tls_output}"
        local cert_info=$(echo | openssl s_client -connect "${domain}:443" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
        
        # Certificate validity
        local cert_dates=$(echo "${cert_info}" | grep -E 'Not Before|Not After')
        echo "${cert_dates}" >> "${tls_output}"
        
        # Check if certificate is expired
        local not_after=$(echo "${cert_info}" | grep 'Not After' | sed 's/.*Not After : //')
        local not_after_seconds=$(date -d "${not_after}" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "${not_after}" +%s 2>/dev/null)
        local current_seconds=$(date +%s)
        
        if [[ ${not_after_seconds} -lt ${current_seconds} ]]; then
            echo "[-] Certificate Status: Expired" >> "${tls_output}"
        else
            echo "[+] Certificate Status: Valid" >> "${tls_output}"
            
            # Calculate days until expiration
            local days_left=$(( (not_after_seconds - current_seconds) / 86400 ))
            echo "    Days until expiration: ${days_left}" >> "${tls_output}"
            
            if [[ ${days_left} -lt 30 ]]; then
                echo "    Warning: Certificate will expire soon" >> "${tls_output}"
            fi
        fi
        
        # Check certificate issuer
        local issuer=$(echo "${cert_info}" | grep 'Issuer:' | head -1)
        echo "    ${issuer}" >> "${tls_output}"
        
        # Check subject alternative names
        local sans=$(echo "${cert_info}" | grep -A1 'Subject Alternative Name' | tail -1 | tr ',' '\n' | sed 's/^ */    /')
        echo "    Subject Alternative Names:" >> "${tls_output}"
        echo "${sans}" >> "${tls_output}"
    else
        echo "OpenSSL not found - cannot perform detailed TLS/SSL checks" >> "${tls_output}"
    fi
    
    log_message "TLS/SSL configuration check completed" "INFO"
}

# Function to check for proper implementation of CORS headers
check_cors_headers() {
    local target=$1
    local output_dir=$2
    local cors_output="${output_dir}/cors_headers.txt"
    
    log_message "Checking CORS headers for ${target}" "INFO"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    echo "CORS Headers Check for ${target}" > "${cors_output}"
    echo "----------------------------------------" >> "${cors_output}"
    
    # Perform a simple OPTIONS request to check CORS headers
    local cors_headers=$(curl -s -i -X OPTIONS "${target}" -H "Origin: https://example.com" -H "Access-Control-Request-Method: GET")
    
    # Extract relevant CORS headers
    local ac_allow_origin=$(echo "${cors_headers}" | grep -i "^Access-Control-Allow-Origin:" | head -1 | sed 's/^Access-Control-Allow-Origin://i' | tr -d '\r' | xargs)
    local ac_allow_methods=$(echo "${cors_headers}" | grep -i "^Access-Control-Allow-Methods:" | head -1 | sed 's/^Access-Control-Allow-Methods://i' | tr -d '\r' | xargs)
    local ac_allow_headers=$(echo "${cors_headers}" | grep -i "^Access-Control-Allow-Headers:" | head -1 | sed 's/^Access-Control-Allow-Headers://i' | tr -d '\r' | xargs)
    local ac_expose_headers=$(echo "${cors_headers}" | grep -i "^Access-Control-Expose-Headers:" | head -1 | sed 's/^Access-Control-Expose-Headers://i' | tr -d '\r' | xargs)
    local ac_max_age=$(echo "${cors_headers}" | grep -i "^Access-Control-Max-Age:" | head -1 | sed 's/^Access-Control-Max-Age://i' | tr -d '\r' | xargs)
    local ac_allow_credentials=$(echo "${cors_headers}" | grep -i "^Access-Control-Allow-Credentials:" | head -1 | sed 's/^Access-Control-Allow-Credentials://i' | tr -d '\r' | xargs)
    
    # Analyze Access-Control-Allow-Origin
    echo "Access-Control-Allow-Origin:" >> "${cors_output}"
    if [[ -z "${ac_allow_origin}" ]]; then
        echo "  Not present" >> "${cors_output}"
    elif [[ "${ac_allow_origin}" == "*" ]]; then
        echo "  [!] Set to wildcard (*) - allows any domain to access the resource" >> "${cors_output}"
        echo "      Recommendation: Restrict to specific domains if possible, especially if sensitive data is being accessed" >> "${cors_output}"
    else
        echo "  [+] ${ac_allow_origin}" >> "${cors_output}"
    fi
    
    # Analyze Access-Control-Allow-Methods
    echo "Access-Control-Allow-Methods:" >> "${cors_output}"
    if [[ -z "${ac_allow_methods}" ]]; then
        echo "  Not present" >> "${cors_output}"
    else
        echo "  ${ac_allow_methods}" >> "${cors_output}"
        
        # Check for sensitive methods
        if [[ "${ac_allow_methods}" =~ (PUT|DELETE|PATCH) ]]; then
            echo "  [!] Warning: Allows sensitive HTTP methods that could modify resources" >> "${cors_output}"
        fi
    fi
    
    # Analyze Access-Control-Allow-Credentials
    echo "Access-Control-Allow-Credentials:" >> "${cors_output}"
    if [[ -z "${ac_allow_credentials}" ]]; then
        echo "  Not present" >> "${cors_output}"
    elif [[ "${ac_allow_credentials}" == "true" && "${ac_allow_origin}" == "*" ]]; then
        echo "  [!!] Critical: Credentials allowed with wildcard origin" >> "${cors_output}"
        echo "      This is a security risk and most browsers will block this combination" >> "${cors_output}"
    elif [[ "${ac_allow_credentials}" == "true" ]]; then
        echo "  [!] Set to true - allows sending credentials (cookies, auth headers) in cross-origin requests" >> "${cors_output}"
        echo "      Ensure the Access-Control-Allow-Origin is restricted to trusted domains" >> "${cors_output}"
    else
        echo "  ${ac_allow_credentials}" >> "${cors_output}"
    fi
    
    # Other headers
    echo "Access-Control-Allow-Headers: ${ac_allow_headers:-Not present}" >> "${cors_output}"
    echo "Access-Control-Expose-Headers: ${ac_expose_headers:-Not present}" >> "${cors_output}"
    echo "Access-Control-Max-Age: ${ac_max_age:-Not present}" >> "${cors_output}"
    
    echo "" >> "${cors_output}"
    echo "CORS Policy Summary:" >> "${cors_output}"
    
    # Determine if CORS is implemented
    if [[ -z "${ac_allow_origin}" && -z "${ac_allow_methods}" && -z "${ac_allow_headers}" && -z "${ac_allow_credentials}" ]]; then
        echo "CORS is not implemented or not responding to preflight requests" >> "${cors_output}"
    else
        echo "CORS is implemented" >> "${cors_output}"
        
        # Security assessment
        if [[ "${ac_allow_origin}" == "*" && "${ac_allow_credentials}" == "true" ]]; then
            echo "Security Assessment: Critical vulnerability detected (wildcard origin with credentials)" >> "${cors_output}"
        elif [[ "${ac_allow_origin}" == "*" ]]; then
            echo "Security Assessment: Potential vulnerability detected (wildcard origin)" >> "${cors_output}"
        else
            echo "Security Assessment: CORS configuration appears to be securely configured" >> "${cors_output}"
        fi
    fi
    
    log_message "CORS headers check completed" "INFO"
}

# Function to check for implementation of CSP and its effectiveness
analyze_csp_effectiveness() {
    local target=$1
    local output_dir=$2
    local csp_output="${output_dir}/csp_analysis.txt"
    
    log_message "Analyzing Content Security Policy for ${target}" "INFO"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    echo "Content Security Policy Analysis for ${target}" > "${csp_output}"
    echo "----------------------------------------" >> "${csp_output}"
    
    # Get the HTTP headers
    local headers=$(curl -s -i "${target}")
    
    # Extract CSP header (either Content-Security-Policy or X-Content-Security-Policy)
    local csp=$(echo "${headers}" | grep -i "^Content-Security-Policy:" | head -1 | sed 's/^Content-Security-Policy://i' | tr -d '\r' | xargs)
    
    if [[ -z "${csp}" ]]; then
        csp=$(echo "${headers}" | grep -i "^X-Content-Security-Policy:" | head -1 | sed 's/^X-Content-Security-Policy://i' | tr -d '\r' | xargs)
    fi
    
    # Check meta tag CSP if header is not present
    if [[ -z "${csp}" ]]; then
        local meta_csp=$(curl -s "${target}" | grep -o '<meta.*http-equiv="Content-Security-Policy".*>')
        if [[ -n "${meta_csp}" ]]; then
            csp=$(echo "${meta_csp}" | grep -o 'content="[^"]*"' | sed 's/content="//;s/"$//')
            echo "CSP implemented via <meta> tag:" >> "${csp_output}"
        fi
    else
        echo "CSP implemented via HTTP header:" >> "${csp_output}"
    fi
    
    if [[ -z "${csp}" ]]; then
        echo "No Content Security Policy found" >> "${csp_output}"
        echo "Recommendation: Implement a strong CSP to prevent XSS and other code injection attacks" >> "${csp_output}"
    else
        echo "${csp}" >> "${csp_output}"
        echo "" >> "${csp_output}"
        
        echo "CSP Directive Analysis:" >> "${csp_output}"
        echo "----------------------------------------" >> "${csp_output}"
        
        # Split the CSP into directives
        IFS=';' read -ra directives <<< "${csp}"
        
        local has_default_src=false
        local has_unsafe_inline=false
        local has_unsafe_eval=false
        local has_wildcard=false
        local has_frame_ancestors=false
        local has_report_uri=false
        
        for directive in "${directives[@]}"; do
            # Trim whitespace
            directive=$(echo "${directive}" | xargs)
            
            # Extract directive name and value
            local name="${directive%%[[:space:]]*}"
            local value="${directive#*[[:space:]]}"
            
            echo "Directive: ${name}" >> "${csp_output}"
            echo "  Value: ${value}" >> "${csp_output}"
            
            # Analyze specific directives
            case "${name}" in
                "default-src")
                    has_default_src=true
                    if [[ "${value}" == "'none'" ]]; then
                        echo "  [+] Strong setting: 'none'" >> "${csp_output}"
                    elif [[ "${value}" == "*" || "${value}" == "'*'" ]]; then
                        echo "  [-] Weak setting: wildcard (*) allows any source" >> "${csp_output}"
                        has_wildcard=true
                    fi
                    ;;
                    
                "script-src")
                    if [[ "${value}" =~ "'unsafe-inline'" ]]; then
                        echo "  [-] Weakness: 'unsafe-inline' allows inline scripts which can lead to XSS" >> "${csp_output}"
                        has_unsafe_inline=true
                    fi
                    
                    if [[ "${value}" =~ "'unsafe-eval'" ]]; then
                        echo "  [-] Weakness: 'unsafe-eval' allows the use of eval() which can lead to XSS" >> "${csp_output}"
                        has_unsafe_eval=true
                    fi
                    
                    if [[ "${value}" == "*" || "${value}" == "'*'" ]]; then
                        echo "  [-] Weakness: wildcard (*) allows scripts from any source" >> "${csp_output}"
                        has_wildcard=true
                    fi
                    ;;
                    
                "object-src")
                    if [[ "${value}" == "'none'" ]]; then
                        echo "  [+] Good practice: 'none' prevents plugin abuse" >> "${csp_output}"
                    fi
                    ;;
                    
                "base-uri")
                    if [[ "${value}" == "'self'" || "${value}" == "'none'" ]]; then
                        echo "  [+] Good practice: restricts base URI" >> "${csp_output}"
                    fi
                    ;;
                    
                "frame-ancestors")
                    has_frame_ancestors=true
                    if [[ "${value}" == "'none'" ]]; then
                        echo "  [+] Strong setting: 'none' provides clickjacking protection" >> "${csp_output}"
                    elif [[ "${value}" == "'self'" ]]; then
                        echo "  [+] Good setting: 'self' restricts framing to same origin" >> "${csp_output}"
                    elif [[ "${value}" == "*" || "${value}" == "'*'" ]]; then
                        echo "  [-] Weak setting: wildcard (*) allows framing by any site" >> "${csp_output}"
                        has_wildcard=true
                    fi
                    ;;
                    
                "report-uri" | "report-to")
                    has_report_uri=true
                    echo "  [+] Good practice: CSP violations will be reported" >> "${csp_output}"
                    ;;
            esac
            
            echo "" >> "${csp_output}"
        done
        
        echo "CSP Security Assessment:" >> "${csp_output}"
        echo "----------------------------------------" >> "${csp_output}"
        
        # Check for missing important directives
        if [[ "${has_default_src}" == false ]]; then
            echo "[-] Missing 'default-src' directive - this is the fallback for other resource types" >> "${csp_output}"
        fi
        
        if [[ "${has_frame_ancestors}" == false ]]; then
            echo "[-] Missing 'frame-ancestors' directive - consider adding this for clickjacking protection" >> "${csp_output}"
        fi
        
        # Overall assessment
        if [[ "${has_unsafe_inline}" == true && "${has_unsafe_eval}" == true && "${has_wildcard}" == true ]]; then
            echo "Overall Assessment: Weak CSP implementation with multiple security bypasses" >> "${csp_output}"
        elif [[ "${has_unsafe_inline}" == true || "${has_unsafe_eval}" == true || "${has_wildcard}" == true ]]; then
            echo "Overall Assessment: Moderate CSP implementation with potential weaknesses" >> "${csp_output}"
        else
            echo "Overall Assessment: Strong CSP implementation" >> "${csp_output}"
        fi
        
        # Recommendations
        echo "" >> "${csp_output}"
        echo "Recommendations:" >> "${csp_output}"
        
        if [[ "${has_unsafe_inline}" == true ]]; then
            echo "- Remove 'unsafe-inline' and use nonces or hashes for inline scripts" >> "${csp_output}"
        fi
        
        if [[ "${has_unsafe_eval}" == true ]]; then
            echo "- Remove 'unsafe-eval' and refactor code to avoid eval()" >> "${csp_output}"
        fi
        
        if [[ "${has_wildcard}" == true ]]; then
            echo "- Replace wildcards (*) with specific domains" >> "${csp_output}"
        fi
        
        if [[ "${has_report_uri}" == false ]]; then
            echo "- Add 'report-uri' or 'report-to' to monitor CSP violations" >> "${csp_output}"
        fi
    fi
    
    log_message "Content Security Policy analysis completed" "INFO"
}

# Function to check for proper X-Frame-Options and clickjacking protection
check_clickjacking_protection() {
    local target=$1
    local output_dir=$2
    local xfo_output="${output_dir}/clickjacking_protection.txt"
    
    log_message "Checking clickjacking protection for ${target}" "INFO"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    echo "Clickjacking Protection Check for ${target}" > "${xfo_output}"
    echo "----------------------------------------" >> "${xfo_output}"
    
    # Get the HTTP headers
    local headers=$(curl -s -i "${target}")
    
    # Check X-Frame-Options header
    local xfo=$(echo "${headers}" | grep -i "^X-Frame-Options:" | head -1 | sed 's/^X-Frame-Options://i' | tr -d '\r' | xargs)
    
    echo "X-Frame-Options Header:" >> "${xfo_output}"
    if [[ -z "${xfo}" ]]; then
        echo "Not present" >> "${xfo_output}"
        echo "Recommendation: Implement X-Frame-Options header with value 'DENY' or 'SAMEORIGIN'" >> "${xfo_output}"
    else
        echo "${xfo}" >> "${xfo_output}"
        
        # Analyze X-Frame-Options value
        case "${xfo,,}" in
            "deny")
                echo "[+] Strong protection: DENY prevents any framing" >> "${xfo_output}"
                ;;
            "sameorigin")
                echo "[+] Good protection: SAMEORIGIN allows framing only by the same origin" >> "${xfo_output}"
                ;;
            "allow-from"*)
                echo "[!] Limited protection: ALLOW-FROM is deprecated and not supported by all browsers" >> "${xfo_output}"
                echo "    Recommendation: Use CSP's frame-ancestors directive instead" >> "${xfo_output}"
                ;;
            *)
                echo "[!] Unknown value: ${xfo}" >> "${xfo_output}"
                echo "    Recommendation: Use 'DENY' or 'SAMEORIGIN'" >> "${xfo_output}"
                ;;
        esac
    fi
    
    echo "" >> "${xfo_output}"
    
    # Check for CSP frame-ancestors directive (modern alternative to X-Frame-Options)
    local csp=$(echo "${headers}" | grep -i "^Content-Security-Policy:" | head -1 | sed 's/^Content-Security-Policy://i' | tr -d '\r' | xargs)
    
    echo "CSP frame-ancestors Directive:" >> "${xfo_output}"
    if [[ -z "${csp}" ]]; then
        echo "No CSP header found" >> "${xfo_output}"
    elif [[ "${csp}" =~ frame-ancestors[[:space:]]([^;]*) ]]; then
        local frame_ancestors="${BASH_REMATCH[1]}"
        echo "${frame_ancestors}" >> "${xfo_output}"
        
        # Analyze frame-ancestors value
        if [[ "${frame_ancestors}" == "'none'" ]]; then
            echo "[+] Strong protection: 'none' prevents any framing" >> "${xfo_output}"
        elif [[ "${frame_ancestors}" == "'self'" ]]; then
            echo "[+] Good protection: 'self' allows framing only by the same origin" >> "${xfo_output}"
        elif [[ "${frame_ancestors}" == "*" ]]; then
            echo "[-] No protection: wildcard (*) allows framing by any site" >> "${xfo_output}"
        else
            echo "[i] Custom setting: allows framing by specified domains" >> "${xfo_output}"
        fi
    else
        echo "CSP header present but no frame-ancestors directive found" >> "${xfo_output}"
        echo "Recommendation: Add the frame-ancestors directive to your CSP" >> "${xfo_output}"
    fi
    
    echo "" >> "${xfo_output}"
    
    # Overall assessment
    echo "Clickjacking Protection Assessment:" >> "${xfo_output}"
    if [[ -n "${xfo}" && "${xfo,,}" =~ ^(deny|sameorigin)$ ]] || [[ "${csp}" =~ frame-ancestors[[:space:]](\'none\'|\'self\') ]]; then
        echo "Good protection against clickjacking attacks" >> "${xfo_output}"
    else
        echo "Inadequate protection against clickjacking attacks" >> "${xfo_output}"
        echo "Recommendation: Implement either X-Frame-Options: DENY or CSP frame-ancestors: 'none'" >> "${xfo_output}"
    fi
    
    log_message "Clickjacking protection check completed" "INFO"
}

# Function to generate an HTML report for security headers results
generate_security_headers_report() {
    local target=$1
    local output_dir=$2
    local html_report="${output_dir}/security_headers_report.html"
    
    log_message "Generating security headers HTML report for ${target}" "INFO"
    
    # Create an HTML report
    cat > "${html_report}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Headers Report for ${target}</title>
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
        .good {
            color: #27ae60;
            font-weight: bold;
        }
        .warning {
            color: #e67e22;
            font-weight: bold;
        }
        .critical {
            color: #c0392b;
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
        <h1>Security Headers Report</h1>
        <p class="timestamp">Generated on $(date) for target: ${target}</p>
        
        <div class="summary section">
            <h2>Scan Summary</h2>
            <p>This report contains the analysis of security headers and protection mechanisms implemented on the target.</p>
            <table>
                <tr>
                    <th>Test Type</th>
                    <th>Status</th>
                </tr>
                <tr>
                    <td>Security Headers Check</td>
                    <td>$(if [[ -f "${output_dir}/security_headers.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Cookie Security Check</td>
                    <td>$(if [[ -f "${output_dir}/cookie_security.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>TLS/SSL Configuration Check</td>
                    <td>$(if [[ -f "${output_dir}/tls_configuration.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>CORS Headers Check</td>
                    <td>$(if [[ -f "${output_dir}/cors_headers.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>CSP Analysis</td>
                    <td>$(if [[ -f "${output_dir}/csp_analysis.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Clickjacking Protection Check</td>
                    <td>$(if [[ -f "${output_dir}/clickjacking_protection.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Security Headers Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/security_headers.txt" ]]; then
    cat "${output_dir}/security_headers.txt"
else
    echo "No security headers check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Cookie Security Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/cookie_security.txt" ]]; then
    cat "${output_dir}/cookie_security.txt"
else
    echo "No cookie security check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>TLS/SSL Configuration Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/tls_configuration.txt" ]]; then
    cat "${output_dir}/tls_configuration.txt"
else
    echo "No TLS/SSL configuration check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>CORS Headers Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/cors_headers.txt" ]]; then
    cat "${output_dir}/cors_headers.txt"
else
    echo "No CORS headers check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Content Security Policy Analysis</h2>
            <div class="results">
$(if [[ -f "${output_dir}/csp_analysis.txt" ]]; then
    cat "${output_dir}/csp_analysis.txt"
else
    echo "No CSP analysis data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Clickjacking Protection Check</h2>
            <div class="results">
$(if [[ -f "${output_dir}/clickjacking_protection.txt" ]]; then
    cat "${output_dir}/clickjacking_protection.txt"
else
    echo "No clickjacking protection check data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                <li>Implement HTTPS for all web traffic and properly configure TLS/SSL</li>
                <li>Set Strict-Transport-Security with a long max-age and includeSubDomains</li>
                <li>Implement a strong Content-Security-Policy without 'unsafe-inline' or 'unsafe-eval'</li>
                <li>Set X-Content-Type-Options to 'nosniff'</li>
                <li>Set X-Frame-Options to 'DENY' or use CSP's frame-ancestors directive</li>
                <li>Set X-XSS-Protection to '1; mode=block' for legacy browsers</li>
                <li>Implement a clear Referrer-Policy to control information leakage</li>
                <li>Set secure cookies with HttpOnly, Secure, and SameSite flags</li>
                <li>Carefully configure CORS headers to prevent unauthorized cross-origin access</li>
                <li>Regularly review and update security headers to reflect current best practices</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF
    
    log_message "Security headers HTML report generated: ${html_report}" "SUCCESS"
}

# Main function for security headers module
run_security_headers_module() {
    show_security_headers_banner
    
    # Check if a target is provided
    if [[ -z "${target}" ]]; then
        log_message "No target specified. Use -t or --target option." "ERROR"
        return 1
    fi
    
    # Create output directory for security headers results
    local security_headers_dir="${target_dir}/security_headers"
    mkdir -p "${security_headers_dir}"
    
    log_message "Starting Security Headers module for ${target}" "INFO"
    
    # Run the security headers functions in sequence
    check_security_headers "${target}" "${security_headers_dir}"
    check_cookie_security "${target}" "${security_headers_dir}"
    check_tls_configuration "${target}" "${security_headers_dir}"
    check_cors_headers "${target}" "${security_headers_dir}"
    analyze_csp_effectiveness "${target}" "${security_headers_dir}"
    check_clickjacking_protection "${target}" "${security_headers_dir}"
    
    # Generate HTML report
    generate_security_headers_report "${target}" "${security_headers_dir}"
    
    log_message "Security Headers module completed for ${target}" "SUCCESS"
    
    # Display summary
    echo "--------------------------------------------------"
    echo "Security Headers Check Summary for ${target}:"
    echo "--------------------------------------------------"
    echo "Checks performed:"
    echo "- Security Headers Check"
    echo "- Cookie Security Check"
    echo "- TLS/SSL Configuration Check"
    echo "- CORS Headers Check"
    echo "- Content Security Policy Analysis"
    echo "- Clickjacking Protection Check"
    echo "--------------------------------------------------"
    echo "HTML Report: ${security_headers_dir}/security_headers_report.html"
    echo "--------------------------------------------------"
    
    return 0
}