#!/bin/bash
# Authentication Testing Module for MR Legacy Bug Bounty Tool
# Author: Abdulrahman Muhammad (0xLegacy)
# This module performs comprehensive authentication vulnerability testing

# Load the common functions
if [[ -f "./utils/common.sh" ]]; then
    source "./utils/common.sh"
else
    echo "Error: common.sh not found"
    exit 1
fi

# Authentication Testing Banner
show_auth_testing_banner() {
    echo '
 █████╗ ██╗   ██╗████████╗██╗  ██╗    ████████╗███████╗███████╗████████╗
██╔══██╗██║   ██║╚══██╔══╝██║  ██║    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
███████║██║   ██║   ██║   ███████║       ██║   █████╗  ███████╗   ██║   
██╔══██║██║   ██║   ██║   ██╔══██║       ██║   ██╔══╝  ╚════██║   ██║   
██║  ██║╚██████╔╝   ██║   ██║  ██║       ██║   ███████╗███████║   ██║   
╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   
================================================================================
  Authentication Vulnerability Assessment
================================================================================'
}

# Function to test for username enumeration
test_username_enumeration() {
    local target=$1
    local output_dir=$2
    local username_enum_output="${output_dir}/username_enumeration.txt"
    
    log_message "Testing for username enumeration on ${target}" "INFO"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    echo "Username Enumeration Test for ${target}" > "${username_enum_output}"
    echo "----------------------------------------" >> "${username_enum_output}"
    
    # Step 1: Find common login endpoints
    local login_endpoints=(
        "/login"
        "/signin"
        "/auth"
        "/user/login"
        "/account/login"
        "/admin"
        "/admin/login"
        "/wp-login.php"
        "/portal"
        "/user"
    )
    
    log_message "Searching for login endpoints" "INFO"
    echo "Detected Login Endpoints:" >> "${username_enum_output}"
    
    local found_login_pages=()
    for endpoint in "${login_endpoints[@]}"; do
        local url="${target}${endpoint}"
        local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${url}")
        
        if [[ "${response_code}" == "200" || "${response_code}" == "302" ]]; then
            echo "  [+] ${url} (Status: ${response_code})" >> "${username_enum_output}"
            found_login_pages+=("${url}")
        fi
    done
    
    if [[ ${#found_login_pages[@]} -eq 0 ]]; then
        log_message "No common login pages found" "WARNING"
        echo "  [-] No common login pages found. Consider manual exploration." >> "${username_enum_output}"
    else
        log_message "Found ${#found_login_pages[@]} potential login endpoints" "INFO"
    fi
    
    echo "" >> "${username_enum_output}"
    
    # Step 2: Test for differences in error messages and response times
    if [[ ${#found_login_pages[@]} -gt 0 ]]; then
        log_message "Testing for username enumeration via error messages" "INFO"
        echo "Username Enumeration Test Results:" >> "${username_enum_output}"
        
        # Test usernames (common valid and invalid)
        local usernames=("admin" "administrator" "root" "user" "test" "guest" "thisisnotavalidusername12345")
        
        for login_url in "${found_login_pages[@]}"; do
            echo "Testing Login URL: ${login_url}" >> "${username_enum_output}"
            
            # Get the login page to analyze form structure
            local page_content=$(curl -s "${login_url}")
            
            # Look for common username & password field names
            local username_fields=("username" "user" "email" "login" "id" "user_login")
            local password_fields=("password" "pass" "pwd" "user_pass")
            
            for username in "${usernames[@]}"; do
                for username_field in "${username_fields[@]}"; do
                    for password_field in "${password_fields[@]}"; do
                        # Try with a random password
                        local response=$(curl -s -X POST "${login_url}" -d "${username_field}=${username}&${password_field}=wrongpass123")
                        local response_length=${#response}
                        
                        # Look for specific error patterns that might reveal username validity
                        if echo "${response}" | grep -q -i "password.*incorrect\|invalid password\|wrong password"; then
                            echo "  [!] VULNERABLE: Username '${username}' appears valid (error message indicates valid username but wrong password)" >> "${username_enum_output}"
                            echo "  Field names detected: ${username_field}=${username}, ${password_field}=****" >> "${username_enum_output}"
                        elif echo "${response}" | grep -q -i "user.*not found\|invalid username\|user.*not exist"; then
                            echo "  [!] VULNERABLE: System explicitly states that username '${username}' is invalid" >> "${username_enum_output}"
                            echo "  Field names detected: ${username_field}=${username}, ${password_field}=****" >> "${username_enum_output}"
                        fi
                    done
                done
            done
            
            echo "" >> "${username_enum_output}"
        done
        
        # Test for timing differences
        log_message "Testing for timing-based username enumeration" "INFO"
        echo "Timing-Based Username Enumeration Test:" >> "${username_enum_output}"
        
        for login_url in "${found_login_pages[@]}"; do
            echo "Testing Login URL (Timing): ${login_url}" >> "${username_enum_output}"
            
            # Test a likely valid username vs an invalid one and measure response time
            local valid_user_time=$(curl -s -w "%{time_total}" -o /dev/null -X POST "${login_url}" -d "username=admin&password=wrongpass123")
            local invalid_user_time=$(curl -s -w "%{time_total}" -o /dev/null -X POST "${login_url}" -d "username=thisisnotavalidusername12345&password=wrongpass123")
            
            echo "  Valid username response time: ${valid_user_time} seconds" >> "${username_enum_output}"
            echo "  Invalid username response time: ${invalid_user_time} seconds" >> "${username_enum_output}"
            
            # Compare times - significant difference might indicate enumeration possibility
            awk -v vt="${valid_user_time}" -v it="${invalid_user_time}" 'BEGIN {
                difference = vt - it
                if (difference > 0.5 || difference < -0.5) {
                    print "  [!] POTENTIAL TIMING VULNERABILITY: Significant timing difference detected"
                    print "  Timing difference: " difference " seconds"
                } else {
                    print "  [-] No significant timing differences detected"
                }
            }' >> "${username_enum_output}"
            
            echo "" >> "${username_enum_output}"
        done
    fi
    
    log_message "Username enumeration testing completed" "INFO"
}

# Function to test for authentication bypass
test_auth_bypass() {
    local target=$1
    local output_dir=$2
    local auth_bypass_output="${output_dir}/auth_bypass.txt"
    
    log_message "Testing for authentication bypass on ${target}" "INFO"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    echo "Authentication Bypass Test for ${target}" > "${auth_bypass_output}"
    echo "----------------------------------------" >> "${auth_bypass_output}"
    
    # Step 1: Try direct access to common admin/restricted pages
    local restricted_endpoints=(
        "/admin"
        "/dashboard"
        "/account"
        "/profile"
        "/settings"
        "/config"
        "/admin/dashboard"
        "/admin/settings"
        "/admin/users"
        "/wp-admin"
        "/administrator"
        "/private"
        "/user/profile"
    )
    
    log_message "Testing direct access to restricted pages" "INFO"
    echo "Testing Direct Access to Restricted Pages:" >> "${auth_bypass_output}"
    
    for endpoint in "${restricted_endpoints[@]}"; do
        local url="${target}${endpoint}"
        local response_code=$(curl -s -L -o /dev/null -w "%{http_code}" "${url}")
        local final_url=$(curl -s -L -o /dev/null -w "%{url_effective}" "${url}")
        
        echo "  Testing: ${url} (Status: ${response_code}, Redirected to: ${final_url})" >> "${auth_bypass_output}"
        
        # Check if the response is not a redirect to login and not 403/401
        if [[ "${response_code}" == "200" && ! "${final_url}" =~ login|signin|auth ]]; then
            echo "  [!] POTENTIAL BYPASS: Page accessible without authentication: ${url}" >> "${auth_bypass_output}"
        fi
    done
    
    echo "" >> "${auth_bypass_output}"
    
    # Step 2: Test for parameter manipulation and cookie tampering
    log_message "Testing for parameter manipulation" "INFO"
    echo "Parameter Manipulation Tests:" >> "${auth_bypass_output}"
    
    local auth_parameters=(
        "admin=false" "admin=0" "admin=no"
        "authenticated=false" "authenticated=0" "authenticated=no"
        "debug=true" "debug=1" "debug=on"
        "test=true" "test=1" "test=on"
        "role=user" "role=guest"
        "access=false" "access=0"
        "logged=false" "logged=0"
    )
    
    # Generate variations with auth parameters
    for endpoint in "${restricted_endpoints[@]}"; do
        for param in "${auth_parameters[@]}"; do
            local url="${target}${endpoint}?${param}"
            local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${url}")
            
            # Only record potentially successful attempts
            if [[ "${response_code}" == "200" ]]; then
                echo "  Testing: ${url} (Status: ${response_code})" >> "${auth_bypass_output}"
                echo "  [!] POTENTIAL BYPASS: Parameter manipulation may work: ${url}" >> "${auth_bypass_output}"
            fi
        done
    done
    
    echo "" >> "${auth_bypass_output}"
    
    # Step 3: Test for default credentials
    log_message "Testing for default credentials" "INFO"
    echo "Default Credentials Test:" >> "${auth_bypass_output}"
    
    local default_credentials=(
        "admin:admin"
        "admin:password"
        "admin:123456"
        "root:root"
        "root:password"
        "administrator:administrator"
        "administrator:password"
        "user:user"
        "user:password"
        "guest:guest"
        "test:test"
    )
    
    # Find login pages first
    local login_pages=($(grep -A 100 "Detected Login Endpoints:" "${output_dir}/username_enumeration.txt" | grep "\[+\]" | awk '{print $2}'))
    
    if [[ ${#login_pages[@]} -eq 0 ]]; then
        # Try to find login pages if the username enumeration didn't find any
        for endpoint in "/login" "/signin" "/auth" "/user/login" "/admin/login" "/wp-login.php"; do
            local url="${target}${endpoint}"
            local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${url}")
            
            if [[ "${response_code}" == "200" || "${response_code}" == "302" ]]; then
                login_pages+=("${url}")
            fi
        done
    fi
    
    if [[ ${#login_pages[@]} -gt 0 ]]; then
        for login_page in "${login_pages[@]}"; do
            echo "  Testing login page: ${login_page}" >> "${auth_bypass_output}"
            
            for cred in "${default_credentials[@]}"; do
                IFS=':' read -ra parts <<< "${cred}"
                local username="${parts[0]}"
                local password="${parts[1]}"
                
                # Attempt login with default credentials
                local response=$(curl -s -c /tmp/cookie.txt -L -X POST "${login_page}" -d "username=${username}&password=${password}")
                
                # Check for successful login indicators
                if echo "${response}" | grep -q -i "welcome\|dashboard\|profile\|logout\|sign out"; then
                    echo "  [!] POTENTIAL DEFAULT CREDENTIALS FOUND: ${username}:${password}" >> "${auth_bypass_output}"
                    break
                fi
                
                # Clean up cookie file
                rm -f /tmp/cookie.txt
            done
        done
    else
        echo "  [-] No login pages found for default credential testing" >> "${auth_bypass_output}"
    fi
    
    log_message "Authentication bypass testing completed" "INFO"
}

# Function to test for brute force protections
test_brute_force_protection() {
    local target=$1
    local output_dir=$2
    local brute_force_output="${output_dir}/brute_force_protection.txt"
    
    log_message "Testing for brute force protections on ${target}" "INFO"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    echo "Brute Force Protection Test for ${target}" > "${brute_force_output}"
    echo "----------------------------------------" >> "${brute_force_output}"
    
    # Find login pages first
    local login_pages=($(grep -A 100 "Detected Login Endpoints:" "${output_dir}/username_enumeration.txt" | grep "\[+\]" | awk '{print $2}'))
    
    if [[ ${#login_pages[@]} -eq 0 ]]; then
        # Try to find login pages if the username enumeration didn't find any
        for endpoint in "/login" "/signin" "/auth" "/user/login" "/admin/login" "/wp-login.php"; do
            local url="${target}${endpoint}"
            local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${url}")
            
            if [[ "${response_code}" == "200" || "${response_code}" == "302" ]]; then
                login_pages+=("${url}")
            fi
        done
    fi
    
    if [[ ${#login_pages[@]} -gt 0 ]]; then
        for login_page in "${login_pages[@]}"; do
            echo "Testing login page: ${login_page}" >> "${brute_force_output}"
            echo "Sending multiple failed login attempts to test rate limiting and account lockout..." >> "${brute_force_output}"
            
            # Make 10 login attempts with wrong credentials
            local username="admin"
            local captcha_detected=false
            local rate_limit_detected=false
            local attempt_responses=()
            
            for i in {1..10}; do
                # Use a random password for each attempt
                local password="wrongpassword${RANDOM}"
                
                echo "  Attempt ${i} - Username: ${username}, Password: ${password}" >> "${brute_force_output}"
                
                # Attempt login with wrong credentials
                local start_time=$(date +%s.%N)
                local response=$(curl -s -c /tmp/cookie.txt -L -X POST "${login_page}" -d "username=${username}&password=${password}")
                local end_time=$(date +%s.%N)
                local time_taken=$(echo "${end_time} - ${start_time}" | bc)
                
                echo "  Response time: ${time_taken} seconds" >> "${brute_force_output}"
                
                # Check for CAPTCHA indicators
                if echo "${response}" | grep -q -i "captcha\|recaptcha\|human verification\|not a robot"; then
                    captcha_detected=true
                    echo "  [!] CAPTCHA detected after ${i} attempts" >> "${brute_force_output}"
                    break
                fi
                
                # Check for rate limiting or account lockout indicators
                if echo "${response}" | grep -q -i "too many attempts\|account locked\|try again later\|temporary block\|rate limit\|blocked"; then
                    rate_limit_detected=true
                    echo "  [!] Rate limiting or account lockout detected after ${i} attempts" >> "${brute_force_output}"
                    break
                fi
                
                # Check for increasing response time (adaptive rate limiting)
                attempt_responses+=("${time_taken}")
                
                if [[ $i -gt 1 ]]; then
                    local prev_time=${attempt_responses[$i-2]}
                    local time_diff=$(echo "${time_taken} - ${prev_time}" | bc)
                    
                    if (( $(echo "${time_diff} > 1.0" | bc -l) )); then
                        echo "  [!] Increasing response time detected (possible adaptive rate limiting)" >> "${brute_force_output}"
                    fi
                fi
                
                # Small pause between attempts to avoid overloading the server
                sleep 1
            done
            
            if [[ "${captcha_detected}" == false && "${rate_limit_detected}" == false ]]; then
                echo "  [!] VULNERABLE: No CAPTCHA or rate limiting detected after 10 login attempts" >> "${brute_force_output}"
                echo "  This system may be vulnerable to brute force attacks" >> "${brute_force_output}"
            else
                if [[ "${captcha_detected}" == true ]]; then
                    echo "  [+] CAPTCHA protection in place" >> "${brute_force_output}"
                fi
                
                if [[ "${rate_limit_detected}" == true ]]; then
                    echo "  [+] Rate limiting or account lockout protection in place" >> "${brute_force_output}"
                fi
            fi
            
            # Clean up cookie file
            rm -f /tmp/cookie.txt
            
            echo "" >> "${brute_force_output}"
        done
    else
        log_message "No login pages found for brute force testing" "WARNING"
        echo "[-] No login pages found for brute force testing" >> "${brute_force_output}"
    fi
    
    log_message "Brute force protection testing completed" "INFO"
}

# Function to test for password reset vulnerabilities
test_password_reset() {
    local target=$1
    local output_dir=$2
    local pwd_reset_output="${output_dir}/password_reset.txt"
    
    log_message "Testing for password reset vulnerabilities on ${target}" "INFO"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    echo "Password Reset Vulnerability Test for ${target}" > "${pwd_reset_output}"
    echo "----------------------------------------" >> "${pwd_reset_output}"
    
    # Step 1: Find password reset pages
    local reset_endpoints=(
        "/forgot-password"
        "/reset-password"
        "/forgot"
        "/password/reset"
        "/account/forgot-password"
        "/password/forgot"
        "/user/forgot-password"
        "/reset"
        "/forgot_password.php"
        "/wp-login.php?action=lostpassword"
    )
    
    log_message "Searching for password reset endpoints" "INFO"
    echo "Detected Password Reset Endpoints:" >> "${pwd_reset_output}"
    
    local found_reset_pages=()
    for endpoint in "${reset_endpoints[@]}"; do
        local url="${target}${endpoint}"
        local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${url}")
        
        if [[ "${response_code}" == "200" || "${response_code}" == "302" ]]; then
            echo "  [+] ${url} (Status: ${response_code})" >> "${pwd_reset_output}"
            found_reset_pages+=("${url}")
        fi
    done
    
    if [[ ${#found_reset_pages[@]} -eq 0 ]]; then
        log_message "No common password reset pages found" "WARNING"
        echo "  [-] No common password reset pages found. Consider manual exploration." >> "${pwd_reset_output}"
    else
        log_message "Found ${#found_reset_pages[@]} potential password reset endpoints" "INFO"
    fi
    
    echo "" >> "${pwd_reset_output}"
    
    # Step 2: Test for username enumeration in reset pages
    if [[ ${#found_reset_pages[@]} -gt 0 ]]; then
        log_message "Testing for username enumeration in password reset" "INFO"
        echo "Username Enumeration in Password Reset:" >> "${pwd_reset_output}"
        
        # Test usernames (common valid and invalid)
        local usernames=("admin" "administrator" "test" "thisisnotavalidusername12345")
        
        for reset_url in "${found_reset_pages[@]}"; do
            echo "Testing Reset URL: ${reset_url}" >> "${pwd_reset_output}"
            
            # Get the reset page to analyze form structure
            local page_content=$(curl -s "${reset_url}")
            
            # Look for common email/username field names
            local email_fields=("email" "user_email" "username" "user" "login")
            
            for username in "${usernames[@]}"; do
                # Try both as username and as email
                local email="${username}@example.com"
                
                for field in "${email_fields[@]}"; do
                    # Try with username
                    local response_user=$(curl -s -X POST "${reset_url}" -d "${field}=${username}")
                    
                    # Check for specific responses that might reveal username validity
                    if echo "${response_user}" | grep -q -i "email sent\|check your email\|instructions sent"; then
                        echo "  [!] VULNERABLE: System indicates that password reset for '${username}' was initiated (valid username likely)" >> "${pwd_reset_output}"
                    elif echo "${response_user}" | grep -q -i "user not found\|no account\|email not found"; then
                        echo "  [!] VULNERABLE: System explicitly states that '${username}' is invalid" >> "${pwd_reset_output}"
                    fi
                    
                    # Try with email
                    local response_email=$(curl -s -X POST "${reset_url}" -d "${field}=${email}")
                    
                    # Check for specific responses that might reveal email validity
                    if echo "${response_email}" | grep -q -i "email sent\|check your email\|instructions sent"; then
                        echo "  [!] VULNERABLE: System indicates that password reset for '${email}' was initiated (valid email likely)" >> "${pwd_reset_output}"
                    elif echo "${response_email}" | grep -q -i "user not found\|no account\|email not found"; then
                        echo "  [!] VULNERABLE: System explicitly states that '${email}' is invalid" >> "${pwd_reset_output}"
                    fi
                done
            done
            
            echo "" >> "${pwd_reset_output}"
        done
    fi
    
    # Step 3: Test token prediction/leakage (simulation)
    log_message "Testing for password reset token issues (simulated)" "INFO"
    echo "Password Reset Token Security (Simulated Test):" >> "${pwd_reset_output}"
    echo "  [i] Note: This is a simulated test as we can't intercept actual reset tokens" >> "${pwd_reset_output}"
    echo "" >> "${pwd_reset_output}"
    
    echo "Potential Token Security Issues to Check Manually:" >> "${pwd_reset_output}"
    echo "  1. Short token length (less than 20 characters)" >> "${pwd_reset_output}"
    echo "  2. Tokens based on predictable information (timestamp, user ID)" >> "${pwd_reset_output}"
    echo "  3. Tokens that don't expire (long or no expiration time)" >> "${pwd_reset_output}"
    echo "  4. Tokens that remain valid after use" >> "${pwd_reset_output}"
    echo "  5. Tokens sent over HTTP instead of HTTPS" >> "${pwd_reset_output}"
    echo "  6. Tokens visible in the URL (vulnerable to referrer leakage)" >> "${pwd_reset_output}"
    echo "" >> "${pwd_reset_output}"
    
    log_message "Password reset vulnerability testing completed" "INFO"
}

# Function to test JWT & token-based authentication
test_jwt_auth() {
    local target=$1
    local output_dir=$2
    local jwt_output="${output_dir}/jwt_token_security.txt"
    local jwt_poc_dir="${output_dir}/jwt_poc"
    
    # Create PoC directory
    mkdir -p "${jwt_poc_dir}"
    
    log_message "Testing for JWT and token-based authentication vulnerabilities on ${target}" "INFO"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    echo "JWT & Token-Based Authentication Test for ${target}" > "${jwt_output}"
    echo "----------------------------------------" >> "${jwt_output}"
    
    # Step 1: Check for JWT usage in the application
    log_message "Checking for JWT usage in the application" "INFO"
    echo "Checking for JWT Usage:" >> "${jwt_output}"
    
    # Find login pages first to check for JWT after login
    local login_pages=($(grep -A 100 "Detected Login Endpoints:" "${output_dir}/username_enumeration.txt" | grep "\[+\]" | awk '{print $2}'))
    
    if [[ ${#login_pages[@]} -eq 0 ]]; then
        # Try to find login pages if the username enumeration didn't find any
        for endpoint in "/login" "/signin" "/auth"; do
            local url="${target}${endpoint}"
            local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${url}")
            
            if [[ "${response_code}" == "200" || "${response_code}" == "302" ]]; then
                login_pages+=("${url}")
            fi
        done
    fi
    
    local jwt_detected=false
    
    if [[ ${#login_pages[@]} -gt 0 ]]; then
        for login_page in "${login_pages[@]}"; do
            echo "  Testing login page: ${login_page}" >> "${jwt_output}"
            
            # Try with some default credentials (non-invasive)
            for cred in "admin:admin" "test:test" "user:user"; do
                IFS=':' read -ra parts <<< "${cred}"
                local username="${parts[0]}"
                local password="${parts[1]}"
                
                # Attempt login and check for JWT in response headers or body
                local response_headers=$(curl -s -i -c /tmp/cookie.txt -L -X POST "${login_page}" -d "username=${username}&password=${password}")
                
                # Check for JWT in Authorization header, Set-Cookie, or response body
                if echo "${response_headers}" | grep -q -i "eyJ"; then
                    jwt_detected=true
                    
                    # Extract the JWT token
                    local jwt_token=$(echo "${response_headers}" | grep -o "eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*")
                    
                    if [[ -n "${jwt_token}" ]]; then
                        echo "  [!] JWT token detected: ${jwt_token}" >> "${jwt_output}"
                        
                        # Analyze JWT token parts
                        local header=$(echo "${jwt_token}" | cut -d '.' -f 1)
                        local payload=$(echo "${jwt_token}" | cut -d '.' -f 2)
                        
                        # Base64 decode (handle padding)
                        decode_base64_url() {
                            local len=$((${#1} % 4))
                            local encoded="$1"
                            if [[ $len -eq 2 ]]; then encoded="${encoded}=="; 
                            elif [[ $len -eq 3 ]]; then encoded="${encoded}="; fi
                            echo "${encoded}" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "Unable to decode"
                        }
                        
                        local decoded_header=$(decode_base64_url "${header}")
                        local decoded_payload=$(decode_base64_url "${payload}")
                        
                        echo "  JWT Header: ${decoded_header}" >> "${jwt_output}"
                        echo "  JWT Payload: ${decoded_payload}" >> "${jwt_output}"
                        
                        # Check for algorithm vulnerabilities
                        if echo "${decoded_header}" | grep -q -i '"alg"\s*:\s*"none"'; then
                            echo "  [!!] CRITICAL: JWT uses 'none' algorithm which is vulnerable to signature bypass" >> "${jwt_output}"
                        elif echo "${decoded_header}" | grep -q -i '"alg"\s*:\s*"HS'; then
                            echo "  [i] JWT uses HMAC-SHA algorithm (HS256/HS384/HS512)" >> "${jwt_output}"
                            echo "  [i] Potential issue: May be vulnerable to brute force attacks if weak secret key is used" >> "${jwt_output}"
                        fi
                        
                        # Check for missing claims
                        if ! echo "${decoded_payload}" | grep -q -i '"exp"'; then
                            echo "  [!] VULNERABLE: No expiration claim (exp) found - token may never expire" >> "${jwt_output}"
                        fi
                        
                        break
                    fi
                fi
                
                # Clean up cookie file
                rm -f /tmp/cookie.txt
            done
        done
    fi
    
    if [[ "${jwt_detected}" == false ]]; then
        echo "  [-] No JWT tokens detected during authentication testing" >> "${jwt_output}"
        
        # Check for JWT in API endpoints
        echo "" >> "${jwt_output}"
        echo "Checking for JWT in API Endpoints:" >> "${jwt_output}"
        
        local api_endpoints=(
            "/api"
            "/api/v1"
            "/api/user"
            "/api/data"
            "/api/auth"
            "/rest"
            "/graphql"
        )
        
        for endpoint in "${api_endpoints[@]}"; do
            local url="${target}${endpoint}"
            local response_headers=$(curl -s -i "${url}")
            
            # Look for HTTP 401/403 with WWW-Authenticate or similar headers
            local status_code=$(echo "${response_headers}" | head -n 1 | grep -o "[0-9]\{3\}")
            
            if [[ "${status_code}" == "401" || "${status_code}" == "403" ]]; then
                if echo "${response_headers}" | grep -q -i "Bearer\|JWT\|token\|authorization"; then
                    echo "  [+] Potential JWT usage detected at ${url}" >> "${jwt_output}"
                    jwt_detected=true
                fi
            fi
        done
    fi
    
    echo "" >> "${jwt_output}"
    
    # Step 2: Test for token storage issues (check if tokens are stored in localStorage)
    log_message "Checking for insecure token storage" "INFO"
    echo "Token Storage Security (Informational):" >> "${jwt_output}"
    echo "  [i] Manual check required: Inspect JavaScript for insecure token storage" >> "${jwt_output}"
    echo "" >> "${jwt_output}"
    echo "Potential Token Storage Issues to Check Manually:" >> "${jwt_output}"
    echo "  1. Tokens stored in localStorage (vulnerable to XSS)" >> "${jwt_output}"
    echo "  2. Tokens stored in sessionStorage (vulnerable to XSS)" >> "${jwt_output}"
    echo "  3. Tokens exposed in URL parameters (vulnerable to leakage via Referer header)" >> "${jwt_output}"
    echo "  4. Missing HttpOnly flag on auth cookies (allows JavaScript access)" >> "${jwt_output}"
    echo "  5. Missing Secure flag on auth cookies (allows transmission over HTTP)" >> "${jwt_output}"
    echo "  6. Missing SameSite attribute on auth cookies (vulnerable to CSRF)" >> "${jwt_output}"
    echo "" >> "${jwt_output}"
    
    log_message "JWT and token-based authentication testing completed" "INFO"
}

# Helper function to generate JWT attack PoCs
generate_jwt_attack_poc() {
    local jwt_token=$1
    local poc_dir=$2
    local target=$3
    
    if [[ -z "${jwt_token}" ]]; then
        return 1
    fi
    
    # Create PoC for Algorithm None attack
    cat > "${poc_dir}/alg_none_attack.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>JWT Algorithm None Attack - ${target}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #d9534f; }
        .token { word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 4px; }
        .warning { color: #d9534f; font-weight: bold; }
        pre { background: #f8f9fa; padding: 10px; overflow-x: auto; }
        button { background: #5bc0de; color: white; border: none; padding: 10px 15px; cursor: pointer; border-radius: 4px; margin: 10px 0; }
        button:hover { background: #31b0d5; }
    </style>
</head>
<body>
    <h1>JWT Algorithm None Attack</h1>
    
    <p class="warning">WARNING: This is a proof-of-concept for educational purposes only.</p>
    
    <div class="token">
        <p><strong>Original JWT Token:</strong> ${jwt_token}</p>
    </div>
    
    <div>
        <h3>Steps to Test:</h3>
        <ol>
            <li>Decode the token</li>
            <li>Change the "alg" parameter in the header to "none"</li>
            <li>Remove the signature part (the part after the second period)</li>
            <li>Use the modified token to make requests</li>
        </ol>
    </div>
    
    <div>
        <h3>Manual Testing:</h3>
        <ol>
            <li>Header: <pre id="header">${jwt_token%%.*}</pre></li>
            <li>Payload: <pre id="payload">${jwt_token#*.}</pre></li>
            <li>
                <p>Try a request with this modified token:</p>
                <pre id="modified">Header + '.' + Payload + '.'</pre>
            </li>
        </ol>
    </div>
    
    <p class="warning">Note: This attack only works if the server's JWT library accepts "none" as a valid algorithm and doesn't properly validate tokens.</p>
</body>
</html>
EOF
    
    # Create JWT analysis report
    # Extract header, payload for analysis
    local header=$(echo "${jwt_token}" | cut -d. -f1)
    local payload=$(echo "${jwt_token}" | cut -d. -f2)
    
    # Base64 decode the header and payload - handle both Linux and macOS versions
    # Add padding if needed for base64 decoding
    header=$(echo "${header}" | tr '-_' '+/' | awk '{if(length($0)%4==0) print $0; else print $0 substr("===",1,4-length($0)%4)}')
    payload=$(echo "${payload}" | tr '-_' '+/' | awk '{if(length($0)%4==0) print $0; else print $0 substr("===",1,4-length($0)%4)}')
    
    local decoded_header=$(echo "${header}" | base64 -d 2>/dev/null || echo "${header}" | base64 -D 2>/dev/null || echo "Unable to decode")
    local decoded_payload=$(echo "${payload}" | base64 -d 2>/dev/null || echo "${payload}" | base64 -D 2>/dev/null || echo "Unable to decode")
    
    cat > "${poc_dir}/jwt_security_analysis.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>JWT Security Analysis - ${target}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #5cb85c; }
        .token { word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 4px; }
        .warning { color: #d9534f; font-weight: bold; }
        pre { background: #f8f9fa; padding: 10px; overflow-x: auto; }
        .data-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .data-table th, .data-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .data-table th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>JWT Token Security Analysis</h1>
    
    <div class="token">
        <p><strong>JWT Token:</strong> ${jwt_token}</p>
    </div>
    
    <h2>Decoded Data</h2>
    
    <h3>Header:</h3>
    <pre>${decoded_header}</pre>
    
    <h3>Payload:</h3>
    <pre>${decoded_payload}</pre>
    
    <h2>Common JWT Vulnerabilities to Test For</h2>
    
    <ol>
        <li><strong>Algorithm "none" attack</strong> - Modify the header to use "none" algorithm and remove the signature</li>
        <li><strong>Algorithm switching attack</strong> - Change RS256 to HS256 and sign with the public key</li>
        <li><strong>Weak secret key</strong> - Brute force HMAC-based tokens</li>
        <li><strong>Missing token expiration</strong> - Check if tokens can be used indefinitely</li>
        <li><strong>Missing signature validation</strong> - Test if signature is actually validated</li>
        <li><strong>Information disclosure</strong> - Sensitive data in the payload</li>
        <li><strong>Missing audience validation</strong> - Try reusing tokens across services</li>
    </ol>
    
    <h2>Recommended Security Controls</h2>
    
    <ul>
        <li>Use strong algorithms (RS256, ES256) with proper key management</li>
        <li>Implement proper token expiration and validation</li>
        <li>Include and validate the "aud" (audience) claim</li>
        <li>Store tokens securely (HttpOnly cookies with appropriate flags)</li>
        <li>Implement token revocation mechanisms</li>
        <li>Don't store sensitive data in tokens</li>
    </ul>
</body>
</html>
EOF
}

# Function to test session management security
test_session_management() {
    local target=$1
    local output_dir=$2
    local session_output="${output_dir}/session_management.txt"
    
    log_message "Testing session management security on ${target}" "INFO"
    
    # Ensure the target has a protocol prefix
    if [[ ! "${target}" =~ ^https?:// ]]; then
        target="http://${target}"
    fi
    
    echo "Session Management Security Test for ${target}" > "${session_output}"
    echo "----------------------------------------" >> "${session_output}"
    
    # Step 1: Check cookie security flags
    log_message "Checking cookie security attributes" "INFO"
    echo "Cookie Security Analysis:" >> "${session_output}"
    
    # Get cookies from the main page
    local cookies=$(curl -s -i "${target}" | grep -i "set-cookie")
    
    if [[ -n "${cookies}" ]]; then
        echo "  Cookies detected:" >> "${session_output}"
        echo "${cookies}" | sed 's/^/    /' >> "${session_output}"
        echo "" >> "${session_output}"
        
        # Analyze each cookie for security flags
        echo "  Cookie Security Analysis:" >> "${session_output}"
        
        while IFS= read -r cookie; do
            if [[ -n "${cookie}" ]]; then
                # Extract cookie name
                local cookie_name=$(echo "${cookie}" | sed -n 's/.*Set-Cookie: \([^=]*\)=.*/\1/ip')
                echo "    Cookie: ${cookie_name}" >> "${session_output}"
                
                # Check for HttpOnly flag
                if echo "${cookie}" | grep -q -i "httponly"; then
                    echo "      [+] HttpOnly: Yes (Protects against XSS)" >> "${session_output}"
                else
                    echo "      [-] HttpOnly: No (VULNERABLE to XSS cookie theft)" >> "${session_output}"
                fi
                
                # Check for Secure flag
                if echo "${cookie}" | grep -q -i "secure"; then
                    echo "      [+] Secure: Yes (Restricts to HTTPS)" >> "${session_output}"
                else
                    echo "      [-] Secure: No (VULNERABLE to MITM over HTTP)" >> "${session_output}"
                fi
                
                # Check for SameSite attribute
                if echo "${cookie}" | grep -q -i "samesite"; then
                    local samesite_value=$(echo "${cookie}" | grep -o -i "samesite=[^;]*" | cut -d '=' -f 2)
                    if [[ "${samesite_value,,}" == "none" ]]; then
                        echo "      [-] SameSite: None (VULNERABLE to CSRF attacks)" >> "${session_output}"
                    elif [[ "${samesite_value,,}" == "lax" ]]; then
                        echo "      [i] SameSite: Lax (Partial protection against CSRF)" >> "${session_output}"
                    elif [[ "${samesite_value,,}" == "strict" ]]; then
                        echo "      [+] SameSite: Strict (Good protection against CSRF)" >> "${session_output}"
                    else
                        echo "      [i] SameSite: ${samesite_value}" >> "${session_output}"
                    fi
                else
                    echo "      [-] SameSite: Not set (VULNERABLE to CSRF attacks)" >> "${session_output}"
                fi
                
                # Check for path
                if echo "${cookie}" | grep -q -i "path"; then
                    local path_value=$(echo "${cookie}" | grep -o -i "path=[^;]*" | cut -d '=' -f 2)
                    echo "      [i] Path: ${path_value}" >> "${session_output}"
                fi
                
                # Check for Expires/Max-Age
                if echo "${cookie}" | grep -q -i "expires"; then
                    local expires_value=$(echo "${cookie}" | grep -o -i "expires=[^;]*" | cut -d '=' -f 2-)
                    echo "      [i] Expires: ${expires_value}" >> "${session_output}"
                elif echo "${cookie}" | grep -q -i "max-age"; then
                    local maxage_value=$(echo "${cookie}" | grep -o -i "max-age=[^;]*" | cut -d '=' -f 2)
                    echo "      [i] Max-Age: ${maxage_value} seconds" >> "${session_output}"
                else
                    echo "      [i] Expiration: Not set (Session cookie)" >> "${session_output}"
                fi
                
                echo "" >> "${session_output}"
            fi
        done <<< "${cookies}"
    else
        echo "  [-] No cookies detected on the main page" >> "${session_output}"
    fi
    
    # Step 2: Test for session fixation vulnerabilities
    log_message "Testing for session fixation vulnerabilities" "INFO"
    echo "Session Fixation Test:" >> "${session_output}"
    
    # Find login pages
    local login_pages=($(grep -A 100 "Detected Login Endpoints:" "${output_dir}/username_enumeration.txt" | grep "\[+\]" | awk '{print $2}'))
    
    if [[ ${#login_pages[@]} -eq 0 ]]; then
        # Try to find login pages if the username enumeration didn't find any
        for endpoint in "/login" "/signin" "/auth"; do
            local url="${target}${endpoint}"
            local response_code=$(curl -s -o /dev/null -w "%{http_code}" "${url}")
            
            if [[ "${response_code}" == "200" || "${response_code}" == "302" ]]; then
                login_pages+=("${url}")
            fi
        done
    fi
    
    if [[ ${#login_pages[@]} -gt 0 ]]; then
        for login_page in "${login_pages[@]}"; do
            echo "  Testing login page: ${login_page}" >> "${session_output}"
            
            # Step 1: Get initial session ID before login
            local pre_login_cookies=$(curl -s -i "${login_page}" | grep -i "set-cookie")
            
            if [[ -n "${pre_login_cookies}" ]]; then
                echo "    Pre-login cookies:" >> "${session_output}"
                echo "${pre_login_cookies}" | sed 's/^/      /' >> "${session_output}"
                
                # Extract session IDs from cookies
                local session_ids=$(echo "${pre_login_cookies}" | grep -o -E "[a-zA-Z0-9_]+=[a-zA-Z0-9_-]+" | grep -i -E "sess|auth|id|token")
                
                if [[ -n "${session_ids}" ]]; then
                    echo "    Session identifiers before login:" >> "${session_output}"
                    echo "${session_ids}" | sed 's/^/      /' >> "${session_output}"
                    
                    # Try with some default credentials (non-invasive)
                    for cred in "admin:admin" "test:test" "user:user"; do
                        IFS=':' read -ra parts <<< "${cred}"
                        local username="${parts[0]}"
                        local password="${parts[1]}"
                        
                        # Save cookies to file for login attempt
                        curl -s -c /tmp/pre_cookies.txt "${login_page}" > /dev/null
                        
                        # Attempt login with saved cookies
                        local post_login_cookies=$(curl -s -i -b /tmp/pre_cookies.txt -L -X POST "${login_page}" -d "username=${username}&password=${password}" | grep -i "set-cookie")
                        
                        if [[ -n "${post_login_cookies}" ]]; then
                            echo "    Post-login cookies (after login attempt with ${username}:${password}):" >> "${session_output}"
                            echo "${post_login_cookies}" | sed 's/^/      /' >> "${session_output}"
                            
                            # Extract session IDs from post-login cookies
                            local post_session_ids=$(echo "${post_login_cookies}" | grep -o -E "[a-zA-Z0-9_]+=[a-zA-Z0-9_-]+" | grep -i -E "sess|auth|id|token")
                            
                            if [[ -n "${post_session_ids}" ]]; then
                                echo "    Session identifiers after login attempt:" >> "${session_output}"
                                echo "${post_session_ids}" | sed 's/^/      /' >> "${session_output}"
                                
                                # Compare pre and post login session IDs
                                if [[ "${session_ids}" == "${post_session_ids}" ]]; then
                                    echo "    [!] VULNERABLE: Session ID remains unchanged after login attempt (possible session fixation)" >> "${session_output}"
                                else
                                    echo "    [+] Session ID changed after login attempt (mitigation against session fixation)" >> "${session_output}"
                                fi
                            fi
                        fi
                        
                        # Clean up cookie file
                        rm -f /tmp/pre_cookies.txt
                        break  # Just test with one credential pair
                    done
                else
                    echo "    [-] No session identifiers found in cookies" >> "${session_output}"
                fi
            else
                echo "    [-] No cookies set before login" >> "${session_output}"
            fi
            
            echo "" >> "${session_output}"
        done
    else
        echo "  [-] No login pages found for session fixation testing" >> "${session_output}"
    fi
    
    # Step 3: Test for session termination (logout functionality)
    log_message "Testing for session termination issues" "INFO"
    echo "Session Termination Test:" >> "${session_output}"
    
    echo "  [i] Manual check required: Test if sessions are properly invalidated after logout" >> "${session_output}"
    echo "" >> "${session_output}"
    echo "Potential Session Management Issues to Check Manually:" >> "${session_output}"
    echo "  1. Sessions remaining active after logout" >> "${session_output}"
    echo "  2. No session timeout for inactive users" >> "${session_output}"
    echo "  3. Session tokens accepting old/expired values" >> "${session_output}"
    echo "  4. Sessions not invalidated after password change" >> "${session_output}"
    echo "  5. No protection against concurrent sessions (multiple devices)" >> "${session_output}"
    echo "" >> "${session_output}"
    
    log_message "Session management security testing completed" "INFO"
}

# Function to generate an HTML report for auth testing results
generate_auth_testing_report() {
    local target=$1
    local output_dir=$2
    local html_report="${output_dir}/auth_testing_report.html"
    
    log_message "Generating authentication testing HTML report for ${target}" "INFO"
    
    # Create an HTML report
    cat > "${html_report}" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Testing Report for ${target}</title>
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
        .vulnerable {
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
        <h1>Authentication Security Testing Report</h1>
        <p class="timestamp">Generated on $(date) for target: ${target}</p>
        
        <div class="summary section">
            <h2>Test Summary</h2>
            <p>This report contains the results of authentication security tests performed on the target.</p>
            <table>
                <tr>
                    <th>Test Type</th>
                    <th>Status</th>
                </tr>
                <tr>
                    <td>Username Enumeration</td>
                    <td>$(if [[ -f "${output_dir}/username_enumeration.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Authentication Bypass</td>
                    <td>$(if [[ -f "${output_dir}/auth_bypass.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Brute Force Protection</td>
                    <td>$(if [[ -f "${output_dir}/brute_force_protection.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Password Reset Security</td>
                    <td>$(if [[ -f "${output_dir}/password_reset.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>JWT Token Security</td>
                    <td>$(if [[ -f "${output_dir}/jwt_token_security.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
                <tr>
                    <td>Session Management</td>
                    <td>$(if [[ -f "${output_dir}/session_management.txt" ]]; then echo "Completed"; else echo "Not Run"; fi)</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Username Enumeration Findings</h2>
            <div class="results">
$(if [[ -f "${output_dir}/username_enumeration.txt" ]]; then
    # Highlight important findings
    cat "${output_dir}/username_enumeration.txt" | sed -e 's/\[!]/<span class="vulnerable">[!]<\/span>/g' -e 's/\[+]/<span class="secure">[+]<\/span>/g' -e 's/\[-]/<span class="warning">[-]<\/span>/g' -e 's/VULNERABLE:/<span class="vulnerable">VULNERABLE:<\/span>/g'
else
    echo "No username enumeration test data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Authentication Bypass Findings</h2>
            <div class="results">
$(if [[ -f "${output_dir}/auth_bypass.txt" ]]; then
    # Highlight important findings
    cat "${output_dir}/auth_bypass.txt" | sed -e 's/\[!]/<span class="vulnerable">[!]<\/span>/g' -e 's/\[+]/<span class="secure">[+]<\/span>/g' -e 's/\[-]/<span class="warning">[-]<\/span>/g' -e 's/POTENTIAL BYPASS:/<span class="vulnerable">POTENTIAL BYPASS:<\/span>/g'
else
    echo "No authentication bypass test data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Brute Force Protection Findings</h2>
            <div class="results">
$(if [[ -f "${output_dir}/brute_force_protection.txt" ]]; then
    # Highlight important findings
    cat "${output_dir}/brute_force_protection.txt" | sed -e 's/\[!]/<span class="vulnerable">[!]<\/span>/g' -e 's/\[+]/<span class="secure">[+]<\/span>/g' -e 's/\[-]/<span class="warning">[-]<\/span>/g' -e 's/VULNERABLE:/<span class="vulnerable">VULNERABLE:<\/span>/g'
else
    echo "No brute force protection test data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Password Reset Security Findings</h2>
            <div class="results">
$(if [[ -f "${output_dir}/password_reset.txt" ]]; then
    # Highlight important findings
    cat "${output_dir}/password_reset.txt" | sed -e 's/\[!]/<span class="vulnerable">[!]<\/span>/g' -e 's/\[+]/<span class="secure">[+]<\/span>/g' -e 's/\[-]/<span class="warning">[-]<\/span>/g' -e 's/\[i]/<span class="info">[i]<\/span>/g' -e 's/VULNERABLE:/<span class="vulnerable">VULNERABLE:<\/span>/g'
else
    echo "No password reset security test data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>JWT Token Security Findings</h2>
            <div class="results">
$(if [[ -f "${output_dir}/jwt_token_security.txt" ]]; then
    # Highlight important findings
    cat "${output_dir}/jwt_token_security.txt" | sed -e 's/\[!]/<span class="vulnerable">[!]<\/span>/g' -e 's/\[!!]/<span class="vulnerable">[!!]<\/span>/g' -e 's/\[+]/<span class="secure">[+]<\/span>/g' -e 's/\[-]/<span class="warning">[-]<\/span>/g' -e 's/\[i]/<span class="info">[i]<\/span>/g' -e 's/VULNERABLE:/<span class="vulnerable">VULNERABLE:<\/span>/g' -e 's/CRITICAL:/<span class="vulnerable">CRITICAL:<\/span>/g'
else
    echo "No JWT token security test data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Session Management Findings</h2>
            <div class="results">
$(if [[ -f "${output_dir}/session_management.txt" ]]; then
    # Highlight important findings
    cat "${output_dir}/session_management.txt" | sed -e 's/\[!]/<span class="vulnerable">[!]<\/span>/g' -e 's/\[+]/<span class="secure">[+]<\/span>/g' -e 's/\[-]/<span class="warning">[-]<\/span>/g' -e 's/\[i]/<span class="info">[i]<\/span>/g' -e 's/VULNERABLE:/<span class="vulnerable">VULNERABLE:<\/span>/g' -e 's/VULNERABLE to/<span class="vulnerable">VULNERABLE to<\/span>/g'
else
    echo "No session management test data available."
fi)
            </div>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <h3>Username Enumeration</h3>
            <ul>
                <li>Use generic error messages for both invalid usernames and passwords (e.g., "Invalid credentials")</li>
                <li>Ensure response times are consistent regardless of whether a username exists</li>
                <li>Implement rate limiting to prevent enumeration attacks</li>
            </ul>
            
            <h3>Authentication Bypass</h3>
            <ul>
                <li>Use proper access controls and validate sessions server-side</li>
                <li>Implement role-based access control (RBAC)</li>
                <li>Never trust client-side parameters for authentication decisions</li>
            </ul>
            
            <h3>Brute Force Protection</h3>
            <ul>
                <li>Implement account lockout after multiple failed attempts</li>
                <li>Use CAPTCHAs or similar challenges after suspicious login patterns</li>
                <li>Consider using adaptive authentication for higher-risk scenarios</li>
            </ul>
            
            <h3>Password Reset Security</h3>
            <ul>
                <li>Generate long, random, one-time-use reset tokens</li>
                <li>Set short expiration times for reset tokens (e.g., 15-30 minutes)</li>
                <li>Send generic messages regardless of whether an email/username exists</li>
                <li>Require additional verification for high-risk reset scenarios</li>
            </ul>
            
            <h3>JWT & Token Security</h3>
            <ul>
                <li>Use strong signing algorithms (RS256, ES256) instead of "none" or weak HS256</li>
                <li>Include and validate expiration (exp), issued at (iat), and audience (aud) claims</li>
                <li>Store tokens securely (HttpOnly cookies over localStorage/sessionStorage)</li>
                <li>Implement token revocation mechanisms</li>
            </ul>
            
            <h3>Session Management</h3>
            <ul>
                <li>Use HttpOnly, Secure, and SameSite=Strict flags on session cookies</li>
                <li>Generate new session IDs after authentication</li>
                <li>Implement proper session timeouts</li>
                <li>Invalidate sessions on logout, password change, and suspicious activity</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF
    
    log_message "Authentication testing HTML report generated: ${html_report}" "SUCCESS"
}

# Main function for auth testing module
run_auth_testing_module() {
    show_auth_testing_banner
    
    # Check if a target is provided
    if [[ -z "${target}" ]]; then
        log_message "No target specified. Use -t or --target option." "ERROR"
        return 1
    fi
    
    # Create output directory for auth testing results
    local auth_testing_dir="${target_dir}/auth_testing"
    mkdir -p "${auth_testing_dir}"
    
    log_message "Starting Authentication Testing module for ${target}" "INFO"
    
    # Run the auth testing functions in sequence
    test_username_enumeration "${target}" "${auth_testing_dir}"
    test_auth_bypass "${target}" "${auth_testing_dir}"
    test_brute_force_protection "${target}" "${auth_testing_dir}"
    test_password_reset "${target}" "${auth_testing_dir}"
    test_jwt_auth "${target}" "${auth_testing_dir}"
    test_session_management "${target}" "${auth_testing_dir}"
    
    # Generate HTML report
    generate_auth_testing_report "${target}" "${auth_testing_dir}"
    
    log_message "Authentication Testing module completed for ${target}" "SUCCESS"
    
    # Display summary
    echo "--------------------------------------------------"
    echo "Authentication Testing Summary for ${target}:"
    echo "--------------------------------------------------"
    echo "Tests performed:"
    echo "- Username Enumeration"
    echo "- Authentication Bypass"
    echo "- Brute Force Protection"
    echo "- Password Reset Vulnerabilities"
    echo "- JWT & Token-Based Authentication"
    echo "- Session Management"
    echo "--------------------------------------------------"
    echo "HTML Report: ${auth_testing_dir}/auth_testing_report.html"
    echo "--------------------------------------------------"
    
    return 0
}