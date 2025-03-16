#!/bin/bash

# MR Legacy - Content Discovery Module
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
function show_content_discovery_banner() {
    echo -e "${BLUE}
   ____ ___  _   _ _____ _____ _   _ _____   ____  ___ ____   ____ _____     _______ ______   __
  / ___/ _ \| \ | |_   _| ____| \ | |_   _| |  _ \|_ _/ ___| / ___|_   _|   | ____\ \/ / _ \ / / ___|
 | |  | | | |  \| | | | |  _| |  \| | | |   | | | || |\___ \| |     | |_____| |_   \  / | | | \___ \\
 | |__| |_| | |\  | | | | |___| |\  | | |   | |_| || | ___) | |___  | |_____| |___ /  \ |_| | |___) |
  \____\___/|_| \_| |_| |_____|_| \_| |_|   |____/|___|____/ \____| |_|     |_____/_/\_\___/|_|____/                      
${NC}"
    echo -e "${YELLOW}[+] Content Discovery Module - Hidden Files & Directories${NC}"
    echo -e "${YELLOW}[+] Target: $target${NC}"
    echo "=============================================================="
}

# Function to perform enhanced directory brute force
function directory_bruteforce() {
    if is_completed "directory_bruteforce"; then
        log_message "Directory brute force already completed for $target" "INFO"
        return 0
    fi
    
    start_function "directory_bruteforce" "Enhanced Directory Brute Force for $target"
    
    mkdir -p "$target_dir/content_discovery/directories" 2>/dev/null
    mkdir -p "$target_dir/content_discovery/files" 2>/dev/null
    mkdir -p "$target_dir/content_discovery/api" 2>/dev/null
    mkdir -p "$target_dir/content_discovery/js" 2>/dev/null
    
    output_file="$target_dir/content_discovery/directories/discovered_directories.txt"
    interesting_file="$target_dir/content_discovery/directories/interesting_findings.txt"
    api_endpoints_file="$target_dir/content_discovery/api/api_endpoints.txt"
    js_file_list="$target_dir/content_discovery/js/js_files.txt"
    sensitive_data_file="$target_dir/content_discovery/sensitive_data.txt"
    
    # Initialize files
    > "$output_file"
    > "$interesting_file"
    > "$api_endpoints_file"
    > "$js_file_list"
    > "$sensitive_data_file"
    
    echo "# Interesting Content Findings" > "$interesting_file"
    echo "## Generated on: $(date)" >> "$interesting_file"
    echo "" >> "$interesting_file"
    
    # Define list of potentially interesting file extensions and paths
    interesting_extensions=("php" "asp" "aspx" "jsp" "jspx" "do" "action" "json" "xml" "conf" "config" "bak" "backup" "swp" "old" "db" "sql" "ini" "log" "env" "yml" "yaml" "txt" "bak~" "swp" "_" ".DS_Store" ".git" ".svn" ".htaccess" "wp-config.php" "config.php" "database.yml" "credentials.xml" "id_rsa" "id_dsa")
    
    # Define list of interesting directories
    interesting_dirs=("admin" "administrator" "backup" "backups" "config" "dashboard" "db" "debug" "default" "dev" "develop" "developer" "development" "log" "login" "logs" "old" "panel" "php" "phpmyadmin" "private" "root" "secret" "secrets" "secure" "security" "setup" "sql" "staging" "storage" "temp" "test" "tests" "tmp" "upload" "uploads" "web" "wp-admin" "wp-content" "wp-includes" "api" "v1" "v2" "auth" "login" "users" "admin" "console" ".well-known" ".git" ".svn" ".env" ".config" ".vscode" ".idea")
    
    # API-specific endpoint patterns
    api_patterns=("api" "v1" "v2" "v3" "graphql" "graphiql" "swagger" "docs" "openapi" "rest" "auth" "oauth" "token" "users" "accounts" "data" "service" "services" "endpoint" "endpoints")
    
    # Check for different content discovery tools
    if command_exists ffuf; then
        log_message "Using ffuf for advanced directory and file discovery..." "INFO"
        
        # Create wordlists
        mkdir -p "$target_dir/.tmp/wordlists" 2>/dev/null
        
        # Directory wordlist
        dir_wordlist="$target_dir/.tmp/wordlists/directory_wordlist.txt"
        # File extension wordlist
        ext_wordlist="$target_dir/.tmp/wordlists/extension_wordlist.txt"
        # API endpoint wordlist
        api_wordlist="$target_dir/.tmp/wordlists/api_wordlist.txt"
        
        # Check if common wordlists exist
        found_wordlist=false
        if [[ -f "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ]]; then
            wordlist_file="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            found_wordlist=true
        elif [[ -f "/usr/share/seclists/Discovery/Web-Content/common.txt" ]]; then
            wordlist_file="/usr/share/seclists/Discovery/Web-Content/common.txt"
            found_wordlist=true
        else
            # Create a basic wordlist with common directories
            log_message "No wordlist found. Creating a small basic wordlist." "WARNING"
            cat > "$wordlist_file" << EOF
admin
wp-admin
login
administrator
phpmyadmin
dashboard
api
upload
uploads
backup
backups
dev
test
staging
wp-content
wp-includes
images
img
css
js
static
assets
public
private
config
include
includes
logs
log
docs
documentation
downloads
database
db
install
tmp
temp
scripts
v1
v2
api/v1
api/v2
manage
management
EOF
            log_message "Created basic wordlist with common directories" "INFO"
        fi
        
        # Run ffuf with the selected wordlist
        log_message "Running ffuf with wordlist: $wordlist_file" "INFO"
        
        ffuf -u "https://$target/FUZZ" -w "$wordlist_file" -mc 200,204,301,302,307,403 -o "$output_file.json" -of json > /dev/null 2>&1
        
        # Parse ffuf output if it exists
        if [[ -f "$output_file.json" ]]; then
            jq -r '.results[].url' "$output_file.json" | sort -u > "$output_file"
            dir_count=$(wc -l < "$output_file")
            log_message "Directory brute force completed. Found $dir_count potential directories." "SUCCESS"
            
            # Clean up temporary file
            if [[ "$found_wordlist" == false ]]; then
                rm -f "$wordlist_file" 2>/dev/null
            fi
        else
            log_message "ffuf did not produce any output." "WARNING"
            echo "No directories found" > "$output_file"
        fi
    elif command_exists gobuster; then
        log_message "Using gobuster for directory brute force..." "INFO"
        
        # Create a wordlist if it doesn't exist
        wordlist_file="$target_dir/.tmp/wordlist.txt"
        mkdir -p "$target_dir/.tmp" 2>/dev/null
        
        # Check if common wordlists exist
        found_wordlist=false
        if [[ -f "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" ]]; then
            wordlist_file="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            found_wordlist=true
        elif [[ -f "/usr/share/seclists/Discovery/Web-Content/common.txt" ]]; then
            wordlist_file="/usr/share/seclists/Discovery/Web-Content/common.txt"
            found_wordlist=true
        else
            # Create a basic wordlist with common directories
            log_message "No wordlist found. Creating a small basic wordlist." "WARNING"
            cat > "$wordlist_file" << EOF
admin
wp-admin
login
administrator
phpmyadmin
dashboard
api
upload
uploads
backup
backups
dev
test
staging
wp-content
wp-includes
images
img
css
js
static
assets
public
private
config
include
includes
logs
log
docs
documentation
downloads
database
db
install
tmp
temp
scripts
v1
v2
api/v1
api/v2
manage
management
EOF
            log_message "Created basic wordlist with common directories" "INFO"
        fi
        
        # Run gobuster with the selected wordlist
        log_message "Running gobuster with wordlist: $wordlist_file" "INFO"
        
        gobuster dir -u "https://$target" -w "$wordlist_file" -o "$output_file.tmp" > /dev/null 2>&1
        
        # Parse gobuster output if it exists
        if [[ -f "$output_file.tmp" ]]; then
            grep "Status: 20" "$output_file.tmp" | awk '{print $1}' > "$output_file"
            grep "Status: 30" "$output_file.tmp" | awk '{print $1}' >> "$output_file"
            grep "Status: 403" "$output_file.tmp" | awk '{print $1}' >> "$output_file"
            
            dir_count=$(wc -l < "$output_file")
            log_message "Directory brute force completed. Found $dir_count potential directories." "SUCCESS"
            
            # Clean up temporary files
            rm -f "$output_file.tmp" 2>/dev/null
            if [[ "$found_wordlist" == false ]]; then
                rm -f "$wordlist_file" 2>/dev/null
            fi
        else
            log_message "gobuster did not produce any output." "WARNING"
            echo "No directories found" > "$output_file"
        fi
    else
        log_message "No directory fuzzing tools found. Using curl for basic content discovery..." "WARNING"
        
        # Create a basic wordlist with common directories
        wordlist_file="$target_dir/.tmp/wordlist.txt"
        mkdir -p "$target_dir/.tmp" 2>/dev/null
        cat > "$wordlist_file" << EOF
admin
wp-admin
login
administrator
phpmyadmin
dashboard
api
upload
uploads
backup
backups
dev
test
staging
wp-content
wp-includes
images
img
css
js
static
assets
public
private
config
include
includes
logs
log
docs
documentation
downloads
database
db
install
tmp
temp
scripts
v1
v2
api/v1
api/v2
manage
management
EOF
        log_message "Created basic wordlist with common directories" "INFO"
        
        # Initialize output file
        > "$output_file"
        
        # Check each path with curl
        while read -r path; do
            url="https://$target/$path"
            status_code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
            
            if [[ "$status_code" == "200" || "$status_code" == "301" || "$status_code" == "302" || "$status_code" == "403" ]]; then
                echo "$url (Status: $status_code)" >> "$output_file"
                log_message "Found: $url (Status: $status_code)" "INFO"
            fi
        done < "$wordlist_file"
        
        dir_count=$(wc -l < "$output_file")
        log_message "Basic directory discovery completed. Found $dir_count potential directories." "INFO"
        
        # Clean up temporary file
        rm -f "$wordlist_file" 2>/dev/null
    fi
    
    end_function "directory_bruteforce" $?
}

# Function to find sensitive files
function sensitive_files() {
    if is_completed "sensitive_files"; then
        log_message "Sensitive files check already completed for $target" "INFO"
        return 0
    fi
    
    start_function "sensitive_files" "Sensitive Files Check for $target"
    
    mkdir -p "$target_dir/directories" 2>/dev/null
    output_file="$target_dir/directories/sensitive_files.txt"
    
    # Initialize output file
    echo "Sensitive Files Check for $target" > "$output_file"
    echo "==============================================" >> "$output_file"
    echo "" >> "$output_file"
    
    # List of sensitive files to check
    sensitive_files=()
    
    # Get the script path for relative references
    script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."
    custom_wordlist="${script_path}/modules/wordlists/sensitive_files.txt"
    
    # Check if custom sensitive files wordlist exists
    if [[ -f "$custom_wordlist" ]]; then
        log_message "Using custom sensitive files wordlist: $custom_wordlist" "INFO"
        
        # Read wordlist and add entries to sensitive_files array
        while IFS= read -r file || [[ -n "$file" ]]; do
            # Skip comments and empty lines
            [[ "${file}" =~ ^#.*$ || -z "${file}" ]] && continue
            
            # Add the file path to the array
            sensitive_files+=("/$file")
        done < "$custom_wordlist"
        
        log_message "Loaded $(echo ${#sensitive_files[@]}) sensitive files from wordlist" "INFO"
    else
        log_message "Custom sensitive files wordlist not found. Using default list." "WARNING"
        
        # Default list of sensitive files to check if wordlist is not available
        sensitive_files=(
            # Configuration files
            "/.env"
            "/.env.backup"
            "/.env.dev"
            "/.env.local"
            "/config.php"
            "/config.js"
            "/config.json"
            "/database.yml"
            "/wp-config.php"
            "/wp-config.bak"
            "/web.config"
            
            # Backup files
            "/backup.sql"
            "/backup.zip"
            "/backup.tar.gz"
            "/db_backup.sql"
            "/database.sql"
            
            # Git repositories
            "/.git/HEAD"
            "/.git/config"
            
            # Log files
            "/log.txt"
            "/error_log"
            "/debug.log"
            "/access.log"
            
            # Information disclosure
            "/phpinfo.php"
            "/info.php"
            "/server-status"
            "/server-info"
            
            # API documentation
            "/api/docs"
            "/swagger"
            "/swagger-ui.html"
            "/api-docs"
            "/graphql"
            
            # Common CMS files
            "/wp-login.php"
            "/administrator/index.php"
            "/admin.php"
            "/login.php"
            "/admin/login"
        )
    fi
    
    # Check each sensitive file
    found_files=0
    
    for file in "${sensitive_files[@]}"; do
        url="https://$target$file"
        status_code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
        
        if [[ "$status_code" == "200" ]]; then
            echo "[FOUND] $url (Status: $status_code)" >> "$output_file"
            log_message "Found sensitive file: $url" "WARNING"
            ((found_files++))
        elif [[ "$status_code" == "403" ]]; then
            echo "[RESTRICTED] $url (Status: $status_code)" >> "$output_file"
            log_message "Found restricted file: $url" "INFO"
            ((found_files++))
        elif [[ "$status_code" == "301" || "$status_code" == "302" ]]; then
            redirect_url=$(curl -s -I "$url" | grep -i "Location:" | cut -d " " -f2- | tr -d '\r')
            echo "[REDIRECT] $url -> $redirect_url (Status: $status_code)" >> "$output_file"
            log_message "Found redirect: $url -> $redirect_url" "INFO"
            ((found_files++))
        fi
    done
    
    log_message "Sensitive files check completed. Found $found_files potentially sensitive files." "SUCCESS"
    
    end_function "sensitive_files" $?
}

# Function to find JavaScript files
function javascript_files() {
    if is_completed "javascript_files"; then
        log_message "JavaScript files discovery already completed for $target" "INFO"
        return 0
    fi
    
    start_function "javascript_files" "JavaScript Files Discovery for $target"
    
    mkdir -p "$target_dir/directories/js" 2>/dev/null
    output_file="$target_dir/directories/javascript_files.txt"
    
    # Initialize output file
    echo "JavaScript Files for $target" > "$output_file"
    echo "==============================================" >> "$output_file"
    echo "" >> "$output_file"
    
    # First, check if waybackurls is available
    if command_exists waybackurls; then
        log_message "Using waybackurls to find JavaScript files..." "INFO"
        
        echo "$target" | waybackurls 2>/dev/null | grep "\.js$" | sort -u > "$target_dir/.tmp_js_files.txt"
        
        if [[ -s "$target_dir/.tmp_js_files.txt" ]]; then
            cat "$target_dir/.tmp_js_files.txt" >> "$output_file"
            js_count=$(wc -l < "$target_dir/.tmp_js_files.txt")
            log_message "Found $js_count JavaScript files from Wayback Machine" "SUCCESS"
            
            # Download some JS files for analysis
            mkdir -p "$target_dir/directories/js/downloaded" 2>/dev/null
            
            log_message "Downloading JavaScript files for analysis..." "INFO"
            head -n 10 "$target_dir/.tmp_js_files.txt" | while read -r js_url; do
                js_filename=$(basename "$js_url")
                curl -s "$js_url" > "$target_dir/directories/js/downloaded/$js_filename" 2>/dev/null
                
                # Check for potential sensitive information in the JavaScript file
                if grep -q -E "api_key|apiKey|key|token|secret|password|credentials" "$target_dir/directories/js/downloaded/$js_filename"; then
                    log_message "Potential sensitive data found in $js_filename" "WARNING"
                    echo "[SENSITIVE] $js_url" >> "$output_file"
                    
                    # Extract potential API keys and sensitive values
                    grep -E "api_key|apiKey|key|token|secret|password|credentials" "$target_dir/directories/js/downloaded/$js_filename" > "$target_dir/directories/js/downloaded/$js_filename.sensitive"
                fi
            done
        else
            log_message "No JavaScript files found with waybackurls" "WARNING"
        fi
        
        # Clean up temporary file
        rm -f "$target_dir/.tmp_js_files.txt" 2>/dev/null
    else
        log_message "waybackurls not found. Using basic curl to find JavaScript files..." "WARNING"
        
        # Use curl to get the main page and extract JavaScript files
        log_message "Finding JavaScript files on http://$target using curl" "INFO"
        curl -s "http://$target" | grep -o '<script src="[^"]*\.js[^"]*"' | grep -o '"[^"]*"' | tr -d '"' > "$target_dir/.tmp_js_files.txt"
        
        log_message "Finding JavaScript files on https://$target using curl" "INFO"
        curl -s "https://$target" | grep -o '<script src="[^"]*\.js[^"]*"' | grep -o '"[^"]*"' | tr -d '"' >> "$target_dir/.tmp_js_files.txt"
        
        if [[ -s "$target_dir/.tmp_js_files.txt" ]]; then
            cat "$target_dir/.tmp_js_files.txt" | sort -u >> "$output_file"
            js_count=$(wc -l < "$target_dir/.tmp_js_files.txt" | sort -u)
            log_message "Found $js_count JavaScript files" "SUCCESS"
            
            # Download some JS files for analysis
            mkdir -p "$target_dir/directories/js/downloaded" 2>/dev/null
            
            log_message "Downloading JavaScript files for analysis..." "INFO"
            while read -r js_path; do
                # Check if it's a full URL or just a path
                if [[ "$js_path" == http* ]]; then
                    js_url="$js_path"
                else
                    # Prepend with target domain if it's a relative path
                    js_url="https://$target$js_path"
                fi
                
                js_filename=$(basename "$js_path")
                curl -s "$js_url" > "$target_dir/directories/js/downloaded/$js_filename" 2>/dev/null
                
                # Check for potential sensitive information in the JavaScript file
                if grep -q -E "api_key|apiKey|key|token|secret|password|credentials" "$target_dir/directories/js/downloaded/$js_filename"; then
                    log_message "Potential sensitive data found in $js_filename" "WARNING"
                    echo "[SENSITIVE] $js_url" >> "$output_file"
                    
                    # Extract potential API keys and sensitive values
                    grep -E "api_key|apiKey|key|token|secret|password|credentials" "$target_dir/directories/js/downloaded/$js_filename" > "$target_dir/directories/js/downloaded/$js_filename.sensitive"
                fi
            done < "$target_dir/.tmp_js_files.txt"
        else
            log_message "No JavaScript files found" "WARNING"
            echo "No JavaScript files found" >> "$output_file"
        fi
        
        # Clean up temporary file
        rm -f "$target_dir/.tmp_js_files.txt" 2>/dev/null
    fi
    
    end_function "javascript_files" $?
}

# Function to analyze interesting parameters
function interesting_parameters() {
    if is_completed "interesting_parameters"; then
        log_message "Interesting parameters analysis already completed for $target" "INFO"
        return 0
    fi
    
    start_function "interesting_parameters" "Interesting Parameters Analysis for $target"
    
    mkdir -p "$target_dir/directories/parameters" 2>/dev/null
    output_file="$target_dir/directories/interesting_parameters.txt"
    
    # Initialize output file
    echo "Interesting Parameters for $target" > "$output_file"
    echo "==============================================" >> "$output_file"
    echo "" >> "$output_file"
    
    # List of potentially vulnerable parameters
    vulnerable_params=(
        "id"
        "page"
        "file"
        "path"
        "url"
        "redirect"
        "return_url"
        "next"
        "redir"
        "redirect_uri"
        "return"
        "src"
        "source"
        "dir"
        "display"
        "view"
        "template"
        "search"
        "query"
        "data"
        "user"
        "username"
        "email"
        "type"
        "sql"
        "debug"
        "admin"
        "order"
        "sort"
        "cmd"
        "exec"
        "command"
        "action"
        "read"
        "upload"
        "show"
        "download"
        "log"
        "ip"
        "api_key"
        "key"
        "token"
    )
    
    log_message "Searching for URLs with interesting parameters..." "INFO"
    
    # First check if we have waybackurls or gau to find URLs
    if command_exists waybackurls || command_exists gau; then
        # Create a temporary file to store all URLs
        all_urls_file="$target_dir/.tmp_all_urls.txt"
        > "$all_urls_file"
        
        if command_exists waybackurls; then
            log_message "Using waybackurls to find URLs with parameters..." "INFO"
            echo "$target" | waybackurls 2>/dev/null >> "$all_urls_file"
        fi
        
        if command_exists gau; then
            log_message "Using gau to find URLs with parameters..." "INFO"
            echo "$target" | gau 2>/dev/null >> "$all_urls_file"
        fi
        
        # Filter URLs with parameters
        grep -E "(\?|\&)([^=]+)=" "$all_urls_file" | sort -u > "$target_dir/.tmp_urls_with_params.txt"
        
        # Check if we found any URLs with parameters
        if [[ -s "$target_dir/.tmp_urls_with_params.txt" ]]; then
            # Find interesting parameters
            for param in "${vulnerable_params[@]}"; do
                # Find URLs containing this parameter
                grep -i "[?&]$param=" "$target_dir/.tmp_urls_with_params.txt" > "$target_dir/.tmp_param_$param.txt"
                
                if [[ -s "$target_dir/.tmp_param_$param.txt" ]]; then
                    param_count=$(wc -l < "$target_dir/.tmp_param_$param.txt")
                    echo "Parameter: $param ($param_count URLs)" >> "$output_file"
                    cat "$target_dir/.tmp_param_$param.txt" >> "$output_file"
                    echo "" >> "$output_file"
                    
                    log_message "Found $param_count URLs with parameter '$param'" "INFO"
                fi
                
                # Clean up temporary file
                rm -f "$target_dir/.tmp_param_$param.txt" 2>/dev/null
            done
        else
            log_message "No URLs with parameters found" "WARNING"
            echo "No URLs with parameters found" >> "$output_file"
        fi
        
        # Clean up temporary files
        rm -f "$all_urls_file" "$target_dir/.tmp_urls_with_params.txt" 2>/dev/null
    else
        log_message "Neither waybackurls nor gau is available. Using basic methods..." "WARNING"
        
        # Use curl to get the main page and extract potential URLs with parameters
        log_message "Checking main page for URLs with parameters..." "INFO"
        curl -s "https://$target" | grep -o 'href="[^"]*?[^"]*"' | grep -o '"[^"]*"' | tr -d '"' | grep "?" > "$target_dir/.tmp_urls_with_params.txt"
        
        # Check if we found any URLs with parameters
        if [[ -s "$target_dir/.tmp_urls_with_params.txt" ]]; then
            # Find interesting parameters
            for param in "${vulnerable_params[@]}"; do
                # Find URLs containing this parameter
                grep -i "[?&]$param=" "$target_dir/.tmp_urls_with_params.txt" > "$target_dir/.tmp_param_$param.txt"
                
                if [[ -s "$target_dir/.tmp_param_$param.txt" ]]; then
                    param_count=$(wc -l < "$target_dir/.tmp_param_$param.txt")
                    echo "Parameter: $param ($param_count URLs)" >> "$output_file"
                    cat "$target_dir/.tmp_param_$param.txt" >> "$output_file"
                    echo "" >> "$output_file"
                    
                    log_message "Found $param_count URLs with parameter '$param'" "INFO"
                fi
                
                # Clean up temporary file
                rm -f "$target_dir/.tmp_param_$param.txt" 2>/dev/null
            done
        else
            log_message "No URLs with parameters found on main page" "WARNING"
            echo "No URLs with parameters found" >> "$output_file"
        fi
        
        # Clean up temporary files
        rm -f "$target_dir/.tmp_urls_with_params.txt" 2>/dev/null
    fi
    
    end_function "interesting_parameters" $?
}

# Main function to run the content discovery module
function run_content_discovery_module() {
    # Create necessary directories
    mkdir -p "$target_dir/directories" 2>/dev/null
    mkdir -p "$CALLED_FN_DIR" 2>/dev/null
    chmod 755 "$CALLED_FN_DIR" 2>/dev/null
    
    # Show banner
    show_content_discovery_banner
    
    # Run content discovery functions
    directory_bruteforce
    sensitive_files
    javascript_files
    interesting_parameters
    
    # Clean up temp files
    rm -rf "${target_dir}/.tmp" 2>/dev/null
    
    log_message "Content discovery module completed for $target" "SUCCESS"
}

# Export functions
export -f directory_bruteforce
export -f sensitive_files
export -f javascript_files
export -f interesting_parameters
export -f run_content_discovery_module