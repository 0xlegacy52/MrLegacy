#!/bin/bash

# MR Legacy - Tool Check Functions
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.1.0

# List of essential tools with corresponding package names
declare -A ESSENTIAL_TOOLS=(
    ["curl"]="curl"
    ["grep"]="grep"
    ["awk"]="gawk"
    ["sed"]="sed"
    ["timeout"]="coreutils"
)

# List of recommended but not essential tools
declare -A RECOMMENDED_TOOLS=(
    ["dig"]="dnsutils"
    ["whois"]="whois"
    ["nslookup"]="dnsutils"
)

# List of useful tools with corresponding package names
declare -A USEFUL_TOOLS=(
    ["nmap"]="nmap"
    ["whatweb"]="whatweb"
    ["subfinder"]="subfinder"
    ["assetfinder"]="assetfinder"
    ["httprobe"]="httprobe"
    ["httpx"]="httpx"
    ["waybackurls"]="waybackurls"
    ["gau"]="gau"
    ["nuclei"]="nuclei"
    ["gobuster"]="gobuster"
    ["ffuf"]="ffuf"
    ["masscan"]="masscan"
    ["sqlmap"]="sqlmap"
    ["wfuzz"]="wfuzz"
    ["amass"]="amass"
    ["jq"]="jq"
    ["tor"]="tor"
    ["proxychains"]="proxychains"
)

# Function to check for essential tools
function check_essential_tools() {
    log_message "Checking for essential tools..." "INFO"
    
    local missing_tools=()
    
    for tool in "${!ESSENTIAL_TOOLS[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
            log_message "Essential tool '$tool' is missing" "WARNING"
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_message "Some essential tools are missing. The script may not function correctly." "WARNING"
        
        if [[ "$(id -u)" -eq 0 ]]; then
            log_message "Running as root, attempting to install missing tools..." "INFO"
            
            # Detect package manager
            if command_exists "apt-get"; then
                local pkgman="apt-get"
                local install_cmd="apt-get install -y"
            elif command_exists "apk"; then
                local pkgman="apk"
                local install_cmd="apk add"
            elif command_exists "yum"; then
                local pkgman="yum"
                local install_cmd="yum install -y"
            elif command_exists "dnf"; then
                local pkgman="dnf"
                local install_cmd="dnf install -y"
            elif command_exists "pacman"; then
                local pkgman="pacman"
                local install_cmd="pacman -S --noconfirm"
            else
                log_message "Could not detect package manager. Please install missing tools manually." "ERROR"
                return 1
            fi
            
            # Update package list
            log_message "Updating package list..." "INFO"
            if [[ "$pkgman" == "apt-get" ]]; then
                apt-get update -q
            elif [[ "$pkgman" == "apk" ]]; then
                apk update
            elif [[ "$pkgman" == "pacman" ]]; then
                pacman -Sy
            fi
            
            # Install missing tools
            for tool in "${missing_tools[@]}"; do
                local package="${ESSENTIAL_TOOLS[$tool]}"
                log_message "Installing $tool (package: $package)..." "INFO"
                $install_cmd $package
                
                # Check if installation was successful
                if ! command_exists "$tool"; then
                    log_message "Failed to install $tool" "ERROR"
                else
                    log_message "Successfully installed $tool" "SUCCESS"
                fi
            done
        else
            log_message "Not running as root, cannot automatically install missing tools" "WARNING"
            log_message "Please install the following tools: ${missing_tools[*]}" "INFO"
            log_message "For Debian/Ubuntu: sudo apt-get install ${ESSENTIAL_TOOLS[*]}" "INFO"
            log_message "For Alpine: sudo apk add ${ESSENTIAL_TOOLS[*]}" "INFO"
            log_message "For RHEL/CentOS: sudo yum install ${ESSENTIAL_TOOLS[*]}" "INFO"
            log_message "For Arch: sudo pacman -S ${ESSENTIAL_TOOLS[*]}" "INFO"
        fi
    else
        log_message "All essential tools are installed" "SUCCESS"
    fi
    
    # Check for recommended tools
    log_message "Checking for recommended tools..." "INFO"
    
    local missing_recommended=()
    
    for tool in "${!RECOMMENDED_TOOLS[@]}"; do
        if ! command_exists "$tool"; then
            missing_recommended+=("$tool")
            log_message "Recommended tool '$tool' is missing" "INFO"
        fi
    done
    
    if [[ ${#missing_recommended[@]} -gt 0 ]]; then
        log_message "Some recommended tools are missing. Some features will use fallback methods." "INFO"
        
        if [[ "$VERBOSE" == true ]]; then
            log_message "Missing recommended tools: ${missing_recommended[*]}" "INFO"
            log_message "For Debian/Ubuntu: sudo apt-get install dnsutils whois" "INFO"
        fi
    else
        log_message "All recommended tools are installed" "SUCCESS"
    fi
}

# Function to check for useful tools
function check_useful_tools() {
    log_message "Checking for useful tools..." "INFO"
    
    local missing_tools=()
    local count=0
    local total=${#USEFUL_TOOLS[@]}
    
    for tool in "${!USEFUL_TOOLS[@]}"; do
        if command_exists "$tool"; then
            ((count++))
            if [[ "$VERBOSE" == true ]]; then
                log_message "Found useful tool: $tool" "INFO"
            fi
        else
            missing_tools+=("$tool")
            if [[ "$VERBOSE" == true ]]; then
                log_message "Useful tool '$tool' is not installed" "DEBUG"
            fi
        fi
    done
    
    local percentage=$((count * 100 / total))
    
    log_message "Found $count out of $total useful tools ($percentage%)" "INFO"
    
    if [[ ${#missing_tools[@]} -gt 0 && "$VERBOSE" == true ]]; then
        log_message "Missing useful tools: ${missing_tools[*]}" "DEBUG"
        log_message "These tools are optional but can enhance the script's capabilities" "INFO"
    fi
    
    # Return true if at least 50% of useful tools are available
    [[ $percentage -ge 50 ]]
}

# Function to check if Tor proxy is set up correctly
function check_tor_proxy() {
    if [[ "$TOR" != true ]]; then
        # Tor is not enabled, so no need to check
        return 0
    fi
    
    log_message "Checking Tor proxy setup..." "INFO"
    
    # Check if Tor is installed
    if ! command_exists "tor"; then
        log_message "Tor is not installed. Please install Tor to use Tor proxy feature." "ERROR"
        return 1
    fi
    
    # Check if Tor service is running
    if pgrep -x "tor" >/dev/null; then
        log_message "Tor service is running" "SUCCESS"
    else
        log_message "Tor service is not running. Attempting to start..." "WARNING"
        
        # Attempt to start Tor
        if [[ "$(id -u)" -eq 0 ]]; then
            # Running as root, try service commands
            if command_exists "systemctl"; then
                systemctl start tor
            elif command_exists "service"; then
                service tor start
            else
                tor &
            fi
        else
            # Not running as root, just try to start tor in background
            tor &
        fi
        
        # Wait a bit and check again
        sleep 3
        
        if pgrep -x "tor" >/dev/null; then
            log_message "Successfully started Tor service" "SUCCESS"
        else
            log_message "Failed to start Tor service. Please start it manually." "ERROR"
            log_message "Run: sudo systemctl start tor" "INFO"
            return 1
        fi
    fi
    
    # Check if Tor proxy is accessible
    if curl --socks5 127.0.0.1:9050 --socks5-hostname 127.0.0.1:9050 -s https://check.torproject.org/ | grep -q "Congratulations"; then
        log_message "Tor proxy is working correctly" "SUCCESS"
        return 0
    else
        log_message "Tor proxy is not working correctly. Please check your Tor configuration." "ERROR"
        return 1
    fi
}

# Function to check for Python and its modules
function check_python() {
    log_message "Checking for Python..." "INFO"
    
    # Check for Python 3
    if command_exists "python3"; then
        local python="python3"
    elif command_exists "python" && python --version 2>&1 | grep -q "Python 3"; then
        local python="python"
    else
        log_message "Python 3 is not installed. Some features may not work." "WARNING"
        return 1
    fi
    
    log_message "Found Python: $($python --version 2>&1)" "INFO"
    
    # Check for essential Python modules
    local modules=("requests" "argparse" "json" "concurrent.futures")
    local missing_modules=()
    
    for module in "${modules[@]}"; do
        if ! $python -c "import $module" 2>/dev/null; then
            missing_modules+=("$module")
            log_message "Python module '$module' is missing" "WARNING"
        fi
    done
    
    if [[ ${#missing_modules[@]} -gt 0 ]]; then
        log_message "Some essential Python modules are missing" "WARNING"
        
        # Check for pip
        if command_exists "pip3"; then
            local pip="pip3"
        elif command_exists "pip"; then
            local pip="pip"
        else
            log_message "pip is not installed. Cannot install Python modules." "ERROR"
            log_message "Please install pip and then run: pip install ${missing_modules[*]}" "INFO"
            return 1
        fi
        
        # Try to install modules without sudo first
        log_message "Attempting to install missing Python modules..." "INFO"
        for module in "${missing_modules[@]}"; do
            log_message "Installing Python module: $module" "INFO"
            
            # Try user installation first
            $pip install --user $module >/dev/null 2>&1
            
            # Check if installation was successful
            if ! $python -c "import $module" 2>/dev/null; then
                # Try system-wide installation if user installation failed
                if [[ "$(id -u)" -eq 0 ]]; then
                    $pip install $module >/dev/null 2>&1
                    
                    # Check again
                    if ! $python -c "import $module" 2>/dev/null; then
                        log_message "Failed to install Python module: $module" "ERROR"
                    else
                        log_message "Successfully installed Python module: $module" "SUCCESS"
                    fi
                else
                    log_message "Failed to install Python module: $module" "WARNING"
                    log_message "You may need to manually install it with: pip install $module" "INFO"
                fi
            else
                log_message "Successfully installed Python module: $module" "SUCCESS"
            fi
        done
    else
        log_message "All essential Python modules are installed" "SUCCESS"
    fi
    
    return 0
}

# Main function to run all checks
function run_tool_checks() {
    log_message "Running tool environment checks..." "INFO"
    
    # Create a temporary directory for checks
    mkdir -p "${target_dir}/.tmp" 2>/dev/null
    
    # Run the checks
    check_essential_tools
    check_useful_tools
    check_python
    
    if [[ "$TOR" == true ]]; then
        check_tor_proxy
    fi
    
    log_message "Tool environment checks completed" "INFO"
}

# Export the functions
export -f check_essential_tools
export -f check_useful_tools
export -f check_tor_proxy
export -f check_python
export -f run_tool_checks