#!/bin/bash

# MR Legacy - Tool Installation Script
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.1.0

# Source helper functions if available
if [[ -f "utils/helpers.sh" ]]; then
    source "utils/helpers.sh"
else
    # Simple log message function if helpers.sh is not available
    function log_message() {
        local message="$1"
        local level="${2:-INFO}"
        local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        
        # Define colors
        local GREEN="\033[0;32m"
        local YELLOW="\033[0;33m"
        local RED="\033[0;31m"
        local BLUE="\033[0;34m"
        local PURPLE="\033[0;35m"
        local CYAN="\033[0;36m"
        local NC="\033[0m" # No Color
        
        # Print colored output
        case "$level" in
            "DEBUG")
                echo -e "${BLUE}[$timestamp] [DEBUG] $message${NC}" ;;
            "INFO")
                echo -e "${GREEN}[$timestamp] [INFO] $message${NC}" ;;
            "WARNING")
                echo -e "${YELLOW}[$timestamp] [WARNING] $message${NC}" ;;
            "ERROR")
                echo -e "${RED}[$timestamp] [ERROR] $message${NC}" ;;
            "SUCCESS")
                echo -e "${CYAN}[$timestamp] [SUCCESS] $message${NC}" ;;
            "CRITICAL")
                echo -e "${PURPLE}[$timestamp] [CRITICAL] $message${NC}" ;;
            *)
                echo -e "[$timestamp] [$level] $message" ;;
        esac
    }
    
    # Simple function to check if command exists
    function command_exists() {
        command -v "$1" >/dev/null 2>&1
    }
fi

# Function to detect the package manager
function detect_package_manager() {
    if command_exists apt-get; then
        echo "apt"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists yum; then
        echo "yum"
    elif command_exists pacman; then
        echo "pacman"
    elif command_exists zypper; then
        echo "zypper"
    else
        echo "unknown"
    fi
}

# Function to install packages using the appropriate package manager
function install_package() {
    local package="$1"
    local package_manager=$(detect_package_manager)
    
    case "$package_manager" in
        "apt")
            sudo apt-get update && sudo apt-get install -y "$package"
            ;;
        "dnf")
            sudo dnf install -y "$package"
            ;;
        "yum")
            sudo yum install -y "$package"
            ;;
        "pacman")
            sudo pacman -S --noconfirm "$package"
            ;;
        "zypper")
            sudo zypper install -y "$package"
            ;;
        *)
            log_message "Unknown package manager. Please install $package manually." "ERROR"
            return 1
            ;;
    esac
    
    return $?
}

# Function to install Python packages
function install_pip_package() {
    local package="$1"
    
    if ! command_exists pip3; then
        log_message "pip3 is not installed. Installing..." "INFO"
        install_package "python3-pip"
    fi
    
    log_message "Installing Python package: $package" "INFO"
    pip3 install --user "$package"
    
    return $?
}

# Function to install Go packages
function install_go_package() {
    local package="$1"
    
    if ! command_exists go; then
        log_message "Go is not installed. Installing..." "INFO"
        install_package "golang"
    fi
    
    log_message "Installing Go package: $package" "INFO"
    go install "$package"@latest
    
    return $?
}

# Function to install Nmap
function install_nmap() {
    log_message "Installing Nmap..." "INFO"
    install_package "nmap"
    
    if command_exists nmap; then
        log_message "Nmap installed successfully" "SUCCESS"
        return 0
    else
        log_message "Failed to install Nmap" "ERROR"
        return 1
    fi
}

# Function to install Masscan
function install_masscan() {
    log_message "Installing Masscan..." "INFO"
    
    if command_exists git; then
        git clone https://github.com/robertdavidgraham/masscan
        cd masscan
        make
        sudo make install
        cd ..
        rm -rf masscan
        
        if command_exists masscan; then
            log_message "Masscan installed successfully" "SUCCESS"
            return 0
        else
            log_message "Failed to install Masscan" "ERROR"
            return 1
        fi
    else
        log_message "Git is required to install Masscan" "ERROR"
        return 1
    fi
}

# Function to install Nuclei
function install_nuclei() {
    log_message "Installing Nuclei..." "INFO"
    
    install_go_package "github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    
    if command_exists nuclei; then
        log_message "Nuclei installed successfully" "SUCCESS"
        return 0
    else
        log_message "Failed to install Nuclei. Updating PATH to include Go binaries..." "WARNING"
        
        # Try to find the Go bin directory and add it to PATH
        local go_bin=$(go env GOPATH)/bin
        if [[ -d "$go_bin" ]]; then
            export PATH="$PATH:$go_bin"
            log_message "Added $go_bin to PATH" "INFO"
            
            if command_exists nuclei; then
                log_message "Nuclei installation verified successfully" "SUCCESS"
                return 0
            fi
        fi
        
        log_message "Failed to install Nuclei. Make sure your Go environment is set up correctly." "ERROR"
        return 1
    fi
}

# Function to install WaybackUrls
function install_waybackurls() {
    log_message "Installing WaybackUrls..." "INFO"
    
    install_go_package "github.com/tomnomnom/waybackurls"
    
    if command_exists waybackurls; then
        log_message "WaybackUrls installed successfully" "SUCCESS"
        return 0
    else
        # Try to find it in the Go bin directory
        local go_bin=$(go env GOPATH)/bin
        if [[ -f "$go_bin/waybackurls" ]]; then
            export PATH="$PATH:$go_bin"
            log_message "Added $go_bin to PATH" "INFO"
            
            if command_exists waybackurls; then
                log_message "WaybackUrls installation verified successfully" "SUCCESS"
                return 0
            fi
        fi
        
        log_message "Failed to install WaybackUrls" "ERROR"
        return 1
    fi
}

# Function to install Assetfinder
function install_assetfinder() {
    log_message "Installing Assetfinder..." "INFO"
    
    install_go_package "github.com/tomnomnom/assetfinder"
    
    if command_exists assetfinder; then
        log_message "Assetfinder installed successfully" "SUCCESS"
        return 0
    else
        # Try to find it in the Go bin directory
        local go_bin=$(go env GOPATH)/bin
        if [[ -f "$go_bin/assetfinder" ]]; then
            export PATH="$PATH:$go_bin"
            log_message "Added $go_bin to PATH" "INFO"
            
            if command_exists assetfinder; then
                log_message "Assetfinder installation verified successfully" "SUCCESS"
                return 0
            fi
        fi
        
        log_message "Failed to install Assetfinder" "ERROR"
        return 1
    fi
}

# Function to install Amass
function install_amass() {
    log_message "Installing Amass..." "INFO"
    
    install_go_package "github.com/owasp-amass/amass/v4/..."
    
    if command_exists amass; then
        log_message "Amass installed successfully" "SUCCESS"
        return 0
    else
        # Try to find it in the Go bin directory
        local go_bin=$(go env GOPATH)/bin
        if [[ -f "$go_bin/amass" ]]; then
            export PATH="$PATH:$go_bin"
            log_message "Added $go_bin to PATH" "INFO"
            
            if command_exists amass; then
                log_message "Amass installation verified successfully" "SUCCESS"
                return 0
            fi
        fi
        
        log_message "Failed to install Amass" "ERROR"
        return 1
    fi
}

# Function to install SQLMap
function install_sqlmap() {
    log_message "Installing SQLMap..." "INFO"
    
    if command_exists git; then
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
        
        # Create a symlink to make it accessible from PATH
        if [[ -d "sqlmap" ]]; then
            chmod +x sqlmap/sqlmap.py
            sudo ln -sf "$(pwd)/sqlmap/sqlmap.py" /usr/local/bin/sqlmap
            
            if command_exists sqlmap; then
                log_message "SQLMap installed successfully" "SUCCESS"
                return 0
            else
                log_message "Failed to create SQLMap symlink" "ERROR"
            fi
        else
            log_message "SQLMap clone failed" "ERROR"
        fi
    else
        log_message "Git is required to install SQLMap" "ERROR"
    fi
    
    return 1
}

# Function to install httpx
function install_httpx() {
    log_message "Installing httpx..." "INFO"
    
    install_go_package "github.com/projectdiscovery/httpx/cmd/httpx"
    
    if command_exists httpx; then
        log_message "httpx installed successfully" "SUCCESS"
        return 0
    else
        # Try to find it in the Go bin directory
        local go_bin=$(go env GOPATH)/bin
        if [[ -f "$go_bin/httpx" ]]; then
            export PATH="$PATH:$go_bin"
            log_message "Added $go_bin to PATH" "INFO"
            
            if command_exists httpx; then
                log_message "httpx installation verified successfully" "SUCCESS"
                return 0
            fi
        fi
        
        log_message "Failed to install httpx" "ERROR"
        return 1
    fi
}

# Function to install Subfinder
function install_subfinder() {
    log_message "Installing Subfinder..." "INFO"
    
    install_go_package "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    
    if command_exists subfinder; then
        log_message "Subfinder installed successfully" "SUCCESS"
        return 0
    else
        # Try to find it in the Go bin directory
        local go_bin=$(go env GOPATH)/bin
        if [[ -f "$go_bin/subfinder" ]]; then
            export PATH="$PATH:$go_bin"
            log_message "Added $go_bin to PATH" "INFO"
            
            if command_exists subfinder; then
                log_message "Subfinder installation verified successfully" "SUCCESS"
                return 0
            fi
        fi
        
        log_message "Failed to install Subfinder" "ERROR"
        return 1
    fi
}

# Function to install jq
function install_jq() {
    log_message "Installing jq..." "INFO"
    install_package "jq"
    
    if command_exists jq; then
        log_message "jq installed successfully" "SUCCESS"
        return 0
    else
        log_message "Failed to install jq" "ERROR"
        return 1
    fi
}

# Function to install GetAllUrls (gau)
function install_gau() {
    log_message "Installing GetAllUrls (gau)..." "INFO"
    
    install_go_package "github.com/lc/gau/v2/cmd/gau"
    
    if command_exists gau; then
        log_message "gau installed successfully" "SUCCESS"
        return 0
    else
        # Try to find it in the Go bin directory
        local go_bin=$(go env GOPATH)/bin
        if [[ -f "$go_bin/gau" ]]; then
            export PATH="$PATH:$go_bin"
            log_message "Added $go_bin to PATH" "INFO"
            
            if command_exists gau; then
                log_message "gau installation verified successfully" "SUCCESS"
                return 0
            fi
        fi
        
        log_message "Failed to install gau" "ERROR"
        return 1
    fi
}

# Function to install WFuzz
function install_wfuzz() {
    log_message "Installing WFuzz..." "INFO"
    
    install_pip_package "wfuzz"
    
    if command_exists wfuzz; then
        log_message "WFuzz installed successfully" "SUCCESS"
        return 0
    else
        log_message "Failed to install WFuzz" "ERROR"
        return 1
    fi
}

# Function to install Gobuster
function install_gobuster() {
    log_message "Installing Gobuster..." "INFO"
    
    install_go_package "github.com/OJ/gobuster/v3"
    
    if command_exists gobuster; then
        log_message "Gobuster installed successfully" "SUCCESS"
        return 0
    else
        # Try to find it in the Go bin directory
        local go_bin=$(go env GOPATH)/bin
        if [[ -f "$go_bin/gobuster" ]]; then
            export PATH="$PATH:$go_bin"
            log_message "Added $go_bin to PATH" "INFO"
            
            if command_exists gobuster; then
                log_message "Gobuster installation verified successfully" "SUCCESS"
                return 0
            fi
        fi
        
        log_message "Failed to install Gobuster" "ERROR"
        return 1
    fi
}

# Function to install Proxychains
function install_proxychains() {
    log_message "Installing Proxychains..." "INFO"
    install_package "proxychains"
    
    if command_exists proxychains; then
        log_message "Proxychains installed successfully" "SUCCESS"
        return 0
    elif command_exists proxychains4; then
        log_message "Proxychains4 installed successfully" "SUCCESS"
        return 0
    else
        log_message "Failed to install Proxychains" "ERROR"
        return 1
    fi
}

# Function to install httprobe
function install_httprobe() {
    log_message "Installing httprobe..." "INFO"
    
    install_go_package "github.com/tomnomnom/httprobe"
    
    if command_exists httprobe; then
        log_message "httprobe installed successfully" "SUCCESS"
        return 0
    else
        # Try to find it in the Go bin directory
        local go_bin=$(go env GOPATH)/bin
        if [[ -f "$go_bin/httprobe" ]]; then
            export PATH="$PATH:$go_bin"
            log_message "Added $go_bin to PATH" "INFO"
            
            if command_exists httprobe; then
                log_message "httprobe installation verified successfully" "SUCCESS"
                return 0
            fi
        fi
        
        log_message "Failed to install httprobe" "ERROR"
        return 1
    fi
}

# Function to install ffuf
function install_ffuf() {
    log_message "Installing ffuf..." "INFO"
    
    install_go_package "github.com/ffuf/ffuf"
    
    if command_exists ffuf; then
        log_message "ffuf installed successfully" "SUCCESS"
        return 0
    else
        # Try to find it in the Go bin directory
        local go_bin=$(go env GOPATH)/bin
        if [[ -f "$go_bin/ffuf" ]]; then
            export PATH="$PATH:$go_bin"
            log_message "Added $go_bin to PATH" "INFO"
            
            if command_exists ffuf; then
                log_message "ffuf installation verified successfully" "SUCCESS"
                return 0
            fi
        fi
        
        log_message "Failed to install ffuf" "ERROR"
        return 1
    fi
}

# Function to install whatweb
function install_whatweb() {
    log_message "Installing whatweb..." "INFO"
    install_package "whatweb"
    
    if command_exists whatweb; then
        log_message "whatweb installed successfully" "SUCCESS"
        return 0
    else
        log_message "Failed to install whatweb" "ERROR"
        return 1
    fi
}

# Function to install dig/nslookup (dnsutils)
function install_dnsutils() {
    log_message "Installing dnsutils (dig, nslookup)..." "INFO"
    
    local package="dnsutils"
    local package_manager=$(detect_package_manager)
    
    if [[ "$package_manager" == "apt" ]]; then
        package="dnsutils"
    elif [[ "$package_manager" == "dnf" || "$package_manager" == "yum" ]]; then
        package="bind-utils"
    elif [[ "$package_manager" == "pacman" ]]; then
        package="bind-tools"
    elif [[ "$package_manager" == "zypper" ]]; then
        package="bind-utils"
    fi
    
    install_package "$package"
    
    if command_exists dig && command_exists nslookup; then
        log_message "dnsutils installed successfully" "SUCCESS"
        return 0
    else
        log_message "Failed to install dnsutils" "ERROR"
        return 1
    fi
}

# Function to install whois
function install_whois() {
    log_message "Installing whois..." "INFO"
    install_package "whois"
    
    if command_exists whois; then
        log_message "whois installed successfully" "SUCCESS"
        return 0
    else
        log_message "Failed to install whois" "ERROR"
        return 1
    fi
}

# Function to install essential packages
function install_essentials() {
    log_message "Installing essential packages..." "INFO"
    
    # List of essential packages
    local essentials=("curl" "wget" "git" "python3" "python3-pip" "build-essential" "libpcap-dev")
    
    local package_manager=$(detect_package_manager)
    if [[ "$package_manager" == "apt" ]]; then
        sudo apt-get update
        
        for pkg in "${essentials[@]}"; do
            log_message "Installing $pkg..." "INFO"
            sudo apt-get install -y "$pkg"
        done
    elif [[ "$package_manager" == "dnf" || "$package_manager" == "yum" ]]; then
        for pkg in "${essentials[@]}"; do
            log_message "Installing $pkg..." "INFO"
            
            # Adjust package names for RHEL/Fedora
            if [[ "$pkg" == "python3-pip" ]]; then
                sudo $package_manager install -y python3-pip
            elif [[ "$pkg" == "build-essential" ]]; then
                sudo $package_manager install -y make automake gcc gcc-c++ kernel-devel
            elif [[ "$pkg" == "libpcap-dev" ]]; then
                sudo $package_manager install -y libpcap-devel
            else
                sudo $package_manager install -y "$pkg"
            fi
        done
    elif [[ "$package_manager" == "pacman" ]]; then
        sudo pacman -Sy
        
        for pkg in "${essentials[@]}"; do
            log_message "Installing $pkg..." "INFO"
            
            # Adjust package names for Arch
            if [[ "$pkg" == "python3-pip" ]]; then
                sudo pacman -S --noconfirm python-pip
            elif [[ "$pkg" == "build-essential" ]]; then
                sudo pacman -S --noconfirm base-devel
            elif [[ "$pkg" == "libpcap-dev" ]]; then
                sudo pacman -S --noconfirm libpcap
            else
                sudo pacman -S --noconfirm "$pkg"
            fi
        done
    elif [[ "$package_manager" == "zypper" ]]; then
        for pkg in "${essentials[@]}"; do
            log_message "Installing $pkg..." "INFO"
            
            # Adjust package names for openSUSE
            if [[ "$pkg" == "build-essential" ]]; then
                sudo zypper install -y patterns-devel-base-devel_basis
            elif [[ "$pkg" == "libpcap-dev" ]]; then
                sudo zypper install -y libpcap-devel
            else
                sudo zypper install -y "$pkg"
            fi
        done
    else
        log_message "Unknown package manager. Please install essential packages manually." "ERROR"
        return 1
    fi
    
    log_message "Essential packages installed" "SUCCESS"
    return 0
}

# Function to install Go
function install_go() {
    if command_exists go; then
        log_message "Go is already installed" "INFO"
        return 0
    fi
    
    log_message "Installing Go..." "INFO"
    
    local package_manager=$(detect_package_manager)
    if [[ "$package_manager" == "apt" ]]; then
        sudo apt-get update
        sudo apt-get install -y golang-go
    elif [[ "$package_manager" == "dnf" ]]; then
        sudo dnf install -y golang
    elif [[ "$package_manager" == "yum" ]]; then
        sudo yum install -y golang
    elif [[ "$package_manager" == "pacman" ]]; then
        sudo pacman -S --noconfirm go
    elif [[ "$package_manager" == "zypper" ]]; then
        sudo zypper install -y go
    else
        log_message "Unknown package manager. Downloading Go from golang.org..." "WARNING"
        
        # Download and install Go manually
        wget https://golang.org/dl/go1.17.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.17.linux-amd64.tar.gz
        rm go1.17.linux-amd64.tar.gz
        
        # Add Go to PATH
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
        
        source ~/.bashrc
    fi
    
    if command_exists go; then
        log_message "Go installed successfully" "SUCCESS"
        return 0
    else
        log_message "Failed to install Go" "ERROR"
        return 1
    fi
}

# Install all tools
function install_all_tools() {
    log_message "Starting installation of all tools..." "INFO"
    
    # Install essentials first
    install_essentials
    
    # Install Go
    install_go
    
    # Install DNS utilities
    install_dnsutils
    install_whois
    
    # Install recon tools
    install_nmap
    install_masscan
    install_waybackurls
    install_assetfinder
    install_amass
    install_subfinder
    install_httpx
    install_gau
    install_httprobe
    install_jq
    
    # Install content discovery tools
    install_gobuster
    install_wfuzz
    install_ffuf
    
    # Install vulnerability scanners
    install_nuclei
    install_sqlmap
    install_whatweb
    
    # Install proxy tools
    install_proxychains
    
    log_message "Installation complete!" "SUCCESS"
}

# Function to display usage information
function show_usage() {
    echo "MR Legacy - Tool Installation Script"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -a, --all             Install all tools"
    echo "  -e, --essentials      Install essential packages"
    echo "  -r, --recon           Install reconnaissance tools"
    echo "  -d, --discovery       Install content discovery tools"
    echo "  -v, --vuln            Install vulnerability scanners"
    echo "  -p, --proxy           Install proxy tools"
    echo "  -h, --help            Display this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --all              Install all tools"
    echo "  $0 --recon --vuln     Install reconnaissance and vulnerability scanning tools"
}

# Parse command-line arguments
if [[ $# -eq 0 ]]; then
    show_usage
    exit 0
fi

# Process arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--all)
            install_all_tools
            shift
            ;;
        -e|--essentials)
            install_essentials
            install_go
            shift
            ;;
        -r|--recon)
            log_message "Installing reconnaissance tools..." "INFO"
            install_nmap
            install_masscan
            install_waybackurls
            install_assetfinder
            install_amass
            install_subfinder
            install_httpx
            install_gau
            install_httprobe
            install_jq
            install_dnsutils
            install_whois
            shift
            ;;
        -d|--discovery)
            log_message "Installing content discovery tools..." "INFO"
            install_gobuster
            install_wfuzz
            install_ffuf
            shift
            ;;
        -v|--vuln)
            log_message "Installing vulnerability scanners..." "INFO"
            install_nuclei
            install_sqlmap
            install_whatweb
            shift
            ;;
        -p|--proxy)
            log_message "Installing proxy tools..." "INFO"
            install_proxychains
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            log_message "Unknown option: $1" "ERROR"
            show_usage
            exit 1
            ;;
    esac
done

exit 0