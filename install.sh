#!/bin/bash

# MR Legacy - Installation Script
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.1.0

# Colors for better output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
MAGENTA="\033[0;35m"
CYAN="\033[0;36m"
NC="\033[0m" # No Color

# Welcome banner
echo -e "${BLUE}"
echo "███╗   ███╗██████╗     ██╗     ███████╗ ██████╗  █████╗  ██████╗██╗   ██╗"
echo "████╗ ████║██╔══██╗    ██║     ██╔════╝██╔════╝ ██╔══██╗██╔════╝╚██╗ ██╔╝"
echo "██╔████╔██║██████╔╝    ██║     █████╗  ██║  ███╗███████║██║      ╚████╔╝"
echo "██║╚██╔╝██║██╔══██╗    ██║     ██╔══╝  ██║   ██║██╔══██║██║       ╚██╔╝"
echo "██║ ╚═╝ ██║██║  ██║    ███████╗███████╗╚██████╔╝██║  ██║╚██████╗   ██║"
echo "╚═╝     ╚═╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝"
echo -e "       Bug Bounty Hunting Tool - By Abdulrahman Muhammad (0xLegacy)\n"
echo -e "       Installation Script - Version 1.1.0${NC}\n"
echo "=========================================================================="

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install essential dependencies
install_essentials() {
    echo -e "\n${CYAN}=== Installing Essential Dependencies ===${NC}\n"
    
    # Detect package manager
    if command_exists apt-get; then
        PKG_MANAGER="apt-get"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update"
    elif command_exists apt; then
        PKG_MANAGER="apt"
        INSTALL_CMD="apt install -y"
        UPDATE_CMD="apt update"
    elif command_exists yum; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        UPDATE_CMD="yum check-update"
    elif command_exists dnf; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf check-update"
    elif command_exists pacman; then
        PKG_MANAGER="pacman"
        INSTALL_CMD="pacman -S --noconfirm"
        UPDATE_CMD="pacman -Sy"
    elif command_exists brew; then
        PKG_MANAGER="brew"
        INSTALL_CMD="brew install"
        UPDATE_CMD="brew update"
    else
        echo -e "${RED}Error: Unsupported package manager.${NC}"
        echo -e "${YELLOW}Please install the following packages manually:${NC}"
        echo "- curl"
        echo "- nmap"
        echo "- whois"
        echo "- dig (dnsutils)"
        echo "- jq"
        echo "- git"
        echo "- python3"
        echo "- pip3"
        echo -e "\n${YELLOW}Then run this script again with --skip-essentials flag.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}Detected package manager: ${PKG_MANAGER}${NC}"
    echo -e "${YELLOW}Updating package lists...${NC}"
    
    # Update package lists
    if [ "$PKG_MANAGER" = "apt-get" ] || [ "$PKG_MANAGER" = "apt" ]; then
        sudo $UPDATE_CMD
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        sudo $UPDATE_CMD
    elif [ "$PKG_MANAGER" = "brew" ]; then
        $UPDATE_CMD
    fi
    
    # Essential packages
    echo -e "\n${YELLOW}Installing essential packages...${NC}"
    
    ESSENTIAL_PACKAGES="curl nmap whois git python3 python3-pip"
    
    # Add distribution-specific package names
    if [ "$PKG_MANAGER" = "apt-get" ] || [ "$PKG_MANAGER" = "apt" ]; then
        ESSENTIAL_PACKAGES="$ESSENTIAL_PACKAGES dnsutils jq"
    elif [ "$PKG_MANAGER" = "yum" ] || [ "$PKG_MANAGER" = "dnf" ]; then
        ESSENTIAL_PACKAGES="$ESSENTIAL_PACKAGES bind-utils jq"
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        ESSENTIAL_PACKAGES="$ESSENTIAL_PACKAGES bind jq"
    elif [ "$PKG_MANAGER" = "brew" ]; then
        ESSENTIAL_PACKAGES="$ESSENTIAL_PACKAGES bind jq"
    fi
    
    # Install packages
    if [ "$PKG_MANAGER" = "brew" ]; then
        for package in $ESSENTIAL_PACKAGES; do
            echo -e "${YELLOW}Installing $package...${NC}"
            $INSTALL_CMD $package
        done
    else
        echo -e "${YELLOW}Installing: $ESSENTIAL_PACKAGES${NC}"
        sudo $INSTALL_CMD $ESSENTIAL_PACKAGES
    fi
    
    echo -e "\n${GREEN}Essential dependencies installed successfully!${NC}"
}

# Function to install Python dependencies
install_python_deps() {
    echo -e "\n${CYAN}=== Installing Python Dependencies ===${NC}\n"
    
    if command_exists pip3; then
        echo -e "${YELLOW}Installing Python packages...${NC}"
        pip3 install --user requests argparse dnspython beautifulsoup4 colorama pyjwt
        echo -e "\n${GREEN}Python dependencies installed successfully!${NC}"
    else
        echo -e "${RED}Error: pip3 not found. Cannot install Python dependencies.${NC}"
        echo -e "${YELLOW}Please install pip3 manually and run this script again.${NC}"
        exit 1
    fi
}

# Function to install recommended tools
install_recommended_tools() {
    echo -e "\n${CYAN}=== Installing Recommended Tools ===${NC}\n"
    
    # Check if Go is installed
    if ! command_exists go; then
        echo -e "${YELLOW}Installing Go (required for several tools)...${NC}"
        
        if [ "$PKG_MANAGER" = "apt-get" ] || [ "$PKG_MANAGER" = "apt" ]; then
            sudo $INSTALL_CMD golang
        elif [ "$PKG_MANAGER" = "yum" ] || [ "$PKG_MANAGER" = "dnf" ]; then
            sudo $INSTALL_CMD golang
        elif [ "$PKG_MANAGER" = "pacman" ]; then
            sudo $INSTALL_CMD go
        elif [ "$PKG_MANAGER" = "brew" ]; then
            $INSTALL_CMD go
        else
            echo -e "${RED}Could not install Go. Please install it manually.${NC}"
            return
        fi
    fi
    
    # GitHub based tools
    echo -e "\n${YELLOW}Installing useful GitHub tools...${NC}"
    
    # Create tools directory
    mkdir -p ~/tools
    cd ~/tools
    
    # List of GitHub tools to install
    declare -A GITHUB_TOOLS=(
        ["subfinder"]="projectdiscovery/subfinder"
        ["httpx"]="projectdiscovery/httpx"
        ["nuclei"]="projectdiscovery/nuclei"
        ["ffuf"]="ffuf/ffuf"
        ["gau"]="lc/gau"
    )
    
    # Install tools
    for tool in "${!GITHUB_TOOLS[@]}"; do
        if ! command_exists $tool; then
            echo -e "${YELLOW}Installing $tool...${NC}"
            go install github.com/${GITHUB_TOOLS[$tool]}/cmd/$tool@latest
        else
            echo -e "${GREEN}$tool is already installed.${NC}"
        fi
    done
    
    # Add Go's bin to PATH if not already there
    GOPATH=$(go env GOPATH)
    if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
        echo -e "\n${YELLOW}Adding Go's bin directory to PATH...${NC}"
        echo 'export PATH=$PATH:'"$GOPATH"'/bin' >> ~/.bashrc
        echo -e "${GREEN}Added $GOPATH/bin to PATH in .bashrc${NC}"
        echo -e "${YELLOW}Please run 'source ~/.bashrc' after this script completes.${NC}"
    fi
    
    # Return to the original directory
    cd - > /dev/null
    
    echo -e "\n${GREEN}Recommended tools installed successfully!${NC}"
}

# Function to verify installation
verify_installation() {
    echo -e "\n${CYAN}=== Verifying Installation ===${NC}\n"
    
    # List of essential commands to check
    ESSENTIAL_COMMANDS=("curl" "nmap" "whois" "dig" "jq" "python3" "pip3")
    
    # Check essential commands
    echo -e "${YELLOW}Checking essential commands...${NC}"
    for cmd in "${ESSENTIAL_COMMANDS[@]}"; do
        if command_exists $cmd; then
            echo -e "${GREEN}✓ $cmd installed${NC}"
        else
            echo -e "${RED}✗ $cmd not installed${NC}"
        fi
    done
    
    # Check Go tools
    if command_exists go; then
        echo -e "\n${YELLOW}Checking Go installation...${NC}"
        echo -e "${GREEN}✓ go installed ($(go version))${NC}"
        
        GOPATH=$(go env GOPATH)
        echo -e "${YELLOW}Checking Go tools...${NC}"
        
        GO_TOOLS=("subfinder" "httpx" "nuclei" "ffuf" "gau")
        
        for tool in "${GO_TOOLS[@]}"; do
            if command_exists $tool; then
                echo -e "${GREEN}✓ $tool installed${NC}"
            elif [ -f "$GOPATH/bin/$tool" ]; then
                echo -e "${YELLOW}~ $tool installed in $GOPATH/bin but not in PATH${NC}"
            else
                echo -e "${RED}✗ $tool not installed${NC}"
            fi
        done
    else
        echo -e "\n${YELLOW}Go is not installed. Some tools may not be available.${NC}"
    fi
    
    # Check script permissions
    echo -e "\n${YELLOW}Checking script permissions...${NC}"
    if [ -x "./mr_legacy.sh" ]; then
        echo -e "${GREEN}✓ mr_legacy.sh is executable${NC}"
    else
        echo -e "${YELLOW}Setting executable permissions on mr_legacy.sh...${NC}"
        chmod +x ./mr_legacy.sh
        echo -e "${GREEN}✓ mr_legacy.sh is now executable${NC}"
    fi
    
    # Check directory structure
    echo -e "\n${YELLOW}Checking directory structure...${NC}"
    REQUIRED_DIRS=("modules" "utils" "config" "logs" "results")
    
    for dir in "${REQUIRED_DIRS[@]}"; do
        if [ -d "./$dir" ]; then
            echo -e "${GREEN}✓ $dir directory exists${NC}"
        else
            echo -e "${YELLOW}Creating $dir directory...${NC}"
            mkdir -p "./$dir"
            echo -e "${GREEN}✓ $dir directory created${NC}"
        fi
    done
    
    echo -e "\n${GREEN}Verification complete!${NC}"
}

# Parse command line arguments
SKIP_ESSENTIALS=false
SKIP_PYTHON=false
SKIP_RECOMMENDED=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --basic)
            SKIP_RECOMMENDED=true
            ;;
        --skip-essentials)
            SKIP_ESSENTIALS=true
            ;;
        --skip-python)
            SKIP_PYTHON=true
            ;;
        --skip-recommended)
            SKIP_RECOMMENDED=true
            ;;
        --full)
            # Install everything (default)
            ;;
        --help)
            echo -e "Usage: ./install.sh [options]"
            echo -e ""
            echo -e "Options:"
            echo -e "  --basic             Install only essential dependencies (no recommended tools)"
            echo -e "  --skip-essentials   Skip installation of essential system packages"
            echo -e "  --skip-python       Skip installation of Python dependencies"
            echo -e "  --skip-recommended  Skip installation of recommended tools"
            echo -e "  --full              Install all dependencies and tools (default)"
            echo -e "  --help              Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo -e "Use ./install.sh --help for usage information."
            exit 1
            ;;
    esac
    shift
done

# Main installation process
echo -e "${YELLOW}Starting installation process...${NC}\n"

# Install essential dependencies
if [ "$SKIP_ESSENTIALS" = false ]; then
    install_essentials
else
    echo -e "${YELLOW}Skipping essential dependencies installation.${NC}"
fi

# Install Python dependencies
if [ "$SKIP_PYTHON" = false ]; then
    install_python_deps
else
    echo -e "${YELLOW}Skipping Python dependencies installation.${NC}"
fi

# Install recommended tools
if [ "$SKIP_RECOMMENDED" = false ]; then
    install_recommended_tools
else
    echo -e "${YELLOW}Skipping recommended tools installation.${NC}"
fi

# Verify installation
verify_installation

# Done
echo -e "\n${CYAN}=== Installation Complete ===${NC}\n"
echo -e "${GREEN}MR Legacy has been successfully installed!${NC}"
echo -e "${YELLOW}Run ./mr_legacy.sh -h to see usage information.${NC}"

# Add notice if Go bin directory was added to PATH
GOPATH=$(go env GOPATH 2>/dev/null)
if [[ -n "$GOPATH" && ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    echo -e "\n${YELLOW}IMPORTANT: You need to refresh your shell to use Go tools.${NC}"
    echo -e "${YELLOW}Run the following command:${NC}"
    echo -e "${CYAN}source ~/.bashrc${NC}"
fi

echo -e "\n${BLUE}Thank you for installing MR Legacy!${NC}"