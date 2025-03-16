#!/bin/bash

# MR Legacy - Banner Functions
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.2.0

# Colors for terminal output
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
PURPLE="\033[0;35m"
CYAN="\033[0;36m"
WHITE="\033[1;37m"
NC="\033[0m" # No Color

# Function to display the main banner
function show_banner() {
    clear
    echo -e "${RED}"
    echo -e "███╗   ███╗██████╗     ██╗     ███████╗ ██████╗  █████╗  ██████╗██╗   ██╗"
    echo -e "████╗ ████║██╔══██╗    ██║     ██╔════╝██╔════╝ ██╔══██╗██╔════╝╚██╗ ██╔╝"
    echo -e "██╔████╔██║██████╔╝    ██║     █████╗  ██║  ███╗███████║██║      ╚████╔╝ "
    echo -e "██║╚██╔╝██║██╔══██╗    ██║     ██╔══╝  ██║   ██║██╔══██║██║       ╚██╔╝  "
    echo -e "██║ ╚═╝ ██║██║  ██║    ███████╗███████╗╚██████╔╝██║  ██║╚██████╗   ██║   "
    echo -e "╚═╝     ╚═╝╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝   "
    echo -e "${NC}"
    echo -e "${YELLOW}       Bug Bounty Hunting Tool - By Abdulrahman Muhammad (0xLegacy)${NC}"
    echo -e "${BLUE}       Version: 1.2.0 | ${GREEN}https://github.com/0xlegacy52/MrLegacy{NC}\n"
    echo -e "${CYAN}==========================================================================${NC}\n"
}

# Function to display the tool start banner
function show_start_banner() {
    echo -e "\n${PURPLE}[+] Starting MR Legacy Bug Bounty Tool${NC}"
    echo -e "${PURPLE}[+] Target: ${WHITE}$target${NC}"
    echo -e "${PURPLE}[+] Output Directory: ${WHITE}$target_dir${NC}"
    echo -e "${PURPLE}[+] Date & Time: ${WHITE}$(date)${NC}"
    
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${PURPLE}[+] Verbose Mode: ${GREEN}Enabled${NC}"
    fi
    
    if [[ "$DEEP" == true ]]; then
        echo -e "${PURPLE}[+] Deep Scan: ${GREEN}Enabled${NC}"
    fi
    
    if [[ "$TOR" == true ]]; then
        echo -e "${PURPLE}[+] Tor Proxy: ${GREEN}Enabled${NC}"
    fi
    
    echo -e "${PURPLE}[+] Threads: ${WHITE}$THREADS${NC}"
    echo -e "${CYAN}==========================================================================${NC}\n"
}

# Function to display the recon banner
function show_recon_banner() {
    echo -e "\n${BLUE}[+] ====== RECONNAISSANCE MODULE ======${NC}"
    echo -e "${BLUE}[+] Starting reconnaissance for ${WHITE}$target${NC}"
    echo -e "${BLUE}[+] =================================${NC}\n"
}

# Function to display the scanning banner
function show_scanning_banner() {
    echo -e "\n${GREEN}[+] ======== SCANNING MODULE ========${NC}"
    echo -e "${GREEN}[+] Starting scanning for ${WHITE}$target${NC}"
    echo -e "${GREEN}[+] =================================${NC}\n"
}

# Function to display the enumeration banner
function show_enumeration_banner() {
    echo -e "\n${YELLOW}[+] ======= ENUMERATION MODULE =======${NC}"
    echo -e "${YELLOW}[+] Starting enumeration for ${WHITE}$target${NC}"
    echo -e "${YELLOW}[+] ==================================${NC}\n"
}

# Function to display the vulnerability banner
function show_vulnerability_banner() {
    echo -e "\n${RED}[+] ===== VULNERABILITY MODULE =====${NC}"
    echo -e "${RED}[+] Starting vulnerability scanning for ${WHITE}$target${NC}"
    echo -e "${RED}[+] =================================${NC}\n"
}

# Function to display the exploitation banner
function show_exploitation_banner() {
    echo -e "\n${PURPLE}[+] ====== EXPLOITATION MODULE ======${NC}"
    echo -e "${PURPLE}[+] Starting exploitation for ${WHITE}$target${NC}"
    echo -e "${PURPLE}[+] ==================================${NC}\n"
}

# Function to display the cloud banner
function show_cloud_banner() {
    echo -e "\n${CYAN}[+] ======== CLOUD MODULE ========${NC}"
    echo -e "${CYAN}[+] Starting cloud resources discovery for ${WHITE}$target${NC}"
    echo -e "${CYAN}[+] ===============================${NC}\n"
}

# Function to display the reporting banner
function show_reporting_banner() {
    echo -e "\n${WHITE}[+] ======= REPORTING MODULE =======${NC}"
    echo -e "${WHITE}[+] Generating reports for ${CYAN}$target${NC}"
    echo -e "${WHITE}[+] ================================${NC}\n"
}

# Function to display the help message
function show_help() {
    echo -e "${GREEN}Usage:${NC}"
    echo -e "  ./mr_legacy.sh [options]"
    echo -e "${GREEN}Options:${NC}"
    echo -e "  -t, --target <domain>       Target domain"
    echo -e "  -o, --output <format>       Output format (json, txt, html, all) [default: all]"
    echo -e "  -T, --threads <num>         Number of threads [default: 10]"
    echo -e "  --tor                       Enable Tor proxy for anonymity"
    echo -e "  -a, --auto                  Run auto-recon mode (all modules in sequence)"
    echo -e "  -v, --verbose               Enable verbose output"
    echo -e "  -d, --deep                  Enable deep scan (more comprehensive)"
    echo -e "  -h, --help                  Show this help message"
    echo -e "${GREEN}Examples:${NC}"
    echo -e "  ./mr_legacy.sh -t example.com -o json"
    echo -e "  ./mr_legacy.sh -t example.com --tor -a -v"
    echo -e "  ./mr_legacy.sh -t example.com -T 20 --auto -d"
}

# Export the banner functions
export -f show_banner
export -f show_start_banner
export -f show_recon_banner
export -f show_scanning_banner
export -f show_enumeration_banner
export -f show_vulnerability_banner
export -f show_exploitation_banner
export -f show_cloud_banner
export -f show_reporting_banner
export -f show_help
