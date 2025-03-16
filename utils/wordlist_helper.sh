#!/bin/bash
# MR Legacy Bug Bounty Tool - Wordlist Helper
# Author: Abdulrahman Muhammad (0xLegacy)
# This script helps manage and understand wordlists in the MR Legacy tool

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Set script path
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST_DIR="${SCRIPT_PATH}/../modules/wordlists"

# Show banner
show_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║  MR LEGACY WORDLIST UTILITY                                    ║"
    echo "║  Author: Abdulrahman Muhammad (0xLegacy)                       ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage instructions
show_usage() {
    echo -e "${YELLOW}Usage:${NC}"
    echo "./wordlist_helper.sh [option]"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -l, --list                List all available wordlists"
    echo "  -c, --count               Show count of entries in each wordlist"
    echo "  -i, --info [wordlist]     Show information about a specific wordlist"
    echo "  -s, --search [term]       Search for a specific term across all wordlists"
    echo "  -h, --help                Show this help message"
    echo "  -e, --examples            Show examples of usage and custom wordlist creation"
    echo ""
}

# List available wordlists
list_wordlists() {
    echo -e "${GREEN}Available wordlists:${NC}"
    echo ""
    for wordlist in "${WORDLIST_DIR}"/*.txt; do
        if [[ -f "$wordlist" ]]; then
            name=$(basename "$wordlist" .txt)
            # Get first line with header comment
            description=$(head -1 "$wordlist" | sed 's/^# //')
            echo -e "${CYAN}$name${NC} - $description"
        fi
    done
}

# Count entries in wordlists
count_wordlists() {
    echo -e "${GREEN}Wordlist entry counts:${NC}"
    echo ""
    echo -e "${CYAN}Wordlist Name            Count${NC}"
    echo "-------------------------------------"
    for wordlist in "${WORDLIST_DIR}"/*.txt; do
        if [[ -f "$wordlist" ]]; then
            # Count lines excluding comments and empty lines
            name=$(basename "$wordlist" .txt)
            count=$(grep -v "^#" "$wordlist" | grep -v "^$" | wc -l)
            printf "%-25s %d\n" "$name" "$count"
        fi
    done
}

# Show information about a specific wordlist
show_info() {
    local wordlist_name="$1"
    local wordlist_file="${WORDLIST_DIR}/${wordlist_name}.txt"
    
    if [[ ! -f "$wordlist_file" ]]; then
        echo -e "${RED}Error: Wordlist '${wordlist_name}' not found.${NC}"
        echo "Available wordlists:"
        for wl in "${WORDLIST_DIR}"/*.txt; do
            if [[ -f "$wl" ]]; then
                echo "  - $(basename "$wl" .txt)"
            fi
        done
        return 1
    fi
    
    echo -e "${GREEN}Information about wordlist: ${CYAN}${wordlist_name}${NC}"
    echo ""
    
    # Extract comments from the beginning of the file
    echo -e "${YELLOW}Description:${NC}"
    grep "^#" "$wordlist_file" | sed 's/^# //'
    echo ""
    
    # Count entries
    local count=$(grep -v "^#" "$wordlist_file" | grep -v "^$" | wc -l)
    echo -e "${YELLOW}Entry count:${NC} $count"
    echo ""
    
    # Show a few sample entries
    echo -e "${YELLOW}Sample entries:${NC}"
    grep -v "^#" "$wordlist_file" | grep -v "^$" | head -10
    
    if [[ $count -gt 10 ]]; then
        echo "..."
    fi
}

# Search for a term across all wordlists
search_wordlists() {
    local search_term="$1"
    
    if [[ -z "$search_term" ]]; then
        echo -e "${RED}Error: No search term provided.${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Searching for '${search_term}' across all wordlists:${NC}"
    echo ""
    
    local found=false
    
    for wordlist in "${WORDLIST_DIR}"/*.txt; do
        if [[ -f "$wordlist" ]]; then
            local name=$(basename "$wordlist" .txt)
            # Search excluding comments
            local results=$(grep -v "^#" "$wordlist" | grep -i "$search_term")
            
            if [[ -n "$results" ]]; then
                found=true
                echo -e "${CYAN}${name}:${NC}"
                echo "$results" | head -5
                local count=$(echo "$results" | wc -l)
                if [[ $count -gt 5 ]]; then
                    echo -e "${YELLOW}... and $(($count - 5)) more matches${NC}"
                fi
                echo ""
            fi
        fi
    done
    
    if [[ "$found" == "false" ]]; then
        echo -e "${YELLOW}No matches found for '$search_term'.${NC}"
    fi
}

# Show examples of usage and custom wordlist creation
show_examples() {
    echo -e "${GREEN}Examples of wordlist usage and creation:${NC}"
    echo ""
    
    echo -e "${YELLOW}1. Viewing wordlist content:${NC}"
    echo "   cat ${WORDLIST_DIR}/xss_payloads.txt | less"
    echo "   head -20 ${WORDLIST_DIR}/sensitive_files.txt"
    echo ""
    
    echo -e "${YELLOW}2. Using wordlists with common tools:${NC}"
    echo "   # Using with gobuster"
    echo "   gobuster dir -u https://example.com -w ${WORDLIST_DIR}/directories.txt"
    echo ""
    echo "   # Using with curl in a loop"
    echo "   while read -r line; do curl -s -o /dev/null -w \"%{url_effective} - %{http_code}\\n\" https://example.com/\$line; done < ${WORDLIST_DIR}/sensitive_files.txt"
    echo ""
    
    echo -e "${YELLOW}3. Creating your own custom wordlist:${NC}"
    echo "   # Create a new wordlist"
    echo "   nano ${WORDLIST_DIR}/custom_wordlist.txt"
    echo ""
    echo "   # Add a header comment"
    echo "   # Custom Wordlist for [Specific Purpose]"
    echo "   # Author: Your Name"
    echo "   # This wordlist contains [description]"
    echo ""
    echo "   # Format: One entry per line, add comments with # prefix"
    echo "   entry1"
    echo "   entry2"
    echo "   # Group entries with comments"
    echo "   entry3"
    echo ""
    
    echo -e "${YELLOW}4. Extending existing wordlists:${NC}"
    echo "   # Add entries to an existing wordlist"
    echo "   echo \"new_entry\" >> ${WORDLIST_DIR}/directories.txt"
    echo ""
    echo "   # Combine wordlists"
    echo "   cat ${WORDLIST_DIR}/wordlist1.txt ${WORDLIST_DIR}/wordlist2.txt | sort -u > ${WORDLIST_DIR}/combined_wordlist.txt"
    echo ""
    
    echo -e "${YELLOW}5. Converting formats:${NC}"
    echo "   # Convert from other format (e.g., CSV)"
    echo "   awk -F, '{print \$1}' input.csv > ${WORDLIST_DIR}/new_wordlist.txt"
    echo ""
}

# Main function
main() {
    if [[ $# -eq 0 ]]; then
        show_banner
        show_usage
        exit 0
    fi
    
    show_banner
    
    case "$1" in
        -l|--list)
            list_wordlists
            ;;
        -c|--count)
            count_wordlists
            ;;
        -i|--info)
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: No wordlist specified.${NC}"
                echo "Usage: $0 --info [wordlist]"
                exit 1
            fi
            show_info "$2"
            ;;
        -s|--search)
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: No search term specified.${NC}"
                echo "Usage: $0 --search [term]"
                exit 1
            fi
            search_wordlists "$2"
            ;;
        -e|--examples)
            show_examples
            ;;
        -h|--help|*)
            show_usage
            ;;
    esac
}

# Execute main function
main "$@"