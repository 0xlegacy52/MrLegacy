#!/bin/bash
# MR Legacy Bug Bounty Tool - Enhanced Wordlists Update Script
# Author: Abdulrahman Muhammad (0xLegacy)
# This script helps update and integrate enhanced wordlists with the main wordlists

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
ENHANCED_DIR="${WORDLIST_DIR}/enhanced"

# Show banner
show_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║  MR LEGACY ENHANCED WORDLISTS UPDATE UTILITY                   ║"
    echo "║  Author: Abdulrahman Muhammad (0xLegacy)                       ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if enhanced wordlists directory exists
check_enhanced_dir() {
    if [[ ! -d "$ENHANCED_DIR" ]]; then
        echo -e "${RED}Enhanced wordlists directory not found. Creating...${NC}"
        mkdir -p "$ENHANCED_DIR"
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}Created enhanced wordlists directory.${NC}"
        else
            echo -e "${RED}Failed to create enhanced wordlists directory. Please check permissions.${NC}"
            exit 1
        fi
    fi
}

# List available enhanced wordlists
list_enhanced_wordlists() {
    local count=0
    echo -e "${GREEN}Available enhanced wordlists:${NC}"
    echo ""
    for wordlist in "${ENHANCED_DIR}"/*.txt; do
        if [[ -f "$wordlist" ]]; then
            count=$((count+1))
            name=$(basename "$wordlist" .txt)
            # Get first line with header comment
            description=$(head -1 "$wordlist" | sed 's/^# //')
            echo -e "${CYAN}$name${NC} - $description"
        fi
    done
    
    if [[ $count -eq 0 ]]; then
        echo -e "${YELLOW}No enhanced wordlists found.${NC}"
    else
        echo ""
        echo -e "${GREEN}Found $count enhanced wordlists.${NC}"
    fi
}

# Update or integrate an enhanced wordlist
update_wordlist() {
    local enhanced_list="$1"
    local target_list="$2"
    
    if [[ ! -f "${ENHANCED_DIR}/${enhanced_list}.txt" ]]; then
        echo -e "${RED}Enhanced wordlist '${enhanced_list}.txt' not found.${NC}"
        return 1
    fi
    
    if [[ ! -f "${WORDLIST_DIR}/${target_list}.txt" && "$target_list" != "new" ]]; then
        echo -e "${YELLOW}Target wordlist '${target_list}.txt' not found. Creating new file.${NC}"
        target_list="new"
    fi
    
    if [[ "$target_list" == "new" ]]; then
        # Create a new wordlist with the same name as the enhanced list
        cp "${ENHANCED_DIR}/${enhanced_list}.txt" "${WORDLIST_DIR}/${enhanced_list}.txt"
        echo -e "${GREEN}Created new wordlist '${enhanced_list}.txt' from enhanced wordlist.${NC}"
    else
        # Merge enhanced wordlist with existing target wordlist
        echo -e "${YELLOW}Merging enhanced wordlist with existing '${target_list}.txt'...${NC}"
        
        # Create a temporary file for unique entries from enhanced wordlist
        tmp_file=$(mktemp)
        
        # Extract non-comment lines from enhanced wordlist
        grep -v "^#" "${ENHANCED_DIR}/${enhanced_list}.txt" > "$tmp_file"
        
        # Get count of entries before merge
        before_count=$(grep -v "^#" "${WORDLIST_DIR}/${target_list}.txt" | wc -l)
        
        # Append unique entries to target wordlist
        cat "$tmp_file" >> "${WORDLIST_DIR}/${target_list}.txt"
        
        # Remove duplicates and preserve order
        sort "${WORDLIST_DIR}/${target_list}.txt" | grep -v "^#" | uniq > "$tmp_file"
        
        # Get header comments from original file
        grep "^#" "${WORDLIST_DIR}/${target_list}.txt" > "${WORDLIST_DIR}/${target_list}.txt.new"
        
        # Add unique entries
        cat "$tmp_file" >> "${WORDLIST_DIR}/${target_list}.txt.new"
        
        # Replace original file
        mv "${WORDLIST_DIR}/${target_list}.txt.new" "${WORDLIST_DIR}/${target_list}.txt"
        
        # Get count of entries after merge
        after_count=$(grep -v "^#" "${WORDLIST_DIR}/${target_list}.txt" | wc -l)
        added_count=$((after_count - before_count))
        
        # Clean up
        rm "$tmp_file"
        
        echo -e "${GREEN}Merged enhanced wordlist with '${target_list}.txt'.${NC}"
        echo -e "${GREEN}Added $added_count new unique entries.${NC}"
    fi
}

# Update all enhanced wordlists
update_all_wordlists() {
    echo -e "${YELLOW}Updating all enhanced wordlists...${NC}"
    echo ""
    
    local enhanced_count=0
    for wordlist in "${ENHANCED_DIR}"/*.txt; do
        if [[ -f "$wordlist" ]]; then
            enhanced_count=$((enhanced_count+1))
            name=$(basename "$wordlist" .txt)
            
            # Find matching target wordlist
            target_list=""
            if [[ -f "${WORDLIST_DIR}/${name}.txt" ]]; then
                target_list="$name"
            elif [[ "$name" == *"xss"* && -f "${WORDLIST_DIR}/xss_payloads.txt" ]]; then
                target_list="xss_payloads"
            elif [[ "$name" == *"sql"* && -f "${WORDLIST_DIR}/sqli_payloads.txt" ]]; then
                target_list="sqli_payloads"
            elif [[ "$name" == *"ssrf"* && -f "${WORDLIST_DIR}/ssrf_payloads.txt" ]]; then
                target_list="ssrf_payloads"
            elif [[ "$name" == *"redirect"* && -f "${WORDLIST_DIR}/openredirect_payloads.txt" ]]; then
                target_list="openredirect_payloads"
            elif [[ "$name" == *"jwt"* && -f "${WORDLIST_DIR}/jwt_secrets.txt" ]]; then
                target_list="jwt_secrets"
            else
                target_list="new"
            fi
            
            echo -e "${CYAN}Updating wordlist: ${name}${NC}"
            update_wordlist "$name" "$target_list"
            echo ""
        fi
    done
    
    if [[ $enhanced_count -eq 0 ]]; then
        echo -e "${YELLOW}No enhanced wordlists found to update.${NC}"
    else
        echo -e "${GREEN}Updated $enhanced_count enhanced wordlists.${NC}"
    fi
}

# Create an enhanced wordlist template
create_enhanced_template() {
    local name="$1"
    
    if [[ -z "$name" ]]; then
        echo -e "${RED}Error: Please provide a name for the new enhanced wordlist.${NC}"
        echo -e "${YELLOW}Usage: $0 --create <name>${NC}"
        return 1
    fi
    
    if [[ -f "${ENHANCED_DIR}/${name}.txt" ]]; then
        echo -e "${YELLOW}Warning: Enhanced wordlist '${name}.txt' already exists.${NC}"
        read -p "Do you want to overwrite it? (y/n): " confirm
        if [[ "$confirm" != "y" ]]; then
            echo -e "${RED}Operation cancelled.${NC}"
            return 0
        fi
    fi
    
    echo -e "${YELLOW}Creating enhanced wordlist template: ${name}.txt${NC}"
    
    cat > "${ENHANCED_DIR}/${name}.txt" << EOF
# Enhanced ${name^} Wordlist
# Author: Abdulrahman Muhammad (0xLegacy)
# Contains specialized payloads for ${name} testing

# Add your entries below this line
entry1
entry2
entry3
EOF
    
    echo -e "${GREEN}Created enhanced wordlist template: ${ENHANCED_DIR}/${name}.txt${NC}"
    echo -e "${YELLOW}Edit this file to add your custom entries.${NC}"
}

# Show usage
show_usage() {
    echo -e "${YELLOW}Usage:${NC}"
    echo "$0 [option]"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  --list, -l                    List available enhanced wordlists"
    echo "  --update <name> [target]      Update/integrate specific enhanced wordlist"
    echo "                               If target is 'new', creates a new wordlist"
    echo "                               If target is omitted, tries to find matching target"
    echo "  --update-all, -ua             Update all enhanced wordlists"
    echo "  --create <name>, -c <name>    Create an enhanced wordlist template"
    echo "  --help, -h                    Show this help message"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 --list"
    echo "  $0 --update sqli_payloads sqli_payloads"
    echo "  $0 --update enhanced_xss xss_payloads"
    echo "  $0 --update new_wordlist new"
    echo "  $0 --update-all"
    echo "  $0 --create custom_xxe_payloads"
}

# Main function
main() {
    if [[ $# -eq 0 ]]; then
        show_banner
        show_usage
        exit 0
    fi
    
    show_banner
    check_enhanced_dir
    
    case "$1" in
        --list|-l)
            list_enhanced_wordlists
            ;;
        --update|-u)
            if [[ -z "$2" ]]; then
                echo -e "${RED}Error: Please provide an enhanced wordlist name.${NC}"
                echo -e "${YELLOW}Usage: $0 --update <name> [target]${NC}"
                exit 1
            fi
            
            if [[ -z "$3" ]]; then
                # Try to find matching target wordlist
                target=""
                if [[ -f "${WORDLIST_DIR}/${2}.txt" ]]; then
                    target="$2"
                elif [[ "$2" == *"xss"* && -f "${WORDLIST_DIR}/xss_payloads.txt" ]]; then
                    target="xss_payloads"
                elif [[ "$2" == *"sql"* && -f "${WORDLIST_DIR}/sqli_payloads.txt" ]]; then
                    target="sqli_payloads"
                elif [[ "$2" == *"ssrf"* && -f "${WORDLIST_DIR}/ssrf_payloads.txt" ]]; then
                    target="ssrf_payloads"
                elif [[ "$2" == *"redirect"* && -f "${WORDLIST_DIR}/openredirect_payloads.txt" ]]; then
                    target="openredirect_payloads"
                elif [[ "$2" == *"jwt"* && -f "${WORDLIST_DIR}/jwt_secrets.txt" ]]; then
                    target="jwt_secrets"
                else
                    target="new"
                fi
                echo -e "${YELLOW}No target specified, using target: $target${NC}"
                update_wordlist "$2" "$target"
            else
                update_wordlist "$2" "$3"
            fi
            ;;
        --update-all|-ua)
            update_all_wordlists
            ;;
        --create|-c)
            create_enhanced_template "$2"
            ;;
        --help|-h)
            show_usage
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            show_usage
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"