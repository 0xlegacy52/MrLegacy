#!/bin/bash
# MR Legacy - Cloud Enumeration Module

# Function to discover AWS S3 buckets
discover_s3_buckets() {
    local domain="$1"
    local output_file="$2"
    
    log_message "Searching for AWS S3 buckets related to $domain..." "INFO"
    
    # Extract the base domain without TLD
    local base_domain=$(echo "$domain" | sed -E 's/\.[^.]+$//')
    
    # Common bucket name patterns
    local patterns=(
        "$domain"
        "$base_domain"
        "www-$base_domain"
        "www.$base_domain"
        "$base_domain-prod"
        "$base_domain-dev"
        "$base_domain-stage"
        "$base_domain-staging"
        "$base_domain-test"
        "$base_domain-backup"
        "$base_domain-bk"
        "$base_domain-data"
        "$base_domain-files"
        "$base_domain-media"
        "$base_domain-uploads"
        "$base_domain-static"
        "$base_domain-assets"
        "$base_domain-images"
        "$base_domain-img"
        "$base_domain-docs"
        "$base_domain-documents"
        "backup-$base_domain"
        "backups-$base_domain"
        "media-$base_domain"
        "static-$base_domain"
        "assets-$base_domain"
        "files-$base_domain"
    )
    
    # Check each potential bucket
    for pattern in "${patterns[@]}"; do
        local bucket_url="https://$pattern.s3.amazonaws.com"
        local status=$(curl -s -o /dev/null -w "%{http_code}" "$bucket_url")
        
        if [ "$status" = "200" ] || [ "$status" = "403" ]; then
            log_message "Found S3 bucket: $bucket_url (Status: $status)" "SUCCESS"
            echo "$bucket_url" >> "$output_file"
            
            # Check for bucket listing
            if [ "$status" = "200" ]; then
                log_message "Bucket listing enabled for $bucket_url!" "SUCCESS"
                echo "$bucket_url (Listing Enabled)" >> "$output_file"
                
                # Save bucket listing
                curl -s "$bucket_url" -o "$output_file.$(echo $pattern | tr '.' '_')_listing.xml" 2>/dev/null
            fi
        fi
    done
}

# Function to discover Azure Blob Storage
discover_azure_storage() {
    local domain="$1"
    local output_file="$2"
    
    log_message "Searching for Azure Blob Storage related to $domain..." "INFO"
    
    # Extract the base domain without TLD
    local base_domain=$(echo "$domain" | sed -E 's/\.[^.]+$//')
    
    # Common storage account name patterns
    local patterns=(
        "$base_domain"
        "${base_domain//-/}"  # Remove hyphens
        "storage$base_domain"
        "${base_domain}storage"
        "${base_domain}prod"
        "${base_domain}dev"
        "${base_domain}stage"
        "${base_domain}test"
        "${base_domain}static"
        "${base_domain}media"
        "${base_domain}files"
        "${base_domain}assets"
        "${base_domain}blob"
        "static$base_domain"
        "media$base_domain"
        "files$base_domain"
        "assets$base_domain"
    )
    
    # Check each potential storage account
    for pattern in "${patterns[@]}"; do
        # Azure storage account names must be lowercase and alphanumeric
        local sanitized_pattern=$(echo "$pattern" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')
        local storage_url="https://$sanitized_pattern.blob.core.windows.net"
        local status=$(curl -s -o /dev/null -w "%{http_code}" "$storage_url")
        
        if [ "$status" = "200" ] || [ "$status" = "400" ] || [ "$status" = "403" ]; then
            log_message "Found Azure Blob Storage: $storage_url (Status: $status)" "SUCCESS"
            echo "$storage_url" >> "$output_file"
            
            # Try to list containers
            local list_url="$storage_url/?comp=list"
            local list_status=$(curl -s -o /dev/null -w "%{http_code}" "$list_url")
            
            if [ "$list_status" = "200" ]; then
                log_message "Container listing enabled for $storage_url!" "SUCCESS"
                echo "$storage_url (Listing Enabled)" >> "$output_file"
                
                # Save container listing
                curl -s "$list_url" -o "$output_file.$(echo $sanitized_pattern | tr '.' '_')_listing.xml" 2>/dev/null
            fi
        fi
    done
}

# Function to discover Google Cloud Storage buckets
discover_gcs_buckets() {
    local domain="$1"
    local output_file="$2"
    
    log_message "Searching for Google Cloud Storage buckets related to $domain..." "INFO"
    
    # Extract the base domain without TLD
    local base_domain=$(echo "$domain" | sed -E 's/\.[^.]+$//')
    
    # Common bucket name patterns
    local patterns=(
        "$domain"
        "$base_domain"
        "$base_domain-prod"
        "$base_domain-dev"
        "$base_domain-stage"
        "$base_domain-test"
        "$base_domain-backup"
        "$base_domain-data"
        "$base_domain-files"
        "$base_domain-media"
        "$base_domain-static"
        "$base_domain-assets"
    )
    
    # Check each potential bucket
    for pattern in "${patterns[@]}"; do
        local bucket_url="https://storage.googleapis.com/$pattern"
        local status=$(curl -s -o /dev/null -w "%{http_code}" "$bucket_url")
        
        if [ "$status" = "200" ] || [ "$status" = "403" ]; then
            log_message "Found GCS bucket: $bucket_url (Status: $status)" "SUCCESS"
            echo "$bucket_url" >> "$output_file"
            
            # Check for bucket listing
            if [ "$status" = "200" ]; then
                log_message "Bucket listing enabled for $bucket_url!" "SUCCESS"
                echo "$bucket_url (Listing Enabled)" >> "$output_file"
                
                # Save bucket listing
                curl -s "$bucket_url" -o "$output_file.$(echo $pattern | tr '.' '_')_listing.xml" 2>/dev/null
            fi
        fi
    done
}

# Function to discover Firebase instances
discover_firebase() {
    local domain="$1"
    local output_file="$2"
    
    log_message "Searching for Firebase instances related to $domain..." "INFO"
    
    # Extract the base domain without TLD
    local base_domain=$(echo "$domain" | sed -E 's/\.[^.]+$//')
    
    # Common Firebase instance name patterns
    local patterns=(
        "$base_domain"
        "$base_domain-app"
        "$base_domain-web"
        "$base_domain-api"
        "$base_domain-prod"
        "$base_domain-dev"
        "$base_domain-staging"
        "app-$base_domain"
        "api-$base_domain"
    )
    
    # Check each potential Firebase instance
    for pattern in "${patterns[@]}"; do
        # Firebase project IDs must be lowercase and can include hyphens
        local sanitized_pattern=$(echo "$pattern" | tr '[:upper:]' '[:lower:]')
        local firebase_url="https://$sanitized_pattern.firebaseio.com/.json"
        local status=$(curl -s -o /dev/null -w "%{http_code}" "$firebase_url")
        
        if [ "$status" = "200" ] || [ "$status" = "401" ] || [ "$status" = "403" ]; then
            log_message "Found Firebase instance: $firebase_url (Status: $status)" "SUCCESS"
            echo "https://$sanitized_pattern.firebaseio.com" >> "$output_file"
            
            # If public access is allowed
            if [ "$status" = "200" ]; then
                log_message "Firebase instance has public data: $firebase_url!" "SUCCESS"
                echo "https://$sanitized_pattern.firebaseio.com (Public Data)" >> "$output_file"
                
                # Save Firebase data
                curl -s "$firebase_url" -o "$output_file.$(echo $sanitized_pattern | tr '.' '_')_firebase.json" 2>/dev/null
            fi
        fi
    done
}

# Function to discover Cloudfront distributions
discover_cloudfront() {
    local domain="$1"
    local subdomains_file="$2"
    local output_file="$3"
    
    log_message "Searching for Cloudfront distributions related to $domain..." "INFO"
    
    # Check if subdomains file exists
    if [ -f "$subdomains_file" ]; then
        # Check each subdomain for Cloudfront
        while IFS= read -r subdomain || [[ -n "$subdomain" ]]; do
            # Skip empty lines
            if [ -z "$subdomain" ]; then
                continue
            fi
            
            # Get headers
            local headers_file=$(mktemp)
            curl -s -I "https://$subdomain" > "$headers_file" 2>/dev/null
            
            # Check for Cloudfront indicators in headers
            if grep -q -i "cloudfront" "$headers_file" || grep -q -i "x-amz-cf-id" "$headers_file"; then
                log_message "Found Cloudfront distribution for $subdomain" "SUCCESS"
                echo "https://$subdomain (Cloudfront)" >> "$output_file"
            fi
            
            # Clean up
            rm -f "$headers_file"
        done < "$subdomains_file"
    else
        log_message "Subdomains file not found. Run subdomain enumeration first." "WARNING"
    fi
}

# Function to discover Digital Ocean Spaces
discover_do_spaces() {
    local domain="$1"
    local output_file="$2"
    
    log_message "Searching for Digital Ocean Spaces related to $domain..." "INFO"
    
    # Extract the base domain without TLD
    local base_domain=$(echo "$domain" | sed -E 's/\.[^.]+$//')
    
    # Common space name patterns
    local patterns=(
        "$base_domain"
        "$base_domain-space"
        "$base_domain-storage"
        "$base_domain-files"
        "$base_domain-media"
        "$base_domain-static"
        "$base_domain-assets"
    )
    
    # Digital Ocean regions
    local regions=(
        "nyc3"
        "sfo2"
        "sfo3"
        "ams3"
        "sgp1"
        "fra1"
    )
    
    # Check each potential space in each region
    for pattern in "${patterns[@]}"; do
        for region in "${regions[@]}"; do
            local space_url="https://$pattern.$region.digitaloceanspaces.com"
            local status=$(curl -s -o /dev/null -w "%{http_code}" "$space_url")
            
            if [ "$status" = "200" ] || [ "$status" = "403" ]; then
                log_message "Found DO Space: $space_url (Status: $status)" "SUCCESS"
                echo "$space_url" >> "$output_file"
                
                # Check for space listing
                if [ "$status" = "200" ]; then
                    log_message "Space listing enabled for $space_url!" "SUCCESS"
                    echo "$space_url (Listing Enabled)" >> "$output_file"
                    
                    # Save space listing
                    curl -s "$space_url" -o "$output_file.$(echo $pattern | tr '.' '_')_$region_listing.xml" 2>/dev/null
                fi
            fi
        done
    done
}

# Function to run cloud enumeration
run_cloud_enum() {
    log_message "Starting cloud resources enumeration for $target..." "INFO"
    
    # Setup Tor proxy if enabled
    setup_tor_proxy
    
    # Create output directory
    local output_dir="$target_dir/cloud"
    mkdir -p "$output_dir"
    
    # Extract domain
    local domain=$(extract_domain "$target")
    
    # Output file for all cloud resources
    local cloud_resources_file="$output_dir/cloud_resources.txt"
    
    # Create empty file
    > "$cloud_resources_file"
    
    # Run different cloud enumeration methods
    discover_s3_buckets "$domain" "$cloud_resources_file"
    discover_azure_storage "$domain" "$cloud_resources_file"
    discover_gcs_buckets "$domain" "$cloud_resources_file"
    discover_firebase "$domain" "$cloud_resources_file"
    discover_do_spaces "$domain" "$cloud_resources_file"
    
    # Get subdomains file for Cloudfront discovery
    local subdomains_file="$target_dir/subdomains/all_subdomains.txt"
    if [ -f "$subdomains_file" ]; then
        discover_cloudfront "$domain" "$subdomains_file" "$cloud_resources_file"
    fi
    
    # Check if any cloud resources were found
    if [ -s "$cloud_resources_file" ]; then
        # Count resources
        local count=$(wc -l < "$cloud_resources_file")
        log_message "Found $count cloud resources" "SUCCESS"
        
        # Save results in different formats
        save_results "$cloud_resources_file" "$output_dir" "cloud_resources" "$output_format"
    else
        log_message "No cloud resources found" "INFO"
        echo "No cloud resources found for $domain" > "$cloud_resources_file"
        
        # Save results in different formats
        save_results "$cloud_resources_file" "$output_dir" "cloud_resources" "$output_format"
    fi
    
    log_message "Cloud resources enumeration completed" "SUCCESS"
    return 0
}
