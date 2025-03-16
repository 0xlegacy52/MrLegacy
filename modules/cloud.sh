#!/bin/bash

# MR Legacy - Cloud Module
# Author: Abdulrahman Muhammad (0xLegacy)
# Version: 1.1.0

# Create necessary variables to track module execution
CALLED_FN_DIR="${target_dir}/.called_fn"
mkdir -p "$CALLED_FN_DIR" 2>/dev/null
chmod 755 "$CALLED_FN_DIR" 2>/dev/null

# Function to check for AWS S3 buckets
function aws_s3_check() {
    if is_completed "aws_s3_check"; then
        log_message "AWS S3 check already completed for $target" "INFO"
        return 0
    fi
    
    start_function "aws_s3_check" "AWS S3 Bucket Check for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/cloud/aws" 2>/dev/null
    local output_file="${target_dir}/cloud/aws/s3_buckets.txt"
    
    # Check if target is valid
    if ! is_valid_domain "$target" && ! is_valid_ip "$target"; then
        log_message "Target doesn't appear to be a valid domain or IP. Skipping AWS S3 check." "ERROR"
        echo "Target is not a valid domain or IP for AWS S3 check." > "$output_file"
        end_function "aws_s3_check" 1 "AWS S3 check skipped - invalid target"
        return 1
    fi
    
    log_message "Starting AWS S3 bucket check for $target" "INFO"
    
    # Create potential bucket names based on target
    local bucket_names=()
    
    # Extract domain without TLD
    if is_valid_domain "$target"; then
        local domain_name=$(echo "$target" | awk -F '.' '{print $(NF-1)}')
        local full_domain=$(echo "$target" | sed 's/https\?:\/\///' | sed 's/\/$//')
        
        # Add variations
        bucket_names+=("$domain_name")
        bucket_names+=("$full_domain")
        bucket_names+=("${domain_name}-backup")
        bucket_names+=("${domain_name}-media")
        bucket_names+=("${domain_name}-static")
        bucket_names+=("${domain_name}-assets")
        bucket_names+=("${domain_name}-public")
        bucket_names+=("${domain_name}-private")
        bucket_names+=("${domain_name}-dev")
        bucket_names+=("${domain_name}-prod")
        bucket_names+=("${domain_name}-production")
        bucket_names+=("${domain_name}-staging")
        bucket_names+=("${domain_name}-test")
        bucket_names+=("${domain_name}-data")
        bucket_names+=("${domain_name}-files")
        bucket_names+=("${domain_name}-content")
    else
        log_message "Target is not a domain. Using limited bucket name variations." "WARNING"
        bucket_names+=("$target")
        bucket_names+=("${target}-backup")
        bucket_names+=("${target}-data")
    fi
    
    # Create a temporary file with the bucket names
    local bucket_list="${target_dir}/.tmp/bucket_names.txt"
    mkdir -p "${target_dir}/.tmp" 2>/dev/null
    
    for bucket_name in "${bucket_names[@]}"; do
        echo "$bucket_name" >> "$bucket_list"
    done
    
    # Check if AWS CLI is available
    if command_exists "aws"; then
        log_message "Using AWS CLI to check S3 buckets" "INFO"
        
        > "$output_file"
        
        while read -r bucket_name; do
            [[ -z "$bucket_name" ]] && continue
            
            log_message "Checking S3 bucket: $bucket_name" "DEBUG"
            
            # Check if bucket exists and is publicly accessible
            if aws s3 ls "s3://${bucket_name}" --no-sign-request &>/dev/null; then
                log_message "Found publicly accessible S3 bucket: $bucket_name" "SUCCESS"
                echo "Publicly accessible S3 bucket: s3://${bucket_name}" >> "$output_file"
                
                # List files in the bucket
                aws s3 ls "s3://${bucket_name}" --no-sign-request --recursive | head -n 20 > "${target_dir}/cloud/aws/${bucket_name}_files.txt" 2>/dev/null
            fi
        done < "$bucket_list"
        
    # If AWS CLI is not available, use curl
    elif command_exists "curl"; then
        log_message "AWS CLI not found. Using curl for basic S3 bucket checks." "WARNING"
        
        > "$output_file"
        
        while read -r bucket_name; do
            [[ -z "$bucket_name" ]] && continue
            
            log_message "Checking S3 bucket: $bucket_name" "DEBUG"
            
            # Check if bucket exists using curl
            local status_code=$(curl -s -o /dev/null -w "%{http_code}" "https://${bucket_name}.s3.amazonaws.com")
            
            if [[ "$status_code" != "404" ]]; then
                log_message "Found potential S3 bucket: $bucket_name (Status: $status_code)" "SUCCESS"
                echo "Potential S3 bucket: https://${bucket_name}.s3.amazonaws.com (Status: $status_code)" >> "$output_file"
                
                # Try to list bucket contents
                curl -s "https://${bucket_name}.s3.amazonaws.com" > "${target_dir}/.tmp/${bucket_name}_response.xml"
                
                if grep -q "<Contents>" "${target_dir}/.tmp/${bucket_name}_response.xml"; then
                    log_message "Bucket appears to be publicly listable" "WARNING"
                    echo "Bucket appears to be publicly listable" >> "$output_file"
                    
                    # Extract file names if possible
                    grep -o "<Key>[^<]*</Key>" "${target_dir}/.tmp/${bucket_name}_response.xml" | sed 's/<Key>//' | sed 's/<\/Key>//' > "${target_dir}/cloud/aws/${bucket_name}_files.txt"
                fi
            fi
        done < "$bucket_list"
    else
        log_message "No tools available for S3 bucket checking. Skipping." "ERROR"
        echo "AWS S3 bucket check skipped - no tools available" > "$output_file"
        end_function "aws_s3_check" 1 "AWS S3 check skipped - no tools available"
        return 1
    fi
    
    # Check results
    if [[ -s "$output_file" ]]; then
        local bucket_count=$(wc -l < "$output_file")
        log_message "AWS S3 bucket check completed. Found $bucket_count potential buckets." "SUCCESS"
        end_function "aws_s3_check" 0 "AWS S3 bucket check completed successfully"
        return 0
    else
        log_message "No AWS S3 buckets found" "INFO"
        echo "No AWS S3 buckets found" > "$output_file"
        end_function "aws_s3_check" 0 "AWS S3 bucket check completed - no buckets found"
        return 0
    fi
}

# Function to check for Azure blob storage
function azure_blob_check() {
    if is_completed "azure_blob_check"; then
        log_message "Azure blob check already completed for $target" "INFO"
        return 0
    fi
    
    start_function "azure_blob_check" "Azure Blob Storage Check for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/cloud/azure" 2>/dev/null
    local output_file="${target_dir}/cloud/azure/blob_storage.txt"
    
    # Check if target is valid
    if ! is_valid_domain "$target" && ! is_valid_ip "$target"; then
        log_message "Target doesn't appear to be a valid domain or IP. Skipping Azure blob check." "ERROR"
        echo "Target is not a valid domain or IP for Azure blob check." > "$output_file"
        end_function "azure_blob_check" 1 "Azure blob check skipped - invalid target"
        return 1
    fi
    
    log_message "Starting Azure blob storage check for $target" "INFO"
    
    # Create potential storage account names based on target
    local storage_accounts=()
    
    # Extract domain without TLD
    if is_valid_domain "$target"; then
        local domain_name=$(echo "$target" | awk -F '.' '{print $(NF-1)}')
        
        # Add variations (Azure storage names must be between 3 and 24 characters, lowercase letters and numbers only)
        # Convert to lowercase and remove non-alphanumeric characters
        domain_name=$(echo "$domain_name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
        
        if [[ ${#domain_name} -ge 3 ]]; then
            storage_accounts+=("$domain_name")
            storage_accounts+=("${domain_name}storage")
            storage_accounts+=("${domain_name}blob")
            storage_accounts+=("${domain_name}media")
            storage_accounts+=("${domain_name}assets")
            storage_accounts+=("${domain_name}static")
            storage_accounts+=("${domain_name}dev")
            storage_accounts+=("${domain_name}prod")
            storage_accounts+=("${domain_name}test")
            storage_accounts+=("${domain_name}stage")
        else
            log_message "Domain name too short for valid Azure storage account. Using generic names." "WARNING"
            storage_accounts+=("${domain_name}storage")
            storage_accounts+=("${domain_name}company")
            storage_accounts+=("${domain_name}enterprise")
        fi
    else
        log_message "Target is not a domain. Using limited storage account name variations." "WARNING"
        local target_clean=$(echo "$target" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
        if [[ ${#target_clean} -ge 3 ]]; then
            storage_accounts+=("$target_clean")
            storage_accounts+=("${target_clean}storage")
        else
            log_message "Target name too short for valid Azure storage account. Skipping." "ERROR"
            echo "Azure blob check skipped - target name too short" > "$output_file"
            end_function "azure_blob_check" 1 "Azure blob check skipped - target name too short"
            return 1
        fi
    fi
    
    # Create a temporary file with the storage account names
    local account_list="${target_dir}/.tmp/azure_accounts.txt"
    mkdir -p "${target_dir}/.tmp" 2>/dev/null
    
    for account_name in "${storage_accounts[@]}"; do
        if [[ ${#account_name} -le 24 && ${#account_name} -ge 3 ]]; then
            echo "$account_name" >> "$account_list"
        fi
    done
    
    # Check Azure blobs using curl
    if command_exists "curl"; then
        log_message "Using curl for Azure blob storage checks" "INFO"
        
        > "$output_file"
        
        while read -r account_name; do
            [[ -z "$account_name" ]] && continue
            
            log_message "Checking Azure blob storage: $account_name" "DEBUG"
            
            # Check if storage account exists
            local blob_url="https://${account_name}.blob.core.windows.net"
            local status_code=$(curl -s -o /dev/null -w "%{http_code}" "$blob_url")
            
            if [[ "$status_code" != "404" ]]; then
                log_message "Found potential Azure blob storage: $account_name (Status: $status_code)" "SUCCESS"
                echo "Potential Azure blob storage: $blob_url (Status: $status_code)" >> "$output_file"
                
                # Check for common containers
                local containers=("public" "private" "media" "assets" "static" "images" "files" "documents" "backup" "data")
                
                for container in "${containers[@]}"; do
                    local container_url="${blob_url}/${container}"
                    local container_status=$(curl -s -o /dev/null -w "%{http_code}" "$container_url")
                    
                    if [[ "$container_status" != "404" ]]; then
                        log_message "Found potential container: $container (Status: $container_status)" "SUCCESS"
                        echo "Potential container: ${container_url} (Status: $container_status)" >> "$output_file"
                        
                        # Try to list contents
                        curl -s "$container_url?restype=container&comp=list" > "${target_dir}/.tmp/${account_name}_${container}_response.xml"
                        
                        if grep -q "<Blob>" "${target_dir}/.tmp/${account_name}_${container}_response.xml"; then
                            log_message "Container appears to be publicly listable" "WARNING"
                            echo "Container appears to be publicly listable" >> "$output_file"
                            
                            # Extract file names if possible
                            grep -o "<Name>[^<]*</Name>" "${target_dir}/.tmp/${account_name}_${container}_response.xml" | sed 's/<Name>//' | sed 's/<\/Name>//' > "${target_dir}/cloud/azure/${account_name}_${container}_files.txt"
                        fi
                    fi
                done
            fi
        done < "$account_list"
    else
        log_message "No tools available for Azure blob checking. Skipping." "ERROR"
        echo "Azure blob check skipped - no tools available" > "$output_file"
        end_function "azure_blob_check" 1 "Azure blob check skipped - no tools available"
        return 1
    fi
    
    # Check results
    if [[ -s "$output_file" ]]; then
        local storage_count=$(grep -c "Potential Azure blob storage:" "$output_file")
        local container_count=$(grep -c "Potential container:" "$output_file")
        log_message "Azure blob check completed. Found $storage_count potential storage accounts and $container_count containers." "SUCCESS"
        end_function "azure_blob_check" 0 "Azure blob check completed successfully"
        return 0
    else
        log_message "No Azure blob storage found" "INFO"
        echo "No Azure blob storage found" > "$output_file"
        end_function "azure_blob_check" 0 "Azure blob check completed - no storage found"
        return 0
    fi
}

# Function to check for Google Cloud Storage buckets
function gcp_storage_check() {
    if is_completed "gcp_storage_check"; then
        log_message "GCP storage check already completed for $target" "INFO"
        return 0
    fi
    
    start_function "gcp_storage_check" "Google Cloud Storage Check for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/cloud/gcp" 2>/dev/null
    local output_file="${target_dir}/cloud/gcp/gcs_buckets.txt"
    
    # Check if target is valid
    if ! is_valid_domain "$target" && ! is_valid_ip "$target"; then
        log_message "Target doesn't appear to be a valid domain or IP. Skipping GCP storage check." "ERROR"
        echo "Target is not a valid domain or IP for GCP storage check." > "$output_file"
        end_function "gcp_storage_check" 1 "GCP storage check skipped - invalid target"
        return 1
    fi
    
    log_message "Starting Google Cloud Storage check for $target" "INFO"
    
    # Create potential bucket names based on target
    local bucket_names=()
    
    # Extract domain without TLD
    if is_valid_domain "$target"; then
        local domain_name=$(echo "$target" | awk -F '.' '{print $(NF-1)}')
        local full_domain=$(echo "$target" | sed 's/https\?:\/\///' | sed 's/\/$//')
        
        # Add variations
        bucket_names+=("$domain_name")
        bucket_names+=("$full_domain")
        bucket_names+=("${domain_name}-backup")
        bucket_names+=("${domain_name}-media")
        bucket_names+=("${domain_name}-static")
        bucket_names+=("${domain_name}-assets")
        bucket_names+=("${domain_name}-public")
        bucket_names+=("${domain_name}-storage")
        bucket_names+=("${domain_name}-gcs")
        bucket_names+=("${domain_name}-bucket")
    else
        log_message "Target is not a domain. Using limited bucket name variations." "WARNING"
        bucket_names+=("$target")
        bucket_names+=("${target}-storage")
        bucket_names+=("${target}-bucket")
    fi
    
    # Create a temporary file with the bucket names
    local bucket_list="${target_dir}/.tmp/gcs_bucket_names.txt"
    mkdir -p "${target_dir}/.tmp" 2>/dev/null
    
    for bucket_name in "${bucket_names[@]}"; do
        echo "$bucket_name" >> "$bucket_list"
    done
    
    # Check if gcloud CLI is available
    if command_exists "gsutil"; then
        log_message "Using gsutil to check GCS buckets" "INFO"
        
        > "$output_file"
        
        while read -r bucket_name; do
            [[ -z "$bucket_name" ]] && continue
            
            log_message "Checking GCS bucket: $bucket_name" "DEBUG"
            
            # Check if bucket exists and is publicly accessible
            if gsutil ls "gs://${bucket_name}" &>/dev/null; then
                log_message "Found accessible GCS bucket: $bucket_name" "SUCCESS"
                echo "Accessible GCS bucket: gs://${bucket_name}" >> "$output_file"
                
                # List files in the bucket
                gsutil ls -r "gs://${bucket_name}" | head -n 20 > "${target_dir}/cloud/gcp/${bucket_name}_files.txt" 2>/dev/null
            fi
        done < "$bucket_list"
        
    # If gsutil is not available, use curl
    elif command_exists "curl"; then
        log_message "gsutil not found. Using curl for basic GCS bucket checks." "WARNING"
        
        > "$output_file"
        
        while read -r bucket_name; do
            [[ -z "$bucket_name" ]] && continue
            
            log_message "Checking GCS bucket: $bucket_name" "DEBUG"
            
            # Check if bucket exists using curl
            local status_code=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${bucket_name}")
            
            if [[ "$status_code" != "404" ]]; then
                log_message "Found potential GCS bucket: $bucket_name (Status: $status_code)" "SUCCESS"
                echo "Potential GCS bucket: https://storage.googleapis.com/${bucket_name} (Status: $status_code)" >> "$output_file"
                
                # Try to list bucket contents
                curl -s "https://storage.googleapis.com/${bucket_name}" > "${target_dir}/.tmp/${bucket_name}_response.xml"
                
                if grep -q "<Contents>" "${target_dir}/.tmp/${bucket_name}_response.xml"; then
                    log_message "Bucket appears to be publicly listable" "WARNING"
                    echo "Bucket appears to be publicly listable" >> "$output_file"
                    
                    # Extract file names if possible
                    grep -o "<Key>[^<]*</Key>" "${target_dir}/.tmp/${bucket_name}_response.xml" | sed 's/<Key>//' | sed 's/<\/Key>//' > "${target_dir}/cloud/gcp/${bucket_name}_files.txt"
                fi
            fi
        done < "$bucket_list"
    else
        log_message "No tools available for GCS bucket checking. Skipping." "ERROR"
        echo "GCP storage check skipped - no tools available" > "$output_file"
        end_function "gcp_storage_check" 1 "GCP storage check skipped - no tools available"
        return 1
    fi
    
    # Check results
    if [[ -s "$output_file" ]]; then
        local bucket_count=$(wc -l < "$output_file")
        log_message "GCP storage check completed. Found $bucket_count potential buckets." "SUCCESS"
        end_function "gcp_storage_check" 0 "GCP storage check completed successfully"
        return 0
    else
        log_message "No Google Cloud Storage buckets found" "INFO"
        echo "No Google Cloud Storage buckets found" > "$output_file"
        end_function "gcp_storage_check" 0 "GCP storage check completed - no buckets found"
        return 0
    fi
}

# Function to compile a summary of all cloud resources
function cloud_summary() {
    if is_completed "cloud_summary"; then
        log_message "Cloud resources summary already completed for $target" "INFO"
        return 0
    fi
    
    start_function "cloud_summary" "Cloud Resources Summary for $target"
    
    # Create output directories
    mkdir -p "${target_dir}/cloud" 2>/dev/null
    local output_file="${target_dir}/cloud/cloud_resources.txt"
    local json_output="${target_dir}/cloud/cloud_resources.json"
    
    log_message "Compiling cloud resources summary" "INFO"
    
    # Initialize summary files
    > "$output_file"
    echo "{" > "$json_output"
    echo "  \"aws_resources\": [" >> "$json_output"
    
    # Check for AWS resources
    local aws_s3_file="${target_dir}/cloud/aws/s3_buckets.txt"
    if [[ -f "$aws_s3_file" && -s "$aws_s3_file" ]]; then
        echo "AWS S3 Buckets:" >> "$output_file"
        cat "$aws_s3_file" >> "$output_file"
        echo "" >> "$output_file"
        
        # Add to JSON
        local first_item=true
        while read -r line; do
            [[ -z "$line" ]] && continue
            
            if [[ "$first_item" == true ]]; then
                echo "    {\"type\": \"s3_bucket\", \"resource\": \"$line\"}" >> "$json_output"
                first_item=false
            else
                echo "    ,{\"type\": \"s3_bucket\", \"resource\": \"$line\"}" >> "$json_output"
            fi
        done < "$aws_s3_file"
    fi
    
    echo "  ]," >> "$json_output"
    echo "  \"azure_resources\": [" >> "$json_output"
    
    # Check for Azure resources
    local azure_blob_file="${target_dir}/cloud/azure/blob_storage.txt"
    if [[ -f "$azure_blob_file" && -s "$azure_blob_file" ]]; then
        echo "Azure Blob Storage:" >> "$output_file"
        cat "$azure_blob_file" >> "$output_file"
        echo "" >> "$output_file"
        
        # Add to JSON
        local first_item=true
        while read -r line; do
            [[ -z "$line" ]] && continue
            
            if [[ "$first_item" == true ]]; then
                echo "    {\"type\": \"blob_storage\", \"resource\": \"$line\"}" >> "$json_output"
                first_item=false
            else
                echo "    ,{\"type\": \"blob_storage\", \"resource\": \"$line\"}" >> "$json_output"
            fi
        done < "$azure_blob_file"
    fi
    
    echo "  ]," >> "$json_output"
    echo "  \"gcp_resources\": [" >> "$json_output"
    
    # Check for GCP resources
    local gcp_storage_file="${target_dir}/cloud/gcp/gcs_buckets.txt"
    if [[ -f "$gcp_storage_file" && -s "$gcp_storage_file" ]]; then
        echo "Google Cloud Storage:" >> "$output_file"
        cat "$gcp_storage_file" >> "$output_file"
        echo "" >> "$output_file"
        
        # Add to JSON
        local first_item=true
        while read -r line; do
            [[ -z "$line" ]] && continue
            
            if [[ "$first_item" == true ]]; then
                echo "    {\"type\": \"gcs_bucket\", \"resource\": \"$line\"}" >> "$json_output"
                first_item=false
            else
                echo "    ,{\"type\": \"gcs_bucket\", \"resource\": \"$line\"}" >> "$json_output"
            fi
        done < "$gcp_storage_file"
    fi
    
    echo "  ]" >> "$json_output"
    echo "}" >> "$json_output"
    
    # Check if we found any cloud resources
    if [[ -s "$output_file" ]]; then
        local resource_count=$(grep -v "^$" "$output_file" | grep -v ":" | wc -l)
        log_message "Cloud resources summary completed. Found $resource_count cloud resources." "SUCCESS"
        end_function "cloud_summary" 0 "Cloud resources summary completed successfully"
        return 0
    else
        log_message "No cloud resources found" "INFO"
        echo "No cloud resources found for target: $target" > "$output_file"
        echo "{\"aws_resources\": [], \"azure_resources\": [], \"gcp_resources\": []}" > "$json_output"
        end_function "cloud_summary" 0 "Cloud resources summary completed - no resources found"
        return 0
    fi
}

# Main cloud discovery function
function run_cloud_module() {
    log_message "Starting cloud resources discovery module for $target" "INFO"
    
    # Create output directories
    mkdir -p "${target_dir}/cloud" 2>/dev/null
    mkdir -p "${target_dir}/.tmp" 2>/dev/null
    
    # Create .called_fn directory with proper permissions
    CALLED_FN_DIR="${target_dir}/.called_fn"
    mkdir -p "$CALLED_FN_DIR" 2>/dev/null
    chmod 755 "$CALLED_FN_DIR" 2>/dev/null
    
    # Show banner
    show_cloud_banner
    
    # Run cloud discovery functions
    aws_s3_check
    azure_blob_check
    gcp_storage_check
    
    # Generate summary
    cloud_summary
    
    # Clean up temp files
    rm -rf "${target_dir}/.tmp" 2>/dev/null
    
    log_message "Cloud resources discovery module completed for $target" "SUCCESS"
}

# Export functions
export -f aws_s3_check
export -f azure_blob_check
export -f gcp_storage_check
export -f cloud_summary
export -f run_cloud_module