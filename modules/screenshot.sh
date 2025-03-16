#!/bin/bash
# MR Legacy - Screenshot Module

# Function to run Gowitness
run_gowitness() {
    local input_file="$1"
    local output_dir="$2"
    
    if is_tool_installed "gowitness"; then
        log_message "Taking screenshots with Gowitness..." "INFO"
        
        # Make sure the output directory exists
        mkdir -p "$output_dir"
        
        # Create a file with URLs for Gowitness
        grep -E "^https?://" "$input_file" > "$output_dir/urls_to_screenshot.txt"
        
        if [ -s "$output_dir/urls_to_screenshot.txt" ]; then
            # Run Gowitness
            gowitness file -f "$output_dir/urls_to_screenshot.txt" -P "$output_dir" --no-http > /dev/null 2>&1
            
            if [ $? -eq 0 ]; then
                log_message "Gowitness completed successfully" "SUCCESS"
                
                # Generate report
                gowitness report serve -a 127.0.0.1:7171 --disable-logging > /dev/null 2>&1 &
                gowitness_pid=$!
                
                sleep 2
                log_message "Gowitness report available at http://127.0.0.1:7171" "INFO"
                log_message "Press Ctrl+C to stop the report server when done" "INFO"
                
                # Wait for user to finish viewing the report
                read -p "Press Enter to continue..."
                
                # Kill the report server
                kill $gowitness_pid 2>/dev/null
            else
                log_message "Gowitness failed" "ERROR"
            fi
        else
            log_message "No URLs to screenshot" "WARNING"
        fi
    else
        log_message "Gowitness not found" "WARNING"
    fi
}

# Function to run Aquatone
run_aquatone() {
    local input_file="$1"
    local output_dir="$2"
    
    if is_tool_installed "aquatone"; then
        log_message "Taking screenshots with Aquatone..." "INFO"
        
        # Make sure the output directory exists
        mkdir -p "$output_dir"
        
        # Extract URLs and remove any protocols
        grep -E "^https?://" "$input_file" | sed 's|^https\?://||' > "$output_dir/hosts_to_screenshot.txt"
        
        if [ -s "$output_dir/hosts_to_screenshot.txt" ]; then
            # Run Aquatone
            cat "$output_dir/hosts_to_screenshot.txt" | aquatone -out "$output_dir/aquatone" -threads "$threads" -silent > /dev/null 2>&1
            
            if [ $? -eq 0 ]; then
                log_message "Aquatone completed successfully" "SUCCESS"
                
                # Create a symlink to the HTML report for easier access
                ln -sf "$output_dir/aquatone/aquatone_report.html" "$output_dir/aquatone_report.html"
                
                log_message "Aquatone report saved to $output_dir/aquatone_report.html" "INFO"
            else
                log_message "Aquatone failed" "ERROR"
            fi
        else
            log_message "No URLs to screenshot" "WARNING"
        fi
    else
        log_message "Aquatone not found" "WARNING"
    fi
}

# Function to create HTML gallery of screenshots
create_screenshot_gallery() {
    local screenshots_dir="$1"
    local output_file="$2"
    
    log_message "Creating screenshot gallery..." "INFO"
    
    # Create HTML header
    cat > "$output_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MR Legacy - Screenshot Gallery</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .gallery {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            grid-gap: 20px;
            margin-top: 20px;
        }
        .gallery-item {
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .gallery-item img {
            width: 100%;
            height: auto;
            display: block;
        }
        .gallery-item .caption {
            padding: 10px;
            background-color: #f9f9f9;
            border-top: 1px solid #ddd;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            font-size: 0.8em;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>MR Legacy - Screenshot Gallery</h1>
        <div class="gallery">
EOF
    
    # Find all screenshot images
    local screenshots=$(find "$screenshots_dir" -type f -name "*.png" -o -name "*.jpg" -o -name "*.jpeg")
    
    # Add each screenshot to the gallery
    for screenshot in $screenshots; do
        # Get the filename without path
        local filename=$(basename "$screenshot")
        
        # Get the hostname from the filename (assuming naming convention)
        local hostname=$(echo "$filename" | sed 's/\.png$//' | sed 's/\.jpg$//' | sed 's/\.jpeg$//')
        
        # Add to gallery
        cat >> "$output_file" << EOF
            <div class="gallery-item">
                <img src="data:image/png;base64,$(base64 -w 0 "$screenshot")" alt="$hostname">
                <div class="caption">$hostname</div>
            </div>
EOF
    done
    
    # Add HTML footer
    cat >> "$output_file" << EOF
        </div>
        <div class="footer">
            <p>Generated by MR Legacy - Bug Bounty Hunting Tool</p>
            <p>Author: Abdulrahman Muhammad (0xLegacy)</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log_message "Screenshot gallery created at $output_file" "SUCCESS"
}

# Main function to run screenshots
run_screenshot() {
    log_message "Starting website screenshots..." "INFO"
    
    # Setup Tor proxy if enabled
    setup_tor_proxy
    
    # Create output directory
    local output_dir="$target_dir/screenshots"
    mkdir -p "$output_dir"
    
    # Live hosts file
    local live_hosts_file="$target_dir/subdomains/live_hosts.txt"
    
    # Check if live hosts file exists
    if [ ! -f "$live_hosts_file" ]; then
        log_message "Live hosts file not found. Run live host detection first." "ERROR"
        return 1
    fi
    
    # Check if file has content
    if [ ! -s "$live_hosts_file" ]; then
        log_message "No live hosts found." "WARNING"
        return 1
    fi
    
    # Try to use Gowitness first, fall back to Aquatone if not available
    if is_tool_installed "gowitness"; then
        run_gowitness "$live_hosts_file" "$output_dir"
    elif is_tool_installed "aquatone"; then
        run_aquatone "$live_hosts_file" "$output_dir"
    else
        log_message "No screenshot tool (Gowitness or Aquatone) found" "ERROR"
        return 1
    fi
    
    # Create screenshot gallery
    create_screenshot_gallery "$output_dir" "$output_dir/screenshot_gallery.html"
    
    log_message "Website screenshots completed" "SUCCESS"
    return 0
}
