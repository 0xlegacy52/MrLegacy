#!/usr/bin/env python3
# MR Legacy - AI Assistant Module
# Analyzes bug bounty findings and provides insights

import os
import sys
import json
import argparse
import logging
from datetime import datetime
import re
from collections import Counter
import textwrap
import time

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("MR Legacy AI")

# ANSI Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class AIAssistant:
    def __init__(self, target, results_dir):
        self.target = target
        self.results_dir = results_dir
        self.data = {}
        self.insights = {}
        self.total_findings = 0
        self.severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        self.report_path = os.path.join(results_dir, "ai_analysis.html")
        
        logger.info(f"{Colors.BLUE}Initializing AI Assistant for target: {target}{Colors.ENDC}")
        logger.info(f"{Colors.BLUE}Results directory: {results_dir}{Colors.ENDC}")
        
    def load_data(self):
        """Load all available data from results directory"""
        logger.info(f"{Colors.BLUE}Loading data from {self.results_dir}...{Colors.ENDC}")
        
        # Track directories to load
        directories = {
            "subdomains": ["all_subdomains.txt", "live_hosts.txt"],
            "ports": ["open_ports.txt", "services.txt"],
            "directories": ["all_directories.txt", "parameters.txt", "vhosts.txt"],
            "vulnerabilities": ["nuclei_vulnerabilities.txt", "xss_vulnerabilities.txt", 
                                "sqli_vulnerabilities.txt", "openredirect_vulnerabilities.txt"],
            "tech": ["whatweb.txt", "security_headers.txt", "waf_detection.txt"],
            "exploitation": ["confirmed_xss.txt", "confirmed_sqli.txt", "cloud_misconfigs.txt", 
                             "upload_vulnerabilities.txt"],
            "cloud": ["cloud_resources.txt"]
        }
        
        # Load data from each directory
        for directory, files in directories.items():
            self.data[directory] = {}
            dir_path = os.path.join(self.results_dir, directory)
            
            if not os.path.exists(dir_path):
                logger.warning(f"{Colors.WARNING}Directory not found: {dir_path}{Colors.ENDC}")
                continue
                
            for file in files:
                file_path = os.path.join(dir_path, file)
                if os.path.exists(file_path):
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            self.data[directory][file] = content
                            logger.info(f"{Colors.GREEN}Loaded {file_path}{Colors.ENDC}")
                    except Exception as e:
                        logger.error(f"{Colors.RED}Error loading {file_path}: {str(e)}{Colors.ENDC}")
                else:
                    logger.warning(f"{Colors.WARNING}File not found: {file_path}{Colors.ENDC}")
                    
        return len(self.data) > 0
    
    def analyze_subdomains(self):
        """Analyze subdomain findings"""
        insights = []
        
        if "subdomains" not in self.data or not self.data["subdomains"]:
            insights.append("No subdomain data available for analysis.")
            return insights
            
        # Count total subdomains
        if "all_subdomains.txt" in self.data["subdomains"]:
            subdomains = self.data["subdomains"]["all_subdomains.txt"].strip().split('\n')
            total_subdomains = len(subdomains)
            insights.append(f"Found {total_subdomains} subdomains.")
            
            # Identify patterns in subdomains
            subdomain_parts = []
            for subdomain in subdomains:
                parts = subdomain.split('.')
                if len(parts) > 1:
                    subdomain_parts.extend(parts[:-2])  # Exclude the main domain
                    
            # Count common subdomain parts
            part_counter = Counter(subdomain_parts)
            common_parts = part_counter.most_common(5)
            if common_parts:
                common_parts_str = ", ".join([f"{part} ({count})" for part, count in common_parts])
                insights.append(f"Common subdomain patterns: {common_parts_str}")
            
            # Identify potential development/staging environments
            dev_environments = [s for s in subdomains if re.search(r'dev|stage|test|uat|qa|demo', s, re.IGNORECASE)]
            if dev_environments:
                insights.append(f"Found {len(dev_environments)} potential development/staging environments.")
                insights.append(f"Example dev environments: {', '.join(dev_environments[:3])}")
                
        # Analyze live hosts
        if "live_hosts.txt" in self.data["subdomains"]:
            live_hosts = self.data["subdomains"]["live_hosts.txt"].strip().split('\n')
            total_live = len(live_hosts)
            if "all_subdomains.txt" in self.data["subdomains"]:
                coverage = (total_live / total_subdomains) * 100 if total_subdomains > 0 else 0
                insights.append(f"Found {total_live} live hosts ({coverage:.1f}% of all subdomains).")
            else:
                insights.append(f"Found {total_live} live hosts.")
                
        return insights
    
    def analyze_ports(self):
        """Analyze port scanning results"""
        insights = []
        
        if "ports" not in self.data or not self.data["ports"]:
            insights.append("No port scanning data available for analysis.")
            return insights
            
        # Analyze open ports
        if "open_ports.txt" in self.data["ports"]:
            open_ports = self.data["ports"]["open_ports.txt"].strip().split('\n')
            total_ports = len(open_ports)
            insights.append(f"Found {total_ports} open ports.")
            
            # Look for interesting ports
            interesting_ports = {
                "21": "FTP", 
                "22": "SSH", 
                "23": "Telnet", 
                "25": "SMTP", 
                "53": "DNS",
                "445": "SMB", 
                "1433": "MSSQL", 
                "1521": "Oracle", 
                "3306": "MySQL",
                "3389": "RDP", 
                "5432": "PostgreSQL", 
                "6379": "Redis", 
                "8080": "Alternative HTTP",
                "8443": "Alternative HTTPS",
                "9200": "Elasticsearch",
                "27017": "MongoDB"
            }
            
            found_interesting = []
            for port in open_ports:
                port = port.strip()
                if port in interesting_ports:
                    found_interesting.append(f"{port} ({interesting_ports[port]})")
                    
            if found_interesting:
                insights.append(f"Interesting ports found: {', '.join(found_interesting)}")
            
        # Analyze service detection
        if "services.txt" in self.data["ports"]:
            services = self.data["ports"]["services.txt"].strip().split('\n')
            
            # Look for outdated or vulnerable services
            outdated_services = []
            for service in services:
                if re.search(r'apache.*2\.2|apache.*2\.4\.[0-9]|nginx\/1\.[0-9]\.[0-9]|openssh.*5|openssh.*6|php\/5|iis\/6|iis\/7', service, re.IGNORECASE):
                    outdated_services.append(service)
                    
            if outdated_services:
                insights.append(f"Found {len(outdated_services)} potentially outdated services.")
                insights.append(f"Example outdated services: {', '.join(outdated_services[:3])}")
                
        return insights
    
    def analyze_directories(self):
        """Analyze directory fuzzing results"""
        insights = []
        
        if "directories" not in self.data or not self.data["directories"]:
            insights.append("No directory fuzzing data available for analysis.")
            return insights
            
        # Analyze directories
        if "all_directories.txt" in self.data["directories"]:
            directories = self.data["directories"]["all_directories.txt"].strip().split('\n')
            total_dirs = len(directories)
            insights.append(f"Found {total_dirs} directories and files.")
            
            # Look for interesting directories
            interesting_paths = []
            patterns = [
                r'wp-|wordpress', r'phpmyadmin', r'admin', r'backup', r'config', r'\.git',
                r'\.env', r'api', r'dev', r'test', r'dbadmin', r'console', r'dashboard',
                r'log', r'logs', r'tmp', r'upload', r'files'
            ]
            
            for path in directories:
                for pattern in patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        interesting_paths.append(path)
                        break
                        
            if interesting_paths:
                insights.append(f"Found {len(interesting_paths)} potentially interesting paths.")
                insights.append(f"Examples: {', '.join(interesting_paths[:5])}")
                
        # Analyze parameters
        if "parameters.txt" in self.data["directories"]:
            parameters = self.data["directories"]["parameters.txt"].strip().split('\n')
            total_params = len(parameters)
            insights.append(f"Found {total_params} URL parameters.")
            
            # Look for interesting parameters
            interesting_params = []
            patterns = [
                r'id', r'file', r'path', r'dir', r'include', r'page', r'view', r'folder',
                r'doc', r'document', r'img', r'image', r'redirect', r'url', r'site',
                r'html', r'cmd', r'exec', r'query', r'search', r'user', r'username', r'pass',
                r'password', r'key', r'api'
            ]
            
            for param in parameters:
                for pattern in patterns:
                    if re.search(f'^{pattern}$|^{pattern}[0-9_]', param, re.IGNORECASE):
                        interesting_params.append(param)
                        break
                        
            if interesting_params:
                insights.append(f"Found {len(interesting_params)} potentially vulnerable parameters.")
                insights.append(f"Examples: {', '.join(interesting_params[:5])}")
                
        return insights
    
    def analyze_vulnerabilities(self):
        """Analyze vulnerability scanning results"""
        insights = []
        
        if "vulnerabilities" not in self.data or not self.data["vulnerabilities"]:
            insights.append("No vulnerability scanning data available for analysis.")
            return insights
            
        # Analyze Nuclei vulnerabilities
        if "nuclei_vulnerabilities.txt" in self.data["vulnerabilities"]:
            nuclei_data = self.data["vulnerabilities"]["nuclei_vulnerabilities.txt"]
            if "No vulnerabilities found" in nuclei_data:
                insights.append("No vulnerabilities found by Nuclei.")
            else:
                # Count vulnerabilities by severity
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                
                for line in nuclei_data.split('\n'):
                    if any(sev in line.lower() for sev in severity_counts.keys()):
                        for sev in severity_counts.keys():
                            if sev in line.lower():
                                severity_counts[sev] += 1
                                self.severity_counts[sev] += 1
                                self.total_findings += 1
                                break
                
                # Add to insights
                vuln_count = sum(severity_counts.values())
                insights.append(f"Found {vuln_count} vulnerabilities with Nuclei.")
                
                sev_details = []
                for sev, count in severity_counts.items():
                    if count > 0:
                        sev_details.append(f"{sev.capitalize()}: {count}")
                
                if sev_details:
                    insights.append(f"Vulnerability breakdown: {', '.join(sev_details)}")
        
        # Check other vulnerability scanners
        vuln_types = {
            "xss_vulnerabilities.txt": "XSS",
            "sqli_vulnerabilities.txt": "SQL Injection",
            "openredirect_vulnerabilities.txt": "Open Redirect",
            "ssrf_vulnerabilities.txt": "SSRF"
        }
        
        for file, vuln_type in vuln_types.items():
            if file in self.data["vulnerabilities"]:
                content = self.data["vulnerabilities"][file]
                if f"No {vuln_type} vulnerabilities found" not in content and "No vulnerabilities found" not in content:
                    # Roughly count the vulnerabilities (one entry per parameter)
                    occurrences = content.lower().count("parameter")
                    if occurrences > 0:
                        insights.append(f"Found {occurrences} potential {vuln_type} vulnerabilities.")
                        self.total_findings += occurrences
                        self.severity_counts["high"] += occurrences
                    
        return insights
    
    def analyze_tech(self):
        """Analyze technology detection results"""
        insights = []
        
        if "tech" not in self.data or not self.data["tech"]:
            insights.append("No technology detection data available for analysis.")
            return insights
            
        # Analyze WhatWeb results
        if "whatweb.txt" in self.data["tech"]:
            whatweb_data = self.data["tech"]["whatweb.txt"]
            
            # Extract server information
            server_match = re.search(r'Server\[(.*?)\]', whatweb_data)
            if server_match:
                server = server_match.group(1)
                insights.append(f"Server technology: {server}")
            
            # Extract framework/CMS information
            for cms in ["WordPress", "Drupal", "Joomla", "Magento", "Laravel", "Django", "Rails", "Express", "ASP.NET"]:
                if re.search(cms, whatweb_data, re.IGNORECASE):
                    insights.append(f"Detected CMS/Framework: {cms}")
                    break
        
        # Analyze security headers
        if "security_headers.txt" in self.data["tech"]:
            headers_data = self.data["tech"]["security_headers.txt"]
            
            # Count missing security headers
            missing_headers = headers_data.count("Not present")
            if missing_headers > 0:
                insights.append(f"Missing {missing_headers} important security headers.")
                
                # Check for specific important headers
                important_headers = ["Content-Security-Policy", "X-XSS-Protection", "X-Frame-Options"]
                missing_important = []
                
                for header in important_headers:
                    if f"{header}: Not present" in headers_data:
                        missing_important.append(header)
                
                if missing_important:
                    insights.append(f"Missing critical headers: {', '.join(missing_important)}")
                    self.total_findings += len(missing_important)
                    self.severity_counts["medium"] += len(missing_important)
        
        # Analyze WAF detection
        if "waf_detection.txt" in self.data["tech"]:
            waf_data = self.data["tech"]["waf_detection.txt"]
            
            if "No WAF" in waf_data or "not behind a WAF" in waf_data:
                insights.append("No Web Application Firewall (WAF) detected.")
            else:
                # Try to extract WAF name
                waf_match = re.search(r'(is behind|protected by|using) ([^\s.,!]+)', waf_data, re.IGNORECASE)
                if waf_match:
                    waf_name = waf_match.group(2)
                    insights.append(f"Protected by WAF: {waf_name}")
                else:
                    insights.append("Web Application Firewall (WAF) detected.")
            
        return insights
    
    def analyze_exploitation(self):
        """Analyze exploitation results"""
        insights = []
        
        if "exploitation" not in self.data or not self.data["exploitation"]:
            insights.append("No exploitation data available for analysis.")
            return insights
            
        # Check for confirmed exploitations
        exploit_types = {
            "confirmed_xss.txt": "XSS",
            "confirmed_sqli.txt": "SQL Injection",
            "cloud_misconfigs.txt": "Cloud Misconfiguration",
            "upload_vulnerabilities.txt": "File Upload Vulnerability"
        }
        
        for file, exploit_type in exploit_types.items():
            if file in self.data["exploitation"]:
                content = self.data["exploitation"][file]
                if f"No {exploit_type}" not in content and "No confirmed" not in content:
                    # Count occurrences
                    occurrences = content.count("---")  # Each entry separated by dashes
                    if occurrences > 0:
                        insights.append(f"Successfully exploited {occurrences} {exploit_type} vulnerabilities.")
                        
                        # Add to total findings with appropriate severity
                        self.total_findings += occurrences
                        if exploit_type in ["SQL Injection", "Cloud Misconfiguration"]:
                            self.severity_counts["critical"] += occurrences
                        else:
                            self.severity_counts["high"] += occurrences
        
        return insights
    
    def analyze_cloud(self):
        """Analyze cloud resources findings"""
        insights = []
        
        if "cloud" not in self.data or not self.data["cloud"]:
            insights.append("No cloud resources data available for analysis.")
            return insights
            
        # Analyze cloud resources
        if "cloud_resources.txt" in self.data["cloud"]:
            cloud_data = self.data["cloud"]["cloud_resources.txt"]
            
            if "No cloud resources found" in cloud_data:
                insights.append("No cloud resources found.")
                return insights
                
            # Count resources by type
            aws_count = cloud_data.count("s3.amazonaws.com")
            azure_count = cloud_data.count("blob.core.windows.net")
            gcp_count = cloud_data.count("storage.googleapis.com")
            firebase_count = cloud_data.count("firebaseio.com")
            do_count = cloud_data.count("digitaloceanspaces.com")
            
            if aws_count > 0:
                insights.append(f"Found {aws_count} AWS S3 buckets.")
            if azure_count > 0:
                insights.append(f"Found {azure_count} Azure Blob Storage accounts.")
            if gcp_count > 0:
                insights.append(f"Found {gcp_count} Google Cloud Storage buckets.")
            if firebase_count > 0:
                insights.append(f"Found {firebase_count} Firebase instances.")
            if do_count > 0:
                insights.append(f"Found {do_count} Digital Ocean Spaces.")
                
            # Check for exposed resources
            exposed_count = cloud_data.count("(Listing Enabled)") + cloud_data.count("(Public Data)")
            if exposed_count > 0:
                insights.append(f"Found {exposed_count} publicly accessible cloud resources!")
                self.total_findings += exposed_count
                self.severity_counts["critical"] += exposed_count
                
        return insights
    
    def analyze_all(self):
        """Run all analysis modules and compile insights"""
        if not self.load_data():
            logger.error(f"{Colors.RED}Failed to load data. Aborting analysis.{Colors.ENDC}")
            return False
            
        logger.info(f"{Colors.BLUE}Starting analysis...{Colors.ENDC}")
        
        # Run all analysis modules
        analysis_modules = {
            "Subdomain Analysis": self.analyze_subdomains,
            "Port Analysis": self.analyze_ports,
            "Directory Analysis": self.analyze_directories,
            "Vulnerability Analysis": self.analyze_vulnerabilities,
            "Technology Analysis": self.analyze_tech,
            "Exploitation Analysis": self.analyze_exploitation,
            "Cloud Resources Analysis": self.analyze_cloud
        }
        
        for module_name, module_func in analysis_modules.items():
            logger.info(f"{Colors.BLUE}Running {module_name}...{Colors.ENDC}")
            self.insights[module_name] = module_func()
            time.sleep(0.5)  # Small delay for better user experience
            
        logger.info(f"{Colors.GREEN}Analysis completed!{Colors.ENDC}")
        return True
    
    def get_priority_recommendations(self):
        """Generate prioritized recommendations based on findings"""
        recommendations = []
        
        # Critical recommendations first
        if self.severity_counts["critical"] > 0:
            recommendations.append("Immediately address critical vulnerabilities, especially cloud misconfigurations and SQL injection issues.")
            
        if "Technology Analysis" in self.insights:
            for insight in self.insights["Technology Analysis"]:
                if "Missing critical headers" in insight:
                    recommendations.append("Implement missing security headers to improve application security posture.")
                if "No Web Application Firewall" in insight:
                    recommendations.append("Consider implementing a Web Application Firewall (WAF) for better protection.")
                    
        if "Exploitation Analysis" in self.insights:
            for insight in self.insights["Exploitation Analysis"]:
                if "Successfully exploited" in insight:
                    recommendations.append("Prioritize fixing confirmed vulnerabilities that were successfully exploited.")
                    
        if "Subdomain Analysis" in self.insights:
            for insight in self.insights["Subdomain Analysis"]:
                if "potential development/staging environments" in insight:
                    recommendations.append("Secure or restrict access to development and staging environments.")
                    
        if "Port Analysis" in self.insights:
            for insight in self.insights["Port Analysis"]:
                if "potentially outdated services" in insight:
                    recommendations.append("Update outdated services and software to their latest secure versions.")
                    
        if "Directory Analysis" in self.insights:
            for insight in self.insights["Directory Analysis"]:
                if "potentially interesting paths" in insight:
                    recommendations.append("Review and secure sensitive paths and directories found during scanning.")
                if "potentially vulnerable parameters" in insight:
                    recommendations.append("Implement proper input validation for all identified parameters.")
                    
        # Add general recommendations if list is small
        if len(recommendations) < 3:
            recommendations.append("Implement regular security scanning and testing as part of your development lifecycle.")
            recommendations.append("Consider a comprehensive review of the application's authorization mechanisms.")
            
        return recommendations[:5]  # Return top 5 recommendations
    
    def generate_report(self):
        """Generate an HTML report with all analysis results"""
        logger.info(f"{Colors.BLUE}Generating HTML report...{Colors.ENDC}")
        
        # Get timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get recommendations
        recommendations = self.get_priority_recommendations()
        
        # Start building HTML report
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MR Legacy - AI Analysis Report for {self.target}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 0;
                    background-color: #f8f9fa;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                header {{
                    background-color: #2c3e50;
                    color: white;
                    padding: 20px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                }}
                h1, h2, h3 {{
                    color: #2c3e50;
                }}
                h1 {{
                    margin: 0;
                    padding: 0;
                }}
                .subheader {{
                    color: #bdc3c7;
                    font-size: 1.1em;
                }}
                .summary-box {{
                    background-color: white;
                    border-radius: 5px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                .findings-count {{
                    font-size: 2em;
                    font-weight: bold;
                    text-align: center;
                    color: #2c3e50;
                }}
                .severity-bar {{
                    display: flex;
                    margin: 10px 0;
                    border-radius: 5px;
                    overflow: hidden;
                    height: 30px;
                }}
                .severity-critical {{
                    background-color: #e74c3c;
                    height: 100%;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white;
                    font-weight: bold;
                }}
                .severity-high {{
                    background-color: #e67e22;
                    height: 100%;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white;
                    font-weight: bold;
                }}
                .severity-medium {{
                    background-color: #f1c40f;
                    height: 100%;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white;
                    font-weight: bold;
                }}
                .severity-low {{
                    background-color: #2ecc71;
                    height: 100%;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white;
                    font-weight: bold;
                }}
                .severity-info {{
                    background-color: #3498db;
                    height: 100%;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    color: white;
                    font-weight: bold;
                }}
                .module-box {{
                    background-color: white;
                    border-radius: 5px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                .module-box h2 {{
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }}
                ul {{
                    padding-left: 20px;
                }}
                li {{
                    margin-bottom: 8px;
                }}
                .recommendations {{
                    background-color: #2c3e50;
                    color: white;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .recommendations h2 {{
                    color: white;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }}
                .recommendation-item {{
                    background-color: rgba(255, 255, 255, 0.1);
                    padding: 10px;
                    margin-bottom: 10px;
                    border-radius: 3px;
                }}
                footer {{
                    text-align: center;
                    margin-top: 30px;
                    color: #7f8c8d;
                    font-size: 0.9em;
                }}
            </style>
        </head>
        <body>
            <header>
                <div class="container">
                    <h1>MR Legacy - AI Analysis Report</h1>
                    <div class="subheader">Target: {self.target} | Date: {timestamp}</div>
                </div>
            </header>
            
            <div class="container">
                <section class="summary-box">
                    <h2>Summary</h2>
                    <div class="findings-count">{self.total_findings} Total Findings</div>
                    <div class="severity-bar">
        """
        
        # Add severity bar sections
        for severity, count in self.severity_counts.items():
            if count > 0:
                percentage = (count / self.total_findings) * 100 if self.total_findings > 0 else 0
                html += f'<div class="severity-{severity}" style="width: {percentage}%;">{count}</div>'
                
        html += """
                    </div>
                </section>
                
                <section class="recommendations">
                    <h2>Priority Recommendations</h2>
        """
        
        # Add recommendations
        for recommendation in recommendations:
            html += f'<div class="recommendation-item">{recommendation}</div>'
            
        html += """
                </section>
                
                <section class="analysis-modules">
        """
        
        # Add each analysis module
        for module_name, module_insights in self.insights.items():
            if module_insights:
                html += f"""
                    <div class="module-box">
                        <h2>{module_name}</h2>
                        <ul>
                """
                
                for insight in module_insights:
                    html += f'<li>{insight}</li>'
                    
                html += """
                        </ul>
                    </div>
                """
                
        # Close the HTML
        html += """
                </section>
                
                <footer>
                    <p>Generated by MR Legacy - Bug Bounty Hunting Tool</p>
                    <p>Author: Abdulrahman Muhammad (0xLegacy)</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        # Write to file
        try:
            with open(self.report_path, 'w') as f:
                f.write(html)
            logger.info(f"{Colors.GREEN}HTML report generated: {self.report_path}{Colors.ENDC}")
            return True
        except Exception as e:
            logger.error(f"{Colors.RED}Error generating HTML report: {str(e)}{Colors.ENDC}")
            return False
    
    def print_summary(self):
        """Print a summary of findings to the console"""
        # Create a nice ASCII border
        border = "+" + "-" * 78 + "+"
        
        print("\n" + border)
        print(f"|{Colors.BOLD} MR LEGACY AI ANALYSIS SUMMARY {' ' * 48}{Colors.ENDC}|")
        print(border)
        print(f"| Target: {self.target}")
        print(f"| Total Findings: {self.total_findings}")
        print(f"| Severity Breakdown: {self.severity_counts['critical']} Critical, {self.severity_counts['high']} High, " + 
              f"{self.severity_counts['medium']} Medium, {self.severity_counts['low']} Low, {self.severity_counts['info']} Info")
        print(border)
        
        # Print recommendations
        print(f"|{Colors.BOLD} PRIORITY RECOMMENDATIONS {' ' * 53}{Colors.ENDC}|")
        print(border)
        
        recommendations = self.get_priority_recommendations()
        for i, recommendation in enumerate(recommendations, 1):
            # Wrap text to fit within the border
            wrapped = textwrap.wrap(recommendation, width=76)
            print(f"| {i}. {wrapped[0]}")
            for line in wrapped[1:]:
                print(f"|    {line}")
            print("|")
        
        print(border)
        print(f"| Full report saved to: {self.report_path}")
        print(border + "\n")

def main():
    """Main function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="MR Legacy AI Assistant - Analyzes bug bounty results")
    parser.add_argument("--target", "-t", help="Target domain", required=True)
    parser.add_argument("--results-dir", "-r", help="Results directory path", required=True)
    parser.add_argument("--verbose", "-v", help="Enable verbose output", action="store_true")
    args = parser.parse_args()
    
    # Set log level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Initialize AI assistant
    assistant = AIAssistant(args.target, args.results_dir)
    
    # Display a welcome banner
    print(f"\n{Colors.CYAN}" + "#" * 80)
    print(f"#{'MR LEGACY AI ASSISTANT':^78}#")
    print(f"#{'Analyzing findings and generating insights':^78}#")
    print("#" * 80 + f"{Colors.ENDC}\n")
    
    # Run analysis
    if assistant.analyze_all():
        # Generate report
        assistant.generate_report()
        
        # Print summary
        assistant.print_summary()
        
        return 0
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())
