# MR Legacy Bug Bounty Tool - Wordlists Overview

## Introduction

This document provides an overview of the custom wordlists included in the MR Legacy Bug Bounty Tool. These wordlists are designed to enhance the effectiveness of various security testing modules.

## Wordlist Summary

| Wordlist | File Path | Count | Purpose |
|----------|-----------|-------|---------|
| XSS Payloads | modules/wordlists/xss_payloads.txt | 300 | Cross-Site Scripting (XSS) testing |
| Modern XSS Payloads | modules/wordlists/modern_xss_payloads.txt | 80 | Modern framework-specific XSS payloads (Angular, React, Vue) |
| SQL Injection Payloads | modules/wordlists/sqli_payloads.txt | 242 | SQL Injection testing |
| NoSQL Injection Payloads | modules/wordlists/nosql_payloads.txt | 90 | NoSQL Injection testing for MongoDB, etc. |
| Open Redirect Payloads | modules/wordlists/openredirect_payloads.txt | 190 | Open Redirect vulnerability testing |
| SSRF Payloads | modules/wordlists/ssrf_payloads.txt | 204 | Server-Side Request Forgery testing |
| JWT Secrets | modules/wordlists/jwt_secrets.txt | 369 | JWT token brute forcing |
| CSP Bypass Payloads | modules/wordlists/csp_bypass_payloads.txt | 100 | Content Security Policy bypass techniques |
| CRLF Injection Payloads | modules/wordlists/crlf_payloads.txt | 95 | CRLF Injection attack vectors |
| Log4j Payloads | modules/wordlists/log4j_payloads.txt | 90 | Log4Shell vulnerability testing |
| Prototype Pollution | modules/wordlists/prototype_pollution_payloads.txt | 95 | JavaScript prototype pollution payloads |
| Directory Paths | modules/wordlists/directories.txt | 345 | Directory fuzzing and content discovery |
| Subdomains | modules/wordlists/subdomains.txt | 654 | Subdomain enumeration and discovery |
| API Endpoints | modules/wordlists/api_endpoints.txt | 334 | API endpoint discovery and testing |
| CTI Sources | modules/wordlists/cti_sources.txt | 91 | Cyber Threat Intelligence sources for OSINT |
| Parameters | modules/wordlists/parameters.txt | 244 | Common web parameters for fuzzing |
| Security Headers | modules/wordlists/security_headers.txt | 74 | HTTP security headers for security analysis |
| Sensitive Files | modules/wordlists/sensitive_files.txt | 228 | Sensitive file disclosure and content discovery |
| LFI Payloads | modules/wordlists/lfi_payloads.txt | 192 | Local File Inclusion testing and exploitation |
| Cloud Metadata | modules/wordlists/cloud_metadata.txt | 115 | Cloud provider metadata endpoints for SSRF testing |
| HTTP Methods | modules/wordlists/http_methods.txt | 20 | HTTP methods for server testing |
| HTTP Status Codes | modules/wordlists/http_status_codes.txt | 63 | HTTP status codes for response analysis |
| Misconfigurations | modules/wordlists/misconfigurations.txt | 78 | Common server and application misconfigurations |

## Wordlist Details

### XSS Payloads
- Includes basic XSS vectors
- Contains WAF bypass techniques
- Includes DOM-based XSS payloads
- Includes polyglot XSS payloads for multiple contexts

### SQL Injection Payloads
- Covers various database engines (MySQL, PostgreSQL, Oracle, SQLite, MSSQL)
- Includes authentication bypass payloads
- Includes time-based and boolean-based blind injection payloads
- Contains WAF bypass techniques

### Open Redirect Payloads
- Multiple URL encoding bypass techniques
- Protocol handler variations
- Domain validation bypass techniques
- Double/triple encoding techniques
- Parameter pollution techniques

### SSRF Payloads
- Local address variations (IPv4, IPv6)
- Alternate IP representations
- Cloud metadata service URLs
- Various protocol handlers (http, https, file, dict, gopher)
- SSRF bypass techniques for common filters

### JWT Secrets
- Common secret keys used in production
- Development environment default secrets
- Common patterns and naming conventions
- Password variations and combinations

### Directory Paths
- Common web application directories and endpoints
- Administrative interfaces and dashboards
- Configuration and settings paths
- Development-related paths and backup files
- Content management system (CMS) specific directories
- API endpoints and documentation
- Authentication-related endpoints
- Application framework specific paths
- Data storage and database access paths
- Test and debugging endpoints

### Subdomains
- Common subdomain naming patterns across organizations
- Internal and administrative subdomains
- Development, staging, and testing environments
- Cloud service specific subdomains
- Infrastructure and networking related subdomains
- Authentication and identity management subdomains
- Remote access and VPN related subdomains
- API and service-specific subdomains
- Legacy and deprecated system subdomains
- Monitoring and analytics subdomains

### API Endpoints
- RESTful API common endpoints
- GraphQL API endpoints
- Authentication endpoints (OAuth, JWT, etc.)
- Administrative API endpoints
- Data access and CRUD operations
- Mobile app API endpoints
- Third-party integration endpoints
- Webhook endpoints
- Legacy API versions
- Documentation and discovery endpoints

### CTI Sources
- OSINT data sources for threat intelligence
- Reputation and blacklist services
- Vulnerability databases and CVE sources
- Threat actor tracking services
- Dark web monitoring services
- Security vendor intelligence feeds
- Security research platforms
- Malware analysis services
- Phishing campaign tracking
- Attack surface monitoring services  

### Parameters
- Common web application parameters
- Authentication and session related parameters
- File operation parameters
- Database query parameters
- Configuration and settings parameters
- Redirect and navigation parameters
- Search and filter parameters
- User profile and account parameters
- Admin control parameters
- API control parameters

### Modern XSS Payloads
- Framework-specific XSS payloads (Angular, React, Vue)
- Template injection vectors for modern JS frameworks
- Client-side template injection payloads
- DOM-based XSS specific to modern applications
- Event handler manipulation for SPAs
- Prototype pollution XSS combinations

### NoSQL Injection Payloads
- MongoDB operator injection vectors ($ne, $gt, $where, etc.)
- NoSQL syntax specific to various databases
- Authentication bypass techniques for NoSQL
- NoSQL query language manipulation
- Document database specific operators
- Object injection techniques

### CSP Bypass Payloads
- Allowed sources exploitation (CDNs, etc.)
- Angular, React, and Vue specific bypasses
- JSONP endpoints for bypassing CSP
- Data URI scheme bypasses
- DOM-based techniques for CSP evasion
- Trusted types bypass techniques

### CRLF Injection Payloads
- Header injection techniques
- Response splitting payloads
- HTTP header separator variants
- Cross-browser CRLF sequence variations
- Encoding bypass techniques
- Combined CRLF+XSS payloads

### Log4j Payloads
- JNDI lookup exploitation vectors
- Protocol handler variations (LDAP, RMI, DNS)
- Obfuscation techniques to bypass WAFs
- Context-specific payloads for Log4Shell
- Environment variable exploits
- Nested expressions for WAF bypass

### Prototype Pollution Payloads
- JavaScript prototype chain pollution
- Object modification techniques
- Constructor property access
- Nested prototype access
- Function prototype manipulation
- Object.prototype modifications for various contexts

### Security Headers
- Core security headers for modern web applications
- Cross-origin headers (CORS, CORP, COEP)
- Content Security Policy related headers
- Cache control and caching security headers
- Information disclosure prevention headers
- Server information and technology headers
- Rate limiting and request control headers
- Legacy and modern security headers

### Sensitive Files
- Configuration files with potential secrets
- Backup and temporary files
- Version control system files (.git, .svn)
- Log files containing sensitive information
- Database dumps and connection files
- SSH and cryptographic key files
- API keys and token storage files
- Development and debug files
- Deployment configuration files
- Web server configuration files

### LFI Payloads
- Basic path traversal sequences
- Unix/Linux sensitive file targets
- Windows sensitive file targets
- Web server configuration and log files
- PHP file wrappers and filter chains
- URL encoding and double encoding techniques
- Null byte injection for older PHP versions
- Path normalization evasion techniques
- Parameter pollution methods
- Path truncation techniques

### Cloud Metadata
- AWS EC2 Instance Metadata Service endpoints
- Google Cloud Platform metadata endpoints
- Azure metadata service endpoints
- Digital Ocean metadata endpoints
- Alibaba Cloud metadata endpoints
- Oracle Cloud Infrastructure metadata endpoints
- OpenStack metadata endpoints
- Kubernetes service endpoints
- IBM Cloud metadata endpoints
- Other cloud provider specific endpoints

### HTTP Methods
- Standard HTTP methods (GET, POST, PUT, etc.)
- WebDAV methods (PROPFIND, MKCOL, etc.)
- Less common HTTP methods for testing
- HTTP method descriptions and security implications
- Method override techniques

### HTTP Status Codes
- Informational response codes (1xx)
- Successful response codes (2xx)
- Redirection message codes (3xx)
- Client error response codes (4xx)
- Server error response codes (5xx)
- Custom and non-standard status codes
- Security implications of each status code

### Misconfigurations
- Common server misconfigurations
- Web server security misconfigurations
- PHP configuration security issues
- Framework-specific security misconfigurations
- Database connection misconfigurations
- Cloud service misconfigurations
- Docker and container misconfigurations
- Access control misconfigurations
- Permissions and privilege misconfigurations
- Authentication and session misconfigurations

## Usage

These wordlists are automatically loaded by the relevant modules when they detect the presence of the custom wordlist files. If a custom wordlist is not found, a smaller default wordlist is generated at runtime.

### Wordlist Helper Utility

MR Legacy includes a wordlist helper utility to make it easier to manage, view, and understand the wordlists. This utility is located in the `utils` directory.

```bash
# Show available wordlists
./utils/wordlist_helper.sh --list

# View count of entries in each wordlist
./utils/wordlist_helper.sh --count

# Get information about a specific wordlist
./utils/wordlist_helper.sh --info xss_payloads

# Search for a term across all wordlists
./utils/wordlist_helper.sh --search "admin"

# Get examples of wordlist usage and creation
./utils/wordlist_helper.sh --examples
```

### Module-specific Usage

Different modules use specific wordlists:

- **Reconnaissance Module**: uses `subdomains.txt`, `api_endpoints.txt`, and more
- **Content Discovery**: uses `directories.txt`, `sensitive_files.txt`, `api_endpoints.txt`
- **Exploitation**: uses `xss_payloads.txt`, `sqli_payloads.txt`, `lfi_payloads.txt`, etc.
- **Security Analysis**: uses `security_headers.txt`, `http_methods.txt`, `http_status_codes.txt`
- **Authentication Testing**: uses `jwt_secrets.txt` and credentials wordlists
- **OSINT**: uses `cti_sources.txt` and other intelligence sources

## Customization

You can extend these wordlists by adding additional entries to the respective files. The changes will be automatically picked up by the modules during execution.

### Wordlist Format

Each wordlist follows a standard format:

1. Header comment with description
2. One entry per line
3. Optional categorization comments with `#` prefix

Example:
```
# Security Headers Wordlist - For HTTP security header analysis
# Author: 0xLegacy

# Standard Security Headers
X-XSS-Protection
Content-Security-Policy
X-Content-Type-Options

# Frame Protection
X-Frame-Options

# Additional Security Headers
Feature-Policy
...
```

## Credits

These wordlists were compiled from various open source resources and security research, enhanced specifically for the MR Legacy Bug Bounty Tool.

Maintained by: Abdulrahman Muhammad (0xLegacy)