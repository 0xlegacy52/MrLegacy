# MR Legacy - Bug Bounty Hunting Tool

A comprehensive Bash-based Bug Bounty hunting tool for reconnaissance, scanning, and exploitation with advanced features for modern bug bounty hunting.

![MR Legacy](generated-icon.png)

## Author
Abdulrahman Muhammad (0xLegacy)

## Features

### Core Capabilities
- Subdomain enumeration and takeover checks
- DNS analysis and zone transfer testing
- Advanced port scanning with service detection
- Web service identification and fingerprinting
- Directory and file discovery with pattern analysis
- Parameter discovery and injection testing
- Technology detection and version analysis
- Comprehensive vulnerability scanning
- Exploitation and proof-of-concept generation
- OSINT reconnaissance with multiple data sources
- Cloud resource detection and configuration analysis
- AI-powered analysis and reporting
- Authentication testing with comprehensive checks

- **Wordlist Collection**: Expanded specialized wordlists for comprehensive security testing:
  - XSS Payloads (300 entries) for diverse cross-site scripting contexts
  - SQL Injection Payloads (242 entries) covering multiple database engines and bypass techniques
  - Open Redirect Payloads (190 entries) with various encoding and validation bypass techniques
  - SSRF Payloads (204 entries) for internal service discovery and metadata access
  - JWT Secret Wordlist (369 entries) for JWT token brute-forcing
  - Sensitive Files (228 entries) for configuration and backup file discovery
  - Security Headers (74 entries) for HTTP security posture analysis
  - LFI Payloads (192 entries) for path traversal and local file inclusion testing
  - Cloud Metadata (115 entries) for cloud environment security testing
  - API Endpoints (334 entries) for comprehensive API discovery
- **XSS Detection**: Advanced payload generation, DOM-based XSS analysis, and better detection for various XSS types with proper payload handling
- **Security Headers Analysis**: Comprehensive security header checks with rating system and detailed recommendations
- **Advanced OSINT Capabilities**: Enhanced email discovery with pattern analysis, DNS-based intelligence, and social media profiling
- **Content Discovery**: Better directory fuzzing with pattern recognition and sensitive file detection
- **Port Scanning**: Detailed port classification by security relevance with recommendations and markdown report generation

## Installation

### Clone the repository

```bash
git clone https://github.com/0xlegacy52/MrLegacy.git
cd MrLegacy
```

### Requirements

MR Legacy depends on several tools for its functions:

- Basic tools: `nmap`, `whois`, `dig`, `curl`, `jq`
- Subdomain tools: `subfinder`, `amass`, `assetfinder`, `findomain`
- Web tools: `httpx`, `nuclei`, `gobuster`, `dirsearch`, `gowitness`, `whatweb`
- Scanning tools: `masscan`, `naabu`
- Exploitation tools: Various depending on modules

### Quick Setup

To install dependencies on Kali Linux or other Debian-based distributions:

```bash
sudo apt update
sudo apt install nmap whois dnsutils curl jq
```

The script will check for other required tools and provide installation instructions.

## Usage

### Basic Usage

```bash
./mr_legacy.sh -t example.com
```

### Command Line Options

```
Usage:
  ./mr_legacy.sh [options]

Options:
  -t, --target <domain>       Target domain
  -o, --output <format>       Output format (json, txt, html, all) [default: all]
  -T, --threads <num>         Number of threads [default: 10]
  --tor                       Enable Tor proxy for anonymity
  -a, --auto                  Run auto-recon mode (all modules in sequence)
  -v, --verbose               Enable verbose output
  -d, --deep                  Enable deep scan (more comprehensive)
  -h, --help                  Show this help message

Examples:
  ./mr_legacy.sh -t example.com -o json
  ./mr_legacy.sh -t example.com --tor -a -v
  ./mr_legacy.sh -t example.com -T 20 --auto -d
```

## Modules

### Reconnaissance
- subdomain enumeration with multiple sources
- DNS resolution and zone transfer testing
- port scanning with service fingerprinting
- Web screenshots and visual analysis
- Technology stack identification with version detection
- Network infrastructure mapping

### OSINT (Open Source Intelligence)
- email discovery with pattern analysis
- Google, GitHub, and Shodan dorks
- Social media profiling and digital footprint analysis
- Data leak detection and sensitive information discovery
- Metadata extraction from documents and images
- DNS-based intelligence gathering
- Employee and organization structure discovery

### Content Discovery
- Advanced directory and file fuzzing
- Pattern-based sensitive file detection
- JavaScript analysis for endpoints and secrets
- API endpoint discovery and documentation
- Hidden parameter detection

### Security Analysis
- security header analysis with rating system
- TLS/SSL configuration testing and vulnerability detection
- Cookie security analysis with recommendations
- Error handling and debug information checks
- Server-side technology security assessment

### Vulnerability Scanning
- Custom template-based scanning
- XSS detection with DOM-based analysis
- SQL injection detection with pattern matching
- Open redirect and SSRF vulnerability testing
- File inclusion and path traversal detection
  
### Exploitation
- XSS exploitation with multiple payload types
  - Reflected XSS payload generation with context awareness
  - Stored XSS detection and exploitation
  - DOM-based XSS analysis with JavaScript parsing
  - CSP bypass technique identification
  - Event handler-based XSS payload generation
  - Automated proof-of-concept HTML file creation
  - Payload encoding and obfuscation techniques
- SQL injection data extraction techniques
  - Boolean-based blind exploitation
  - Time-based blind exploitation
  - Error-based data extraction
  - UNION-based data extraction


### Reporting
- Comprehensive markdown report generation
- JSON output for integration with other tools
- Interactive HTML reports with recommendations
- Security risk scoring and prioritization

## Comprehensive Wordlists

MR Legacy includes specialized wordlists to enhance the effectiveness of various security testing modules:

| Wordlist | Count | Purpose |
|----------|-------|---------|
| XSS Payloads | 300 | Cross-Site Scripting attack vectors with context-specific payloads |
| SQL Injection | 242 | Database-specific SQLi payloads for various attack scenarios |
| Open Redirect | 190 | URL manipulation techniques for bypassing redirect validations |
| SSRF Payloads | 204 | Server-Side Request Forgery techniques for internal service discovery |
| JWT Secrets | 369 | Common JWT signing secrets for brute-force attempts |
| Directory Paths | 345 | Common web directories and files for content discovery |
| Sensitive Files | 228 | Configurations, backups, and other sensitive files |
| Security Headers | 74 | HTTP security headers for security posture analysis |
| LFI Payloads | 192 | Local File Inclusion attack vectors for path traversal |
| Cloud Metadata | 115 | Cloud provider metadata endpoints for SSRF testing |
| API Endpoints | 334 | Common API paths and endpoints for discovery |
| HTTP Methods | 20 | HTTP methods for testing server configurations |
| HTTP Status Codes | 63 | HTTP response codes for error handling analysis |
| Misconfigurations | 78 | Common server and application misconfigurations |

For a detailed explanation of these wordlists, see the [`WORDLISTS.md`](WORDLISTS.md) file.

## Output

Results are saved in the `results` directory, organized by target domain . Multiple output formats are supported:

- Text files (detailed findings with technical information)
- JSON (structured data for integration with other tools)
- HTML reports (comprehensive visual reports with findings, severity ratings, and remediation advice)

## AI Assistant

MR Legacy includes an advanced AI analysis module that processes all scan results to provide:

- Comprehensive security findings correlation across modules
- Severity-based vulnerability prioritization
- Root cause analysis for identified vulnerabilities
- Detailed remediation recommendations with technical guidance
- Executive summary of security posture
- Custom tailored attack vectors based on discovered technologies
- Identification of potential security misconfigurations
- Risk scoring and impact assessment

To run only the AI analysis on existing scan results:

```bash
# Run AI analysis on existing results
./mr_legacy.sh -t example.com --ai-only
```

The AI assistant generates both detailed technical reports and business-oriented summaries:

```
+------------------------------------------------------------------------------+
| MR LEGACY AI ANALYSIS SUMMARY                                                 |
+------------------------------------------------------------------------------+
| Target: http://example.com
| Total Findings: X
| Severity Breakdown: X Critical, X High, X Medium, X Low, X Info
+------------------------------------------------------------------------------+
| PRIORITY RECOMMENDATIONS                                                      |
+------------------------------------------------------------------------------+
| 1. [First priority recommendation with technical context]
|
| 2. [Second priority recommendation with business impact]
|
+------------------------------------------------------------------------------+
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and ethical testing purposes only. Always obtain proper authorization before performing security testing on any system or network.
