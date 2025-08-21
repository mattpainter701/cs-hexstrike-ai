# HexStrike AI MCP Security Tools Reference Guide

## Overview
HexStrike AI MCP provides a comprehensive suite of cybersecurity tools for network reconnaissance, vulnerability assessment, penetration testing, and security analysis. This guide covers all available tools with usage examples and best practices.

---

## Network Reconnaissance Tools

### 1. Nmap Scanning
**Primary tool for network discovery and port scanning**

#### Basic Nmap Scan
```bash
mcp_hexstrike-ai_nmap_scan
- target: "192.168.1.1"
- scan_type: "-sS"
- ports: "22,80,443,8080"
- additional_args: "-T4"
```

#### Advanced Nmap Scan
```bash
mcp_hexstrike-ai_nmap_advanced_scan
- target: "192.168.1.1"
- scan_type: "-sS"
- ports: "1-1000"
- timing: "T4"
- os_detection: true
- version_detection: true
- nse_scripts: "vuln,auth,default"
```

#### High-Speed Scanning
```bash
mcp_hexstrike-ai_masscan_high_speed
- target: "192.168.1.0/24"
- ports: "22,80,443"
- rate: 1000
- banners: true
```

#### Ultra-Fast Scanning
```bash
mcp_hexstrike-ai_rustscan_fast_scan
- target: "192.168.1.1"
- ports: "22,80,443,8080"
- ulimit: 5000
- batch_size: 4500
- timeout: 1500
```

### 2. Network Discovery
**Tools for discovering hosts and services**

#### ARP Scan Discovery
```bash
mcp_hexstrike-ai_arp_scan_discovery
- target: "192.168.1.0/24"
- interface: "eth0"
- timeout: 500
- retry: 3
```

#### NetBIOS Discovery
```bash
mcp_hexstrike-ai_nbtscan_netbios
- target: "192.168.1.0/24"
- verbose: true
- timeout: 2
```

### 3. Comprehensive Reconnaissance
**Automated reconnaissance frameworks**

#### AutoRecon Comprehensive
```bash
mcp_hexstrike-ai_autorecon_comprehensive
- target: "192.168.1.1"
- output_dir: "/tmp/autorecon"
- port_scans: "top-100-ports"
- service_scans: "default"
- heartbeat: 60
- timeout: 300
```

---

## Web Application Security Tools

### 1. Directory Discovery
**Finding hidden directories and files**

#### Gobuster Scan
```bash
mcp_hexstrike-ai_gobuster_scan
- url: "http://example.com"
- mode: "dir"
- wordlist: "/usr/share/wordlists/dirb/common.txt"
- additional_args: "--timeout 10s"
```

#### Feroxbuster Scan
```bash
mcp_hexstrike-ai_feroxbuster_scan
- url: "http://example.com"
- wordlist: "/usr/share/wordlists/dirb/common.txt"
- threads: 10
- additional_args: "--timeout 10"
```

#### Dirsearch Scan
```bash
mcp_hexstrike-ai_dirsearch_scan
- url: "http://example.com"
- extensions: "php,html,js,txt,xml,json"
- wordlist: "/usr/share/wordlists/dirsearch/common.txt"
- threads: 30
- recursive: false
```

### 2. Web Crawling and Discovery
**Advanced web application reconnaissance**

#### Katana Crawl
```bash
mcp_hexstrike-ai_katana_crawl
- url: "http://example.com"
- depth: 3
- js_crawl: true
- form_extraction: true
- output_format: "json"
```

#### URL Discovery
```bash
mcp_hexstrike-ai_gau_discovery
- domain: "example.com"
- providers: "wayback,commoncrawl,otx,urlscan"
- include_subs: true
- blacklist: "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico"
```

#### Wayback URLs
```bash
mcp_hexstrike-ai_waybackurls_discovery
- domain: "example.com"
- get_versions: false
- no_subs: false
```

### 3. Parameter Discovery
**Finding hidden parameters and endpoints**

#### Arjun Parameter Discovery
```bash
mcp_hexstrike-ai_arjun_parameter_discovery
- url: "http://example.com"
- method: "GET"
- wordlist: ""
- delay: 0
- threads: 25
- stable: false
```

#### ParamSpider Mining
```bash
mcp_hexstrike-ai_paramspider_mining
- domain: "example.com"
- level: 2
- exclude: "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico"
- output: ""
```

#### X8 Parameter Discovery
```bash
mcp_hexstrike-ai_x8_parameter_discovery
- url: "http://example.com"
- wordlist: "/usr/share/wordlists/x8/params.txt"
- method: "GET"
- body: ""
- headers: ""
```

---

## Vulnerability Assessment Tools

### 1. Nuclei Vulnerability Scanner
**Fast vulnerability scanner with extensive template library**

```bash
mcp_hexstrike-ai_nuclei_scan
- target: "http://example.com"
- severity: "critical,high,medium"
- tags: "cve,rce,lfi"
- template: ""
- additional_args: ""
```

### 2. Advanced Vulnerability Scanners
**Specialized vulnerability detection tools**

#### Jaeles Vulnerability Scan
```bash
mcp_hexstrike-ai_jaeles_vulnerability_scan
- url: "http://example.com"
- signatures: ""
- config: ""
- threads: 20
- timeout: 20
```

#### Dalfox XSS Scan
```bash
mcp_hexstrike-ai_dalfox_xss_scan
- url: "http://example.com"
- pipe_mode: false
- blind: false
- mining_dom: true
- mining_dict: true
- custom_payload: ""
```

### 3. Web Application Testing
**Specialized web security testing tools**

#### Nikto Scan
```bash
mcp_hexstrike-ai_nikto_scan
- target: "http://example.com"
- additional_args: ""
```

#### SQLMap Scan
```bash
mcp_hexstrike-ai_sqlmap_scan
- url: "http://example.com"
- data: ""
- additional_args: ""
```

#### XSSer Scan
```bash
mcp_hexstrike-ai_xsser_scan
- url: "http://example.com"
- params: ""
- additional_args: ""
```

#### DotDotPwn Scan
```bash
mcp_hexstrike-ai_dotdotpwn_scan
- target: "example.com"
- module: "http"
- additional_args: ""
```

#### Wfuzz Scan
```bash
mcp_hexstrike-ai_wfuzz_scan
- url: "http://example.com/FUZZ"
- wordlist: "/usr/share/wordlists/dirb/common.txt"
- additional_args: ""
```

---

## Network Service Enumeration

### 1. SMB Enumeration
**Windows/SMB service enumeration**

#### Enum4linux Scan
```bash
mcp_hexstrike-ai_enum4linux_scan
- target: "192.168.1.1"
- additional_args: "-a"
```

#### Enum4linux-ng Advanced
```bash
mcp_hexstrike-ai_enum4linux_ng_advanced
- target: "192.168.1.1"
- username: ""
- password: ""
- domain: ""
- shares: true
- users: true
- groups: true
- policy: true
```

#### SMBMap Scan
```bash
mcp_hexstrike-ai_smbmap_scan
- target: "192.168.1.1"
- username: ""
- password: ""
- domain: ""
```

#### NetExec Scan
```bash
mcp_hexstrike-ai_netexec_scan
- target: "192.168.1.1"
- protocol: "smb"
- username: ""
- password: ""
- hash_value: ""
- module: ""
```

### 2. RPC Enumeration
**RPC service enumeration**

```bash
mcp_hexstrike-ai_rpcclient_enumeration
- target: "192.168.1.1"
- username: ""
- password: ""
- domain: ""
- commands: "enumdomusers;enumdomgroups;querydominfo"
```

---

## Password Attacks

### 1. Hydra Brute Force
**Multi-protocol password brute forcing**

```bash
mcp_hexstrike-ai_hydra_attack
- target: "192.168.1.1"
- service: "ssh"
- username: "admin"
- username_file: ""
- password: "password"
- password_file: ""
- additional_args: ""
```

### 2. Hash Cracking
**Password hash cracking tools**

#### John the Ripper
```bash
mcp_hexstrike-ai_john_crack
- hash_file: "hashes.txt"
- wordlist: "/usr/share/wordlists/rockyou.txt"
- format_type: ""
- additional_args: ""
```

#### Hashcat
```bash
mcp_hexstrike-ai_hashcat_crack
- hash_file: "hashes.txt"
- hash_type: "0"
- attack_mode: "0"
- wordlist: "/usr/share/wordlists/rockyou.txt"
- mask: ""
- additional_args: ""
```

---

## Subdomain Enumeration

### 1. Subfinder
**Fast passive subdomain enumeration**

```bash
mcp_hexstrike-ai_subfinder_scan
- domain: "example.com"
- silent: true
- all_sources: false
- additional_args: ""
```

### 2. Amass
**Comprehensive subdomain enumeration**

```bash
mcp_hexstrike-ai_amass_scan
- domain: "example.com"
- mode: "enum"
- additional_args: ""
```

---

## WordPress Security

### WPScan Analysis
**WordPress vulnerability scanner**

```bash
mcp_hexstrike-ai_wpscan_analyze
- url: "http://example.com"
- additional_args: ""
```

---

## Credential Harvesting

### Responder Credential Harvest
**LLMNR/NBT-NS poisoning and credential harvesting**

```bash
mcp_hexstrike-ai_responder_credential_harvest
- interface: "eth0"
- analyze: false
- wpad: true
- force_wpad_auth: false
- fingerprint: false
- duration: 300
```

---

## Binary Analysis Tools

### 1. Basic Binary Analysis
**Fundamental binary analysis tools**

#### Checksec Analysis
```bash
mcp_hexstrike-ai_checksec_analyze
- binary: "target_binary"
```

#### Strings Extraction
```bash
mcp_hexstrike-ai_strings_extract
- file_path: "target_binary"
- min_len: 4
- additional_args: ""
```

#### Hexdump Analysis
```bash
mcp_hexstrike-ai_xxd_hexdump
- file_path: "target_binary"
- offset: "0"
- length: ""
- additional_args: ""
```

#### Objdump Analysis
```bash
mcp_hexstrike-ai_objdump_analyze
- binary: "target_binary"
- disassemble: true
- additional_args: ""
```

### 2. Advanced Binary Analysis
**Professional binary analysis tools**

#### GDB Analysis
```bash
mcp_hexstrike-ai_gdb_analyze
- binary: "target_binary"
- commands: ""
- script_file: ""
- additional_args: ""
```

#### Radare2 Analysis
```bash
mcp_hexstrike-ai_radare2_analyze
- binary: "target_binary"
- commands: ""
- additional_args: ""
```

#### Ghidra Analysis
```bash
mcp_hexstrike-ai_ghidra_analysis
- binary: "target_binary"
- project_name: "hexstrike_analysis"
- script_file: ""
- analysis_timeout: 300
- output_format: "xml"
```

#### Binwalk Analysis
```bash
mcp_hexstrike-ai_binwalk_analyze
- file_path: "target_binary"
- extract: false
- additional_args: ""
```

### 3. Exploitation Tools
**Binary exploitation and ROP tools**

#### ROPgadget Search
```bash
mcp_hexstrike-ai_ropgadget_search
- binary: "target_binary"
- gadget_type: ""
- additional_args: ""
```

#### Ropper Gadget Search
```bash
mcp_hexstrike-ai_ropper_gadget_search
- binary: "target_binary"
- gadget_type: "rop"
- quality: 1
- arch: ""
- search_string: ""
```

#### One Gadget Search
```bash
mcp_hexstrike-ai_one_gadget_search
- libc_path: "libc.so.6"
- level: 1
- additional_args: ""
```

#### Libc Database Lookup
```bash
mcp_hexstrike-ai_libc_database_lookup
- action: "find"
- symbols: ""
- libc_id: ""
- additional_args: ""
```

### 4. Exploitation Frameworks
**Advanced exploitation tools**

#### Pwntools Exploit
```bash
mcp_hexstrike-ai_pwntools_exploit
- script_content: ""
- target_binary: ""
- target_host: ""
- target_port: 0
- exploit_type: "local"
- additional_args: ""
```

#### Angr Symbolic Execution
```bash
mcp_hexstrike-ai_angr_symbolic_execution
- binary: "target_binary"
- script_content: ""
- find_address: ""
- avoid_addresses: ""
- analysis_type: "symbolic"
- additional_args: ""
```

#### Pwninit Setup
```bash
mcp_hexstrike-ai_pwninit_setup
- binary: "target_binary"
- libc: ""
- ld: ""
- template_type: "python"
- additional_args: ""
```

---

## Memory Forensics

### Volatility Analysis
**Memory forensics analysis**

```bash
mcp_hexstrike-ai_volatility_analyze
- memory_file: "memory.dmp"
- plugin: "pslist"
- profile: ""
- additional_args: ""
```

---

## Payload Generation

### 1. MSFVenom Generate
**Metasploit payload generation**

```bash
mcp_hexstrike-ai_msfvenom_generate
- payload: "windows/meterpreter/reverse_tcp"
- format_type: "exe"
- output_file: ""
- encoder: ""
- iterations: ""
- additional_args: ""
```

### 2. Payload Generation
**Custom payload generation**

```bash
mcp_hexstrike-ai_generate_payload
- payload_type: "buffer"
- size: 1024
- pattern: "A"
- filename: ""
```

---

## Cloud Security Assessment

### 1. Prowler Scan
**AWS security assessment**

```bash
mcp_hexstrike-ai_prowler_scan
- provider: "aws"
- profile: "default"
- region: ""
- checks: ""
- output_dir: "/tmp/prowler_output"
- output_format: "json"
```

### 2. Scout Suite Assessment
**Multi-cloud security assessment**

```bash
mcp_hexstrike-ai_scout_suite_assessment
- provider: "aws"
- profile: "default"
- report_dir: "/tmp/scout-suite"
- services: ""
- exceptions: ""
```

### 3. CloudMapper Analysis
**AWS network visualization**

```bash
mcp_hexstrike-ai_cloudmapper_analysis
- action: "collect"
- account: ""
- config: "config.json"
- additional_args: ""
```

### 4. Pacu Exploitation
**AWS exploitation framework**

```bash
mcp_hexstrike-ai_pacu_exploitation
- session_name: "hexstrike_session"
- modules: ""
- data_services: ""
- regions: ""
- additional_args: ""
```

---

## Container Security

### 1. Trivy Scan
**Container and filesystem vulnerability scanning**

```bash
mcp_hexstrike-ai_trivy_scan
- scan_type: "image"
- target: "nginx:latest"
- output_format: "json"
- severity: ""
- output_file: ""
```

### 2. Clair Vulnerability Scan
**Container vulnerability analysis**

```bash
mcp_hexstrike-ai_clair_vulnerability_scan
- image: "nginx:latest"
- config: "/etc/clair/config.yaml"
- output_format: "json"
```

### 3. Docker Bench Security Scan
**Docker security assessment**

```bash
mcp_hexstrike-ai_docker_bench_security_scan
- checks: ""
- exclude: ""
- output_file: "/tmp/docker-bench-results.json"
```

---

## Kubernetes Security

### 1. Kube-hunter Scan
**Kubernetes penetration testing**

```bash
mcp_hexstrike-ai_kube_hunter_scan
- target: ""
- remote: ""
- cidr: ""
- interface: ""
- active: false
- report: "json"
```

### 2. Kube-bench CIS
**CIS Kubernetes benchmark checks**

```bash
mcp_hexstrike-ai_kube_bench_cis
- targets: ""
- version: ""
- config_dir: ""
- output_format: "json"
```

---

## Infrastructure as Code Security

### 1. Checkov IaC Scan
**Infrastructure as code security scanning**

```bash
mcp_hexstrike-ai_checkov_iac_scan
- directory: "."
- framework: ""
- check: ""
- skip_check: ""
- output_format: "json"
```

### 2. Terrascan IaC Scan
**Infrastructure as code security scanning**

```bash
mcp_hexstrike-ai_terrascan_iac_scan
- scan_type: "all"
- iac_dir: "."
- policy_type: ""
- output_format: "json"
- severity: ""
```

---

## Runtime Security Monitoring

### Falco Runtime Monitoring
**Runtime security monitoring**

```bash
mcp_hexstrike-ai_falco_runtime_monitoring
- config_file: "/etc/falco/falco.yaml"
- rules_file: ""
- output_format: "json"
- duration: 60
```

---

## File Management

### 1. Create File
```bash
mcp_hexstrike-ai_create_file
- filename: "test.txt"
- content: "Hello World"
- binary: false
```

### 2. Modify File
```bash
mcp_hexstrike-ai_modify_file
- filename: "test.txt"
- content: "Additional content"
- append: true
```

### 3. Delete File
```bash
mcp_hexstrike-ai_delete_file
- filename: "test.txt"
```

### 4. List Files
```bash
mcp_hexstrike-ai_list_files
- directory: "."
```

---

## Python Environment Management

### 1. Install Python Package
```bash
mcp_hexstrike-ai_install_python_package
- package: "requests"
- env_name: "default"
```

### 2. Execute Python Script
```bash
mcp_hexstrike-ai_execute_python_script
- script: "print('Hello World')"
- env_name: "default"
- filename: ""
```

---

## Best Practices

### 1. Network Scanning
- Always obtain proper authorization before scanning
- Use appropriate timing to avoid overwhelming targets
- Start with non-intrusive scans before aggressive testing
- Document all scan parameters and results

### 2. Web Application Testing
- Test in isolated environments when possible
- Use appropriate wordlists for your target
- Monitor for false positives
- Respect robots.txt and rate limiting

### 3. Password Attacks
- Only test against systems you own or have explicit permission
- Use appropriate wordlists and techniques
- Monitor for account lockouts
- Document all attempts and results

### 4. Binary Analysis
- Always analyze in isolated environments
- Use multiple tools for verification
- Document analysis methodology
- Be aware of anti-analysis techniques

### 5. Cloud Security
- Ensure proper AWS credentials and permissions
- Test in non-production environments
- Follow cloud provider security best practices
- Monitor for unintended resource creation

---

## Common Use Cases

### 1. Network Reconnaissance
```bash
# Initial network discovery
mcp_hexstrike-ai_nmap_scan - target: "192.168.1.0/24" - scan_type: "-sS" - ports: "22,80,443"

# Detailed host analysis
mcp_hexstrike-ai_nmap_advanced_scan - target: "192.168.1.1" - os_detection: true - version_detection: true
```

### 2. Web Application Assessment
```bash
# Directory discovery
mcp_hexstrike-ai_gobuster_scan - url: "http://example.com" - mode: "dir"

# Vulnerability scanning
mcp_hexstrike-ai_nuclei_scan - target: "http://example.com" - severity: "critical,high"
```

### 3. Binary Exploitation
```bash
# Security analysis
mcp_hexstrike-ai_checksec_analyze - binary: "target"

# ROP gadget search
mcp_hexstrike-ai_ropgadget_search - binary: "target"
```

### 4. Cloud Security Assessment
```bash
# AWS security scan
mcp_hexstrike-ai_prowler_scan - provider: "aws" - profile: "default"

# Infrastructure as code scan
mcp_hexstrike-ai_checkov_iac_scan - directory: "." - framework: "terraform"
```

---

## Troubleshooting

### Common Issues:
1. **Tool not found:** Some tools may not be installed on the system
2. **Permission denied:** Ensure proper permissions for file operations
3. **Timeout errors:** Adjust timing parameters for network scans
4. **Wordlist not found:** Use alternative wordlists or create custom ones

### Error Recovery:
- Most tools include automatic retry mechanisms
- Check tool availability before use
- Verify target accessibility
- Review tool documentation for specific requirements

---

## Intelligent Scanning Workflow Architecture

### Phase 1: Initial Target Assessment (Discovery & Enumeration)

#### Network Scanning Sequence
1. **Host Discovery**
   ```
   Priority 1: arp_scan_discovery (local networks)
   Priority 2: nmap_scan (-sn ping sweep)
   Priority 3: masscan_high_speed (large ranges)
   ```

2. **Port Enumeration**
   ```
   Quick Scan: rustscan_fast_scan (top 1000 ports)
   Comprehensive: nmap_advanced_scan (full port range)
   Internet Scale: masscan_high_speed (targeted services)
   ```

3. **Service Detection**
   ```
   nmap_advanced_scan (with -sV, -sC, --script=vuln)
   Custom NSE scripts based on discovered services
   Banner grabbing and version detection
   ```

#### Subdomain & Web Asset Discovery
1. **Passive Enumeration**
   ```
   subfinder_scan (API-based discovery)
   amass_scan (passive mode)
   gau_discovery (historical URLs)
   waybackurls_discovery (archived content)
   ```

2. **Active Enumeration**
   ```
   amass_scan (active brute forcing)
   gobuster_scan (DNS mode)
   ffuf_scan (virtual host enumeration)
   ```

3. **Technology Fingerprinting**
   ```
   httpx probing with technology detection
   whatweb identification
   wafw00f detection
   nuclei_scan with tech-detect templates
   ```

### Phase 2: Vulnerability Assessment

#### Web Application Testing Sequence
1. **Content Discovery**
   ```
   feroxbuster_scan (recursive directory enumeration)
   gobuster_scan (directory/file discovery)
   dirsearch_scan (PHP/extension-specific)
   ```

2. **Parameter Discovery**
   ```
   arjun_parameter_discovery (hidden parameters)
   paramspider_mining (archived parameters)
   x8_parameter_discovery (advanced techniques)
   ```

3. **Vulnerability Scanning**
   ```
   nuclei_scan (comprehensive template scanning)
   jaeles_vulnerability_scan (custom signatures)
   nikto_scan (web server vulnerabilities)
   dalfox_xss_scan (XSS testing)
   ```

4. **Injection Testing**
   ```
   sqlmap_scan (SQL injection)
   xsser_scan (XSS testing)
   dotdotpwn_scan (path traversal)
   wfuzz_scan (parameter fuzzing)
   ```

#### Network Service Testing
1. **SMB/Windows Services**
   ```
   enum4linux_ng_advanced (comprehensive SMB enumeration)
   smbmap_scan (share analysis)
   netexec_scan (multi-protocol testing)
   responder_credential_harvest (if authorized)
   ```

2. **Authentication Testing**
   ```
   hydra_attack (service brute forcing)
   netexec_scan (credential validation)
   Password spraying with common credentials
   ```

### Phase 3: Deep Analysis & Specialized Testing

#### Binary Analysis Workflow
1. **Initial Analysis**
   ```
   checksec_analyze (security mitigations)
   strings_extract (readable strings)
   binwalk_analyze (embedded files/firmware)
   ```

2. **Reverse Engineering**
   ```
   ghidra_analysis (comprehensive analysis)
   radare2_analyze (dynamic analysis)
   gdb_analyze (runtime debugging)
   ```

3. **Exploitation Research**
   ```
   ropgadget_search (ROP chain construction)
   one_gadget_search (one-shot exploitation)
   pwntools_exploit (automated exploitation)
   angr_symbolic_execution (path discovery)
   ```

#### Cloud Security Assessment
1. **AWS Security**
   ```
   prowler_scan (comprehensive AWS assessment)
   scout_suite_assessment (multi-service analysis)
   pacu_exploitation (penetration testing)
   ```

2. **Container Security**
   ```
   trivy_scan (vulnerability scanning)
   docker_bench_security_scan (CIS compliance)
   kube_hunter_scan (Kubernetes testing)
   kube_bench_cis (K8s compliance)
   ```

3. **Infrastructure as Code**
   ```
   checkov_iac_scan (Terraform/CloudFormation)
   terrascan_iac_scan (policy enforcement)
   ```

### Tool Selection Logic & Decision Engine

#### Context-Aware Tool Selection
```python
def select_tools(target_type, scan_objective, time_constraints, stealth_requirements):
    if target_type == "single_host":
        if time_constraints == "fast":
            return ["rustscan_fast_scan", "httpx", "nuclei_scan"]
        elif scan_objective == "comprehensive":
            return ["nmap_advanced_scan", "autorecon_comprehensive", "nuclei_scan"]
    
    elif target_type == "web_application":
        if stealth_requirements == "high":
            return ["subfinder_scan", "waybackurls_discovery", "nuclei_scan"]
        else:
            return ["feroxbuster_scan", "arjun_parameter_discovery", "sqlmap_scan"]
    
    elif target_type == "network_range":
        if time_constraints == "fast":
            return ["masscan_high_speed", "rustscan_fast_scan"]
        else:
            return ["nmap_scan", "enum4linux_ng_advanced", "responder_harvest"]
```

#### Adaptive Scanning Based on Results
```python
def adaptive_scan_selection(initial_results):
    detected_services = parse_services(initial_results)
    
    if "http" in detected_services:
        return ["gobuster_scan", "nuclei_scan", "sqlmap_scan"]
    
    if "smb" in detected_services:
        return ["enum4linux_ng_advanced", "smbmap_scan", "netexec_scan"]
    
    if "ssh" in detected_services:
        return ["hydra_attack", "ssh_audit"]
    
    # Custom tool chains based on service fingerprints
```

### Scanning Sequence Examples

#### Bug Bounty Reconnaissance
```
1. subfinder_scan + amass_scan (subdomain discovery)
2. httpx probing (live host validation)
3. nuclei_scan (vulnerability scanning)
4. feroxbuster_scan (content discovery)
5. arjun_parameter_discovery (parameter mining)
6. sqlmap_scan + dalfox_xss_scan (injection testing)
```

#### Internal Network Assessment
```
1. nmap_scan (-sn host discovery)
2. rustscan_fast_scan (port enumeration)
3. nmap_advanced_scan (service detection)
4. enum4linux_ng_advanced (SMB enumeration)
5. responder_credential_harvest (credential capture)
6. netexec_scan (lateral movement testing)
```

#### CTF Challenge Approach
```
1. checksec_analyze (binary protections)
2. strings_extract + binwalk_analyze (initial analysis)
3. ghidra_analysis (reverse engineering)
4. ropgadget_search (exploitation research)
5. pwntools_exploit (automated exploitation)
```

---

## Report Architecture & Vulnerability Correlation

### Vulnerability Classification System

#### Severity Scoring Matrix
```
CRITICAL (9.0-10.0):
- Remote Code Execution
- Authentication Bypass
- Privilege Escalation to root/admin
- Data Exfiltration

HIGH (7.0-8.9):
- SQL Injection
- Cross-Site Scripting (Stored)
- Local File Inclusion
- Sensitive Data Exposure

MEDIUM (4.0-6.9):
- Cross-Site Scripting (Reflected)
- Cross-Site Request Forgery
- Information Disclosure
- Weak Authentication

LOW (0.1-3.9):
- Verbose Error Messages
- Missing Security Headers
- Version Disclosure
- Directory Listing
```

#### Vulnerability Correlation Engine

##### Multi-Tool Validation
```python
def correlate_vulnerabilities(tool_results):
    validated_vulns = []
    
    # Cross-reference SQL injection findings
    sqlmap_results = filter_results(tool_results, "sqlmap")
    nuclei_sqli = filter_results(tool_results, "nuclei", tag="sqli")
    
    if sqlmap_results and nuclei_sqli:
        confidence_score = 0.95
        validated_vulns.append({
            "type": "SQL Injection",
            "confidence": confidence_score,
            "tools": ["sqlmap", "nuclei"],
            "severity": "HIGH"
        })
```

##### Attack Chain Discovery
```python
def discover_attack_chains(vulnerabilities, network_topology):
    attack_chains = []
    
    # Example: Web shell upload -> Privilege escalation -> Lateral movement
    if has_vulnerability(vulnerabilities, "file_upload") and \
       has_vulnerability(vulnerabilities, "weak_file_permissions"):
        
        chain = {
            "name": "Web Shell to Root Compromise",
            "steps": [
                "Upload malicious file via unrestricted upload",
                "Execute uploaded shell",
                "Exploit weak file permissions for privilege escalation",
                "Access sensitive system files"
            ],
            "impact": "CRITICAL",
            "likelihood": "HIGH"
        }
        attack_chains.append(chain)
```

### Report Structure Templates

#### Executive Summary Template
```markdown
# Security Assessment Report: {target}

## Executive Summary
- **Assessment Date**: {date}
- **Assessment Type**: {type}
- **Critical Findings**: {critical_count}
- **High Risk Issues**: {high_count}
- **Overall Risk Level**: {risk_level}

## Key Findings
1. **Most Critical Issue**: {critical_description}
2. **Business Impact**: {impact_analysis}
3. **Immediate Actions Required**: {remediation_priority}

## Risk Dashboard
[Visual risk matrix with severity distribution]
```

#### Technical Findings Template
```markdown
## Vulnerability Details

### {vuln_id}: {vulnerability_name}
- **Severity**: {severity}
- **CVSS Score**: {cvss_score}
- **Affected Components**: {components}
- **Discovery Tools**: {tools_used}

#### Description
{detailed_description}

#### Proof of Concept
{poc_steps}
```{code_block}
{exploitation_code}
```

#### Business Impact
{business_impact_analysis}

#### Remediation
{remediation_steps}
```

#### Technical Appendix Template
```markdown
## Methodology
### Tools Used
{tool_list_with_versions}

### Scanning Timeline
{timeline_of_activities}

### Network Topology
{network_diagram}

### Raw Tool Outputs
{sanitized_tool_outputs}
```

### Automated Report Generation

#### Report Assembly Logic
```python
def generate_comprehensive_report(scan_results, target_info):
    report = SecurityReport(target_info)
    
    # Vulnerability correlation and validation
    validated_vulns = correlate_vulnerabilities(scan_results)
    
    # Risk assessment
    risk_matrix = calculate_risk_matrix(validated_vulns, target_info.criticality)
    
    # Attack chain analysis
    attack_chains = discover_attack_chains(validated_vulns, target_info.topology)
    
    # Executive summary generation
    exec_summary = generate_executive_summary(validated_vulns, risk_matrix)
    
    # Technical details compilation
    tech_details = compile_technical_findings(validated_vulns, scan_results)
    
    # Remediation prioritization
    remediation_plan = prioritize_remediation(validated_vulns, attack_chains)
    
    return report.compile_final_report()
```

#### Visual Dashboard Generation
```python
def create_vulnerability_dashboard(vulnerabilities):
    dashboard = {
        "severity_distribution": plot_severity_chart(vulnerabilities),
        "timeline_analysis": plot_discovery_timeline(vulnerabilities),
        "network_topology": generate_network_diagram(vulnerabilities),
        "risk_matrix": create_risk_heatmap(vulnerabilities),
        "remediation_timeline": generate_remediation_gantt(vulnerabilities)
    }
    return dashboard
```

### Quality Assurance & Validation

#### False Positive Reduction
```python
def reduce_false_positives(raw_findings):
    validated_findings = []
    
    for finding in raw_findings:
        # Multi-tool confirmation
        if finding.confirmed_by_multiple_tools():
            confidence = 0.9
        
        # Manual validation checks
        if validate_vulnerability(finding):
            confidence += 0.1
        
        # Context-aware filtering
        if contextually_relevant(finding, target_context):
            validated_findings.append(finding)
    
    return validated_findings
```

#### Impact Assessment Framework
```python
def assess_business_impact(vulnerability, business_context):
    impact_factors = {
        "data_sensitivity": business_context.data_classification,
        "system_criticality": business_context.system_importance,
        "compliance_requirements": business_context.regulatory_framework,
        "exposure_level": vulnerability.accessibility
    }
    
    return calculate_business_risk(impact_factors, vulnerability.technical_risk)
```

---

**Note:** This comprehensive guide covers all available HexStrike AI MCP tools with intelligent workflow automation, adaptive scanning sequences, and advanced report generation capabilities. Always ensure you have proper authorization before using these tools against any target systems. Follow responsible disclosure practices and respect legal and ethical boundaries.
