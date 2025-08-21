# HexStrike AI + Cursor Integration Setup

## 🎯 Overview
This guide shows you how to integrate HexStrike AI's 150+ cybersecurity tools with Cursor IDE using MCP (Model Context Protocol).

## ⚡ Quick Setup

### 1. Ensure HexStrike Container is Running
```bash
# Start the HexStrike container
docker-compose up -d

# Verify it's healthy
curl http://localhost:8888/health
```

### 2. Configure Cursor MCP Integration

#### Option A: User Settings (Recommended)
Open Cursor settings and add to your user configuration:

```json
{
  "cursor.mcp.servers": {
    "hexstrike-ai": {
      "command": "python",
      "args": [
        "C:/Users/Home/deepseek/hexstrike-ai/hexstrike_mcp.py",
        "--server",
        "http://localhost:8888"
      ],
      "description": "HexStrike AI Cybersecurity Tools"
    }
  }
}
```

#### Option B: Workspace Settings
Use the `.vscode/settings.json` file already created in this project.

### 3. Restart Cursor
Close and restart Cursor to load the MCP configuration.

### 4. Test the Integration
Open a new chat in Cursor and try:
```
@hexstrike-ai scan 172.16.16.1 with nmap for open ports
```

## 🛠️ Available Tools

Once connected, you can ask Cursor's AI to use any of these tools:

### Network Security
- **nmap_scan**: Advanced port scanning and OS detection
- **rustscan_scan**: Ultra-fast port discovery
- **masscan_scan**: High-speed internet-scale scanning
- **amass_enum**: Subdomain enumeration and OSINT

### Web Application Security  
- **gobuster_scan**: Directory and file enumeration
- **feroxbuster_scan**: Recursive content discovery
- **nuclei_scan**: Vulnerability scanning with 4000+ templates
- **sqlmap_scan**: SQL injection testing
- **wpscan_scan**: WordPress security assessment

### Analysis & Intelligence
- **httpx_probe**: Fast HTTP probing and tech detection
- **subfinder_enum**: Passive subdomain discovery
- **whatweb_analyze**: Web technology identification

## 📝 Example Usage

### Basic Network Scan
```
Hey Cursor, use HexStrike to scan 192.168.1.1 with nmap to find open ports and services
```

### Web Application Testing
```
Run a comprehensive web security scan on https://example.com using nuclei and gobuster
```

### Subdomain Enumeration
```
Find all subdomains for example.com using amass and subfinder
```

### Vulnerability Assessment
```
Scan target.com for vulnerabilities using nuclei with all available templates
```

## 🔧 Troubleshooting

### MCP Connection Issues
1. Ensure Docker container is running: `docker ps`
2. Test API manually: `curl http://localhost:8888/health`
3. Check Python path: `python --version`
4. Restart Cursor completely

### Tool Execution Issues
1. Check container logs: `docker logs hexstrike-ai-platform`
2. Verify tool availability via health endpoint
3. Ensure target is reachable from container

## 🚀 Advanced Configuration

### Custom Timeout
```json
{
  "cursor.mcp.servers": {
    "hexstrike-ai": {
      "command": "python",
      "args": [
        "C:/Users/Home/deepseek/hexstrike-ai/hexstrike_mcp.py",
        "--server",
        "http://localhost:8888"
      ],
      "timeout": 600,
      "description": "HexStrike AI Cybersecurity Tools"
    }
  }
}
```

### Debug Mode
Add `--debug` flag to see detailed logging:
```json
"args": [
  "C:/Users/Home/deepseek/hexstrike-ai/hexstrike_mcp.py",
  "--server",
  "http://localhost:8888",
  "--debug"
]
```

## 📊 Platform Status
- **Container**: Kali Linux 2025.2
- **Tools Available**: 36/127 security tools
- **API Status**: Healthy and operational
- **MCP Version**: 1.13.0

## ⚡ Ready to Go!
Your HexStrike AI cybersecurity platform is now integrated with Cursor. Start asking the AI to perform security scans and assessments!