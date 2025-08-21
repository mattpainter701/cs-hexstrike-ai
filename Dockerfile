FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV HEXSTRIKE_PORT=8888
ENV HEXSTRIKE_HOST=0.0.0.0
ENV PATH="/usr/local/go/bin:/root/go/bin:/root/.cargo/bin:${PATH}"

# Create app directory
WORKDIR /app

# Fix sources.list to use working mirror
RUN echo 'deb http://mirror.math.princeton.edu/pub/kali kali-rolling main contrib non-free non-free-firmware' > /etc/apt/sources.list && \
    echo 'deb-src http://mirror.math.princeton.edu/pub/kali kali-rolling main contrib non-free non-free-firmware' >> /etc/apt/sources.list

# Install minimal required packages
RUN apt-get clean && \
    apt-get update && \
    apt-get install -y \
    python3 python3-pip curl wget git \
    nmap sqlmap gobuster nikto hydra john \
    aircrack-ng tcpdump netcat-traditional \
    ruby ruby-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    /root/.cargo/bin/rustup default stable

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/ffuf/ffuf@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/tomnomnom/anew@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest

# Install Rust-based security tools
RUN /root/.cargo/bin/cargo install rustscan feroxbuster

# Install Python-based security tools (compatible with Python 3.13)
RUN pip3 install --no-cache-dir --break-system-packages \
    requests beautifulsoup4 selenium webdriver-manager \
    mitmproxy dirsearch wpscan \
    httpie pwntools \
    pycryptodome paramiko ldap3 impacket \
    volatility3 smbmap

# Install additional tools via apt that may not be compatible with Python 3.13
RUN apt-get update && apt-get install -y \
    python3-angr python3-trivy \
    && apt-get clean && rm -rf /var/lib/apt/lists/* || true

# Install Ruby-based tools
RUN gem install evil-winrm

# Install build dependencies for masscan
RUN apt-get update && apt-get install -y \
    build-essential make gcc unzip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install additional tools from external sources
RUN mkdir -p /opt/tools

# Install Amass
RUN wget -q https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip -O /tmp/amass.zip && \
    unzip -q /tmp/amass.zip -d /tmp/ && \
    mv /tmp/amass_Linux_amd64/amass /usr/local/bin/ && \
    chmod +x /usr/local/bin/amass && \
    rm -rf /tmp/amass* || true

# Install Katana
RUN wget -q https://github.com/projectdiscovery/katana/releases/download/v1.0.5/katana_1.0.5_linux_amd64.tar.gz -O /tmp/katana.tar.gz && \
    tar -xzf /tmp/katana.tar.gz -C /tmp/ && \
    mv /tmp/katana /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && \
    rm -rf /tmp/katana* || true

# Install Dalfox
RUN wget -q https://github.com/hahwul/dalfox/releases/download/v2.9.2/dalfox_2.9.2_linux_amd64.tar.gz -O /tmp/dalfox.tar.gz && \
    tar -xzf /tmp/dalfox.tar.gz -C /tmp/ && \
    mv /tmp/dalfox /usr/local/bin/ && \
    chmod +x /usr/local/bin/dalfox && \
    rm -rf /tmp/dalfox* || true

# Install Masscan
RUN git clone https://github.com/robertdavidgraham/masscan.git /opt/tools/masscan && \
    cd /opt/tools/masscan && make && ln -sf /opt/tools/masscan/bin/masscan /usr/local/bin/ || true

# Copy application files
COPY . /app/

# Install Python dependencies for HexStrike
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Create necessary directories
RUN mkdir -p /app/data /app/results /app/logs /app/wordlists

# Download SecLists wordlists
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /app/wordlists/SecLists

# Set proper permissions
RUN chmod +x /app/hexstrike_server.py /app/hexstrike_mcp.py

# Update Nuclei templates
RUN nuclei -update-templates || true

# Expose ports for HexStrike
EXPOSE 8888 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8888/health || exit 1

# Default command to start HexStrike server
CMD ["python3", "/app/hexstrike_server.py", "--port", "8888"]