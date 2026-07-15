# ==========================================
# Stage 1: Go Builder (Compile all Go tools)
# ==========================================
FROM golang:latest AS builder

# Install PDTM (ProjectDiscovery Tool Manager) to easily fetch PD tools
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
RUN pdtm -install-all

# Install other Go-based tools not in PDTM
RUN go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/httprobe@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/bp0lr/gauplus@latest && \
    go install -v github.com/OJ/gobuster/v3@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/tomnomnom/anew@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master && \
    go install -v github.com/haccer/subjack@latest && \
    go install -v github.com/003random/getjs@latest && \
    go install -v github.com/tomnomnom/hacks/kxss@latest && \
    go install -v github.com/tomnomnom/unfurl@latest

RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /go/bin

# Rename chaos-client to chaos
RUN if [ -f /root/.pdtm/go/bin/chaos-client ]; then mv /root/.pdtm/go/bin/chaos-client /root/.pdtm/go/bin/chaos; fi

# ==========================================
# Stage 2: Final Image
# ==========================================
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.bountybud-tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV MCP_PORT=8000

# Install system dependencies, Python, Ruby, Java, and APT security tools
# We use Kali Linux repositories to fetch all the tools that were missing in Debian.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    ruby-full default-jre \
    curl wget git build-essential \
    nmap masscan \
    exiftool steghide foremost \
    hashcat john hydra medusa \
    smbmap smbclient \
    sudo gnupg lsb-release \
    whatweb dirb nikto zaproxy burpsuite binwalk jq \
    dnsenum fierce theharvester sherlock \
    feroxbuster \
    joomscan \
    && rm -rf /var/lib/apt/lists/*

# Install Metasploit Framework (Official installer)
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
    chmod 755 msfinstall && \
    ./msfinstall && \
    rm msfinstall

# Install Ruby-based tools
RUN gem install wpscan evil-winrm

# Install Core API Server dependencies first (Do NOT use || true here, this MUST succeed)
RUN pip3 install --no-cache-dir --break-system-packages \
    fastapi uvicorn sse-starlette requests

# Install all the remaining obscure Python/Rust/Go security tools
COPY scripts/install_missing.sh /tmp/install_missing.sh
RUN chmod +x /tmp/install_missing.sh && /tmp/install_missing.sh

# Create centralized bin directory
RUN mkdir -p /root/.bountybud-tools/bin

# Copy compiled Go binaries from builder stage
COPY --from=builder /go/bin/* /root/.bountybud-tools/bin/
COPY --from=builder /root/.pdtm/go/bin/* /root/.bountybud-tools/bin/

# Copy the MCP Server codebase into the container
WORKDIR /app
COPY . /app

# Expose the FastAPI SSE port
EXPOSE 8000

# Set the MCP server as the default entrypoint
ENTRYPOINT ["python3", "mcp_server.py"]
