#!/bin/bash
# ==============================================================================
# BOUNTYBUD ULTIMATE - THE 100% TOTAL WAR SETUP (DEFINITIVE)
# ==============================================================================
# Installs and maps ALL 80 TOOLS | Isolated | Safe | Distro-Agnostic
# ==============================================================================

set -e

# --- Configuration ---
BIN_DIR="$HOME/.local/bin"
TOOLS_DIR="$HOME/bounty_tools"
PY_VENV="$TOOLS_DIR/venv"
GO_BIN="$HOME/go/bin"
mkdir -p "$BIN_DIR" "$TOOLS_DIR"
export PATH="$BIN_DIR:$GO_BIN:$HOME/.cargo/bin:$PATH"

echo "🚀 Starting The Definitive 100% BountyBud Setup..."

# --- 0. System Integrity Protection ---
echo "🧹 Purging any previous interpreter shadows..."
rm -f "$BIN_DIR/python"* "$BIN_DIR/pip"* "$BIN_DIR/activate"*

# --- 1. System Dependencies & Specialized Tools ---
echo "📦 Installing system and AUR packages..."
if [ -f /etc/arch-release ]; then
    # Core system tools
    sudo pacman -S --noconfirm --needed \
        base-devel git go python python-pip rust cargo ruby \
        nmap masscan perl-image-exiftool john hashcat hydra medusa \
        proxychains-ng subversion metasploit wget curl jq xxd unzip \
        foremost steghide binwalk zaproxy burpsuite
    
    # AUR tools (Handling the missing ones)
    if command -v paru &> /dev/null; then
        paru -S --noconfirm --needed dirb dnsenum whatweb kube-bench-bin kube-hunter-bin
    elif command -v yay &> /dev/null; then
        yay -S --noconfirm --needed dirb dnsenum whatweb kube-bench-bin kube-hunter-bin
    fi
fi

# --- 2. Isolated Python Arsenal ---
echo "🐍 Building isolated Python environment..."
[ ! -d "$PY_VENV" ] && python3 -m venv "$PY_VENV"
env -i HOME="$HOME" PATH="/usr/bin:/bin" "$PY_VENV/bin/pip" install --upgrade pip setuptools wheel

PYTHON_TOOLS=(
    "sqlmap" "arjun" "dirsearch" "wafw00f" "checkov" "trufflehog" "s3scanner" "shodan" 
    "uro" "dnsgen" "fierce" "droopescan" "prowler" "scoutsuite" "theHarvester" 
    "sherlock-project" "waymore" "smbmap" "unfurl"
)
for tool in "${PYTHON_TOOLS[@]}"; do
    env -i HOME="$HOME" PATH="/usr/bin:/bin" "$PY_VENV/bin/pip" install "$tool" || echo "⚠️ $tool skipped"
done

# GitHub Python Tools
echo "  -> linkfinder, jwt-tool, paramspider, joomscan"
git clone --depth 1 https://github.com/GerbenJavado/LinkFinder "$TOOLS_DIR/linkfinder" 2>/dev/null || (cd "$TOOLS_DIR/linkfinder" && git pull)
git clone --depth 1 https://github.com/ticarpi/jwt_tool "$TOOLS_DIR/jwt_tool_repo" 2>/dev/null || (cd "$TOOLS_DIR/jwt_tool_repo" && git pull)
git clone --depth 1 https://github.com/devanshbatham/ParamSpider "$TOOLS_DIR/paramspider" 2>/dev/null || (cd "$TOOLS_DIR/paramspider" && git pull)
git clone --depth 1 https://github.com/rezasp/joomscan.git "$TOOLS_DIR/joomscan" 2>/dev/null || (cd "$TOOLS_DIR/joomscan" && git pull)

# --- 3. Go Arsenal ---
echo "🎯 Building Go power suite..."
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/haccer/subjack@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/jaeles-project/gospider@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/lc/subjs@latest"
    "github.com/Emoe/kxss@latest"
    "github.com/bp0lr/gauplus@latest"
    "github.com/tomnomnom/httprobe@latest"
    "github.com/OWASP/Amass/v3/...@master"
)
for tool in "${GO_TOOLS[@]}"; do
    go install -v "$tool" || true
done

# Findomain (Static binary fallback)
if ! command -v findomain &> /dev/null; then
    wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
    unzip -o findomain-linux.zip -d "$BIN_DIR/" && chmod +x "$BIN_DIR/findomain" && rm findomain-linux.zip
fi

# --- 4. Rust & Ruby ---
echo "🦀 Building Rust & Ruby tools..."
cargo install rustscan feroxbuster || true
gem install wpscan evil-winrm || true
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$BIN_DIR"

# --- 5. THE ULTIMATE MAPPING ---
echo "🔗 Mapping all 80 binaries safely..."

mk_safe_wrap() {
    local alias_name=$1
    local source_bin=$2
    [ -z "$source_bin" ] || [ ! -f "$source_bin" ] && return
    rm -f "$BIN_DIR/$alias_name"
    cat <<EOF > "$BIN_DIR/$alias_name"
#!/bin/bash
env -u LD_PRELOAD "$source_bin" "\$@"
EOF
    chmod +x "$BIN_DIR/$alias_name"
}

V_BIN="$PY_VENV/bin"
V_PY="$PY_VENV/bin/python3"

# Standard Python Wrappers
PYTHON_LIST=("sqlmap" "arjun" "dirsearch" "wafw00f" "checkov" "trufflehog" "s3scanner" "shodan" "uro" "dnsgen" "fierce" "droopescan" "prowler" "waymore" "smbmap" "unfurl")
for t in "${PYTHON_LIST[@]}"; do mk_safe_wrap "$t" "$V_BIN/$t"; done

# Python Naming Overrides
mk_safe_wrap "theharvester" "$V_BIN/theHarvester"
mk_safe_wrap "scout-suite" "$V_BIN/scout"
mk_safe_wrap "sherlock" "$V_BIN/sherlock"

# Manual Python Tools
[ -f "$TOOLS_DIR/linkfinder/linkfinder.py" ] && echo -e "#!/bin/bash\nenv -u LD_PRELOAD $V_PY $TOOLS_DIR/linkfinder/linkfinder.py \"\$@\"" > "$BIN_DIR/linkfinder" && chmod +x "$BIN_DIR/linkfinder"
[ -f "$TOOLS_DIR/jwt_tool_repo/jwt_tool.py" ] && echo -e "#!/bin/bash\nenv -u LD_PRELOAD $V_PY $TOOLS_DIR/jwt_tool_repo/jwt_tool.py \"\$@\"" > "$BIN_DIR/jwt-tool" && chmod +x "$BIN_DIR/jwt-tool"
[ -f "$TOOLS_DIR/paramspider/paramspider.py" ] && echo -e "#!/bin/bash\nenv -u LD_PRELOAD $V_PY $TOOLS_DIR/paramspider/paramspider.py \"\$@\"" > "$BIN_DIR/paramspider" && chmod +x "$BIN_DIR/paramspider"
[ -f "$TOOLS_DIR/joomscan/joomscan.pl" ] && echo -e "#!/bin/bash\nperl $TOOLS_DIR/joomscan/joomscan.pl \"\$@\"" > "$BIN_DIR/joomscan" && chmod +x "$BIN_DIR/joomscan"

# Direct links for everything else (Safe because they don't shadow python)
DIRECT_LINKS=(
    "$HOME/go/bin/subfinder" "$HOME/go/bin/httpx" "$HOME/go/bin/nuclei" "$HOME/go/bin/katana"
    "$HOME/go/bin/dnsx" "$HOME/go/bin/ffuf" "$HOME/go/bin/amass" "$HOME/go/bin/gauplus"
    "$HOME/go/bin/httprobe" "$HOME/go/bin/subjs" "$HOME/go/bin/interactsh-client"
    "/usr/bin/nmap" "/usr/bin/masscan" "/usr/bin/msfconsole" "/usr/bin/dirb" "/usr/bin/dnsenum"
    "/usr/bin/whatweb" "/usr/bin/foremost" "/usr/bin/steghide" "/usr/bin/binwalk"
    "/usr/bin/kube-bench" "/usr/bin/kube-hunter" "/usr/bin/zaproxy" "/usr/bin/burpsuite"
)

# Map direct links to their expected BountyBud names
ln -sf "$HOME/go/bin/subjs" "$BIN_DIR/getjs" 2>/dev/null || true
ln -sf "$HOME/go/bin/interactsh-client" "$BIN_DIR/interactsh" 2>/dev/null || true
for link in "${DIRECT_LINKS[@]}"; do
    [ -f "$link" ] && ln -sf "$link" "$BIN_DIR/$(basename "$link")"
done

echo "✅ DONE. 80-tool Arsenal is Armed, Isolated, and Complete."
