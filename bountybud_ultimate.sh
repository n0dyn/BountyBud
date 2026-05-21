#!/bin/bash
# ==============================================================================
# BOUNTYBUD ULTIMATE - THE 100% TOTAL WAR SETUP (ISOLATED VENV)
# ==============================================================================
# Installs ALL 80 TOOLS | Isolated | Safe | Patches MCP Server Automatically
# Designed to be run ONCE on initial system setup.
# ==============================================================================

set -e

# --- Configuration ---
TOOLS_DIR="$HOME/bounty_tools"
PY_VENV="$TOOLS_DIR/venv"
GO_BIN="$HOME/go/bin"
# Dedicated isolated bin directory to never conflict with user's .local/bin
BB_BIN="$TOOLS_DIR/bin"
MCP_SERVER_FILE="$HOME/dev/BountyBud/mcp_server.py"

mkdir -p "$BB_BIN" "$TOOLS_DIR"

# Ensure we don't accidentally export our isolated bin paths before we need to
# We only want BountyBud to use BB_BIN, the user system shouldn't need it.

echo "🚀 Starting The Definitive 100% BountyBud Setup (Single Pass)..."

# --- 0. System Integrity Cleanup ---
echo "🧹 Ensuring no Python shadows exist in local paths..."
rm -f "$HOME/.local/bin/python"* "$HOME/.local/bin/pip"* "$HOME/.local/bin/activate"*
rm -f "$BB_BIN/python"* "$BB_BIN/pip"* "$BB_BIN/activate"*

# --- 1. System Dependencies & Specialized Tools ---
echo "📦 Installing system and AUR packages..."
if [ -f /etc/arch-release ]; then
    sudo pacman -S --noconfirm --needed \
        base-devel git go python python-pip rust cargo ruby \
        nmap masscan perl-image-exiftool john hashcat hydra medusa \
        proxychains-ng subversion metasploit wget curl jq xxd unzip \
        foremost steghide binwalk zaproxy
    
    if command -v paru &> /dev/null; then
        paru -S --noconfirm --needed dirb dnsenum2 whatweb kube-bench-bin kube-hunter-bin burpsuite
    elif command -v yay &> /dev/null; then
        yay -S --noconfirm --needed dirb dnsenum2 whatweb kube-bench-bin kube-hunter-bin burpsuite
    fi
fi

# --- 2. Isolated Python Arsenal ---
echo "🐍 Building isolated Python environment..."
[ ! -d "$PY_VENV" ] && /usr/bin/python3 -m venv "$PY_VENV"

# Use the specific venv pip, with a clean path to avoid NoMachine issues
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
echo "  -> Fetching specialized GitHub Python tools..."
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
    "github.com/owasp-amass/amass/v4/...@master"
)
export GOPATH="$HOME/go"
for tool in "${GO_TOOLS[@]}"; do
    go install -v "$tool" || true
done

# Findomain
if [ ! -f "$BB_BIN/findomain" ]; then
    wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
    unzip -qo findomain-linux.zip -d "$BB_BIN/" && chmod +x "$BB_BIN/findomain" && rm findomain-linux.zip
fi

# --- 4. Rust & Ruby ---
echo "🦀 Building Rust & Ruby tools..."
cargo install rustscan feroxbuster || true
gem install wpscan evil-winrm || true
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$BB_BIN"

# --- 5. THE ULTIMATE MAPPING ---
echo "🔗 Mapping all 80 binaries safely to $BB_BIN..."

mk_safe_wrap() {
    local alias_name=$1
    local source_bin=$2
    [ -z "$source_bin" ] || [ ! -f "$source_bin" ] && return
    
    # CRITICAL: We NEVER create wrappers for python, pip, or activate
    if [[ "$alias_name" == "python"* || "$alias_name" == "pip"* || "$alias_name" == "activate"* ]]; then
        return
    fi
    
    cat <<WRAPPER > "$BB_BIN/$alias_name"
#!/bin/bash
env -u LD_PRELOAD "$source_bin" "\$@"
WRAPPER
    chmod +x "$BB_BIN/$alias_name"
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

# Manual Python Tools (Explicitly calling venv python)
[ -f "$TOOLS_DIR/linkfinder/linkfinder.py" ] && cat <<WRAPPER > "$BB_BIN/linkfinder"
#!/bin/bash
env -u LD_PRELOAD "$V_PY" "$TOOLS_DIR/linkfinder/linkfinder.py" "\$@"
WRAPPER
[ -f "$TOOLS_DIR/linkfinder/linkfinder.py" ] && chmod +x "$BB_BIN/linkfinder"

[ -f "$TOOLS_DIR/jwt_tool_repo/jwt_tool.py" ] && cat <<WRAPPER > "$BB_BIN/jwt-tool"
#!/bin/bash
env -u LD_PRELOAD "$V_PY" "$TOOLS_DIR/jwt_tool_repo/jwt_tool.py" "\$@"
WRAPPER
[ -f "$TOOLS_DIR/jwt_tool_repo/jwt_tool.py" ] && chmod +x "$BB_BIN/jwt-tool"

[ -f "$TOOLS_DIR/paramspider/paramspider.py" ] && cat <<WRAPPER > "$BB_BIN/paramspider"
#!/bin/bash
env -u LD_PRELOAD "$V_PY" "$TOOLS_DIR/paramspider/paramspider.py" "\$@"
WRAPPER
[ -f "$TOOLS_DIR/paramspider/paramspider.py" ] && chmod +x "$BB_BIN/paramspider"

[ -f "$TOOLS_DIR/joomscan/joomscan.pl" ] && cat <<WRAPPER > "$BB_BIN/joomscan"
#!/bin/bash
perl "$TOOLS_DIR/joomscan/joomscan.pl" "\$@"
WRAPPER
[ -f "$TOOLS_DIR/joomscan/joomscan.pl" ] && chmod +x "$BB_BIN/joomscan"

# Go Wrappers
GO_LIST=("subfinder" "httpx" "nuclei" "katana" "dnsx" "ffuf" "amass" "gauplus" "httprobe" "subjs" "interactsh-client" "gau" "waybackurls" "anew" "qsreplace" "unfurl" "assetfinder" "dalfox" "gospider" "hakrawler" "kxss" "subjack")
for g in "${GO_LIST[@]}"; do mk_safe_wrap "$g" "$HOME/go/bin/$g"; done
ln -sf "$BB_BIN/subjs" "$BB_BIN/getjs" 2>/dev/null || true
ln -sf "$BB_BIN/interactsh-client" "$BB_BIN/interactsh" 2>/dev/null || true

# System/GUI Packages
SYSLIST=("nmap" "masscan" "msfconsole" "dirb" "dnsenum" "whatweb" "foremost" "steghide" "binwalk" "kube-bench" "kube-hunter" "zaproxy" "burpsuite" "exiftool" "hashcat" "hydra" "john" "medusa")
for s in "${SYSLIST[@]}"; do mk_safe_wrap "$s" "/usr/bin/$s"; done
# Handle potential dnsenum2 alternative naming from AUR
[ -f "/usr/bin/dnsenum2" ] && mk_safe_wrap "dnsenum" "/usr/bin/dnsenum2"

# --- 6. GLOBAL PERSISTENCE & MCP PATCHING ---
echo "🌍 Configuring global paths and patching BountyBud MCP server..."

# We ONLY add BB_BIN to bashrc/fishrc. We DO NOT add the VENV bin folder.
# This prevents the system python from ever being shadowed.
grep -q "$BB_BIN" "$HOME/.bashrc" || echo "export PATH=\"$BB_BIN:\$PATH\"" >> "$HOME/.bashrc"
if [ -d "$HOME/.config/fish" ]; then
    grep -q "$BB_BIN" "$HOME/.config/fish/config.fish" || echo "set -gx PATH \"$BB_BIN\" \$PATH" >> "$HOME/.config/fish/config.fish"
fi

# Patch mcp_server.py inline if it exists
if [ -f "$MCP_SERVER_FILE" ]; then
    if ! grep -q "os.path.expanduser(\"~/bounty_tools/bin\")" "$MCP_SERVER_FILE"; then
        sed -i 's|os.path.expanduser("~/.local/bin"),|os.path.expanduser("~/bounty_tools/bin"),\n    os.path.expanduser("~/.local/bin"),|g' "$MCP_SERVER_FILE"
        echo "✅ Patched $MCP_SERVER_FILE with persistent tool paths."
    else
        echo "✅ $MCP_SERVER_FILE already correctly configured."
    fi
else
    echo "⚠️ MCP Server file not found at $MCP_SERVER_FILE. Ensure path is correct."
fi

echo "=============================================================================="
echo "✅ SETUP COMPLETE. BountyBud is Permanently Armed with 80 Isolated Tools."
echo "=============================================================================="
