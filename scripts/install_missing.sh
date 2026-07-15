#!/bin/bash
set -e

echo "Installing missing APT packages..."
mkdir -p /root/.bountybud-tools/bin

apt-get update
apt-get install -y --no-install-recommends \
    sqlmap dirsearch wafw00f mitmproxy trivy findomain unzip python3-dev pkg-config libssl-dev

echo "Installing Python pip tools..."
for pkg in arjun dnsgen waymore droopescan s3scanner prowler scoutsuite kube-hunter checkov uro; do
    pip3 install --no-cache-dir --break-system-packages --ignore-installed $pkg || true
done

echo "Installing Rustscan..."
curl -sLO https://github.com/RustScan/RustScan/releases/download/2.2.3/rustscan_2.2.3_amd64.deb
dpkg -i rustscan_2.2.3_amd64.deb || true
rm rustscan_2.2.3_amd64.deb

echo "Installing kube-bench..."
curl -sLO https://github.com/aquasecurity/kube-bench/releases/download/v0.6.17/kube-bench_0.6.17_linux_amd64.deb
dpkg -i kube-bench_0.6.17_linux_amd64.deb || true
rm kube-bench_0.6.17_linux_amd64.deb

echo "Installing x8..."
apt-get install -y cargo || true
cargo install x8 || true
cp ~/.cargo/bin/x8 /root/.bountybud-tools/bin/x8 || true

echo "Installing LinkFinder..."
git clone https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder || true
cd /opt/linkfinder && pip3 install -r requirements.txt --break-system-packages || true
chmod +x /opt/linkfinder/linkfinder.py
ln -sf /opt/linkfinder/linkfinder.py /root/.bountybud-tools/bin/linkfinder

echo "Installing jwt_tool..."
git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool || true
cd /opt/jwt_tool && pip3 install -r requirements.txt --break-system-packages || true
chmod +x /opt/jwt_tool/jwt_tool.py
ln -sf /opt/jwt_tool/jwt_tool.py /root/.bountybud-tools/bin/jwt-tool

echo "Installing paramspider..."
git clone https://github.com/devanshbatham/paramspider /opt/paramspider || true
cd /opt/paramspider && pip3 install . --break-system-packages || true
ln -sf $(which paramspider) /root/.bountybud-tools/bin/paramspider || true

echo "Done!"
