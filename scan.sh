#!/bin/bash
# Usage: ./recon.sh <domain.com>
set -e

DOMAIN="$1"
if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

REPORT_DIR="report"
JS_DIR="$REPORT_DIR/js"
SCREENSHOTS_DIR="$REPORT_DIR/aquatone/screenshots"
DATA_DIR="data"

mkdir -p "$JS_DIR" "$SCREENSHOTS_DIR" "$DATA_DIR"

echo "=== Recon Report Automation ==="
echo "Target: $DOMAIN"
echo

# 1. Subdomain Enumeration
echo "[*] Running Amass..."
amass enum -passive -d "$DOMAIN" -o "$DATA_DIR/amass.txt"
echo "[+] Amass done."

echo "[*] Running Subfinder..."
subfinder -d "$DOMAIN" -o "$DATA_DIR/subfinder.txt"
echo "[+] Subfinder done."

echo "[*] Running Assetfinder..."
assetfinder --subs-only "$DOMAIN" > "$DATA_DIR/assetfinder.txt"
echo "[+] Assetfinder done."

echo "[*] Running Findomain..."
findomain -t "$DOMAIN" -u "$DATA_DIR/findomain.txt"
echo "[+] Findomain done."

# 2. Merge and Deduplicate Subdomains
echo "[*] Merging and deduplicating subdomains..."
cat "$DATA_DIR/"*.txt | sort -u > "$DATA_DIR/all-subs.txt"
echo "[+] Subdomain list created: $DATA_DIR/all-subs.txt ($(wc -l < "$DATA_DIR/all-subs.txt") lines)"

# 3. Probe for Alive Hosts
echo "[*] Probing for alive hosts with dnsx..."
cat "$DATA_DIR/all-subs.txt" | dnsx -silent -a -resp-only > "$DATA_DIR/alive.txt"
echo "[+] Alive hosts (DNS): $DATA_DIR/alive.txt ($(wc -l < "$DATA_DIR/alive.txt") lines)"

echo "[*] Probing for alive web hosts with httpx..."
cat "$DATA_DIR/alive.txt" | httpx -silent -status-code -title -tech-detect -threads 50 > "$DATA_DIR/alive-web.txt"
echo "[+] Alive web hosts: $DATA_DIR/alive-web.txt ($(wc -l < "$DATA_DIR/alive-web.txt") lines)"

# 4. URL collection
echo "[*] Collecting URLs with waybackurls..."
cat "$DATA_DIR/all-subs.txt" | waybackurls > "$DATA_DIR/waybackurls.txt"
echo "[+] waybackurls done."

echo "[*] Collecting URLs with gau..."
cat "$DATA_DIR/all-subs.txt" | gau > "$DATA_DIR/gau.txt"
echo "[+] gau done."

echo "[*] Merging and deduplicating URLs..."
cat "$DATA_DIR/waybackurls.txt" "$DATA_DIR/gau.txt" | sort -u > "$DATA_DIR/all-urls.txt"
echo "[+] URL list created: $DATA_DIR/all-urls.txt ($(wc -l < "$DATA_DIR/all-urls.txt") lines)"

# 5. Parameter discovery
echo "[*] Extracting parameters from URLs..."
grep -oP '\?\K[^=]+' "$DATA_DIR/all-urls.txt" | sort -u > "$DATA_DIR/params.txt"
echo "[+] Parameters extracted: $DATA_DIR/params.txt ($(wc -l < "$DATA_DIR/params.txt") lines)"

# 6. Vulnerability scans
echo "[*] Running nuclei..."
cat "$DATA_DIR/alive-web.txt" | nuclei -silent -o "$DATA_DIR/nuclei.txt"
echo "[+] nuclei done."

echo "[*] Running dalfox..."
cat "$DATA_DIR/all-urls.txt" | dalfox pipe --skip-bav -o "$DATA_DIR/dalfox.txt"
echo "[+] dalfox done."

echo "[*] Running kxss..."
cat "$DATA_DIR/all-urls.txt" | kxss > "$DATA_DIR/kxss.txt"
echo "[+] kxss done."

# 7. Screenshots (Aquatone)
echo "[*] Taking screenshots with Aquatone..."
cat "$DATA_DIR/alive-web.txt" | awk '{print $1}' | aquatone -out "$REPORT_DIR/aquatone"
echo "[+] Aquatone screenshots saved."

# 8. Tool Versions
echo "[*] Collecting tool versions..."
VERSIONS=$(cat <<EOV
amass: $(amass -version 2>&1 | head -1)
subfinder: $(subfinder -version 2>&1 | head -1)
assetfinder: $(assetfinder --version 2>&1 | head -1)
findomain: $(findomain --version 2>&1 | head -1)
dnsx: $(dnsx -version 2>&1 | head -1)
httpx: $(httpx -version 2>&1 | head -1)
waybackurls: $(waybackurls -version 2>&1 | head -1)
gau: $(gau --version 2>&1 | head -1)
nuclei: $(nuclei -version 2>&1 | head -1)
dalfox: $(dalfox -v 2>&1 | head -1)
kxss: $(kxss -version 2>&1 | head -1)
EOV
)

# 9. Stats
SUBS=$(wc -l < "$DATA_DIR/all-subs.txt")
ALIVE=$(wc -l < "$DATA_DIR/alive.txt")
ALIVE_WEB=$(wc -l < "$DATA_DIR/alive-web.txt")
URLS=$(wc -l < "$DATA_DIR/all-urls.txt")
NEW_SUBS=0
if [ -f "$DATA_DIR/prev-subs.txt" ]; then
    NEW_SUBS=$(grep -vxFf "$DATA_DIR/prev-subs.txt" "$DATA_DIR/all-subs.txt" | wc -l)
else
    cp "$DATA_DIR/all-subs.txt" "$DATA_DIR/prev-subs.txt"
fi

# 10. Screenshots for JS
SCREENSHOTS=""
for shot in "$SCREENSHOTS_DIR"/*.png; do
    [ -e "$shot" ] || continue
    fname=$(basename "$shot")
    SCREENSHOTS="${SCREENSHOTS}{file: \"../aquatone/screenshots/$fname\", label: \"$fname\"},"
done
SCREENSHOTS="[${SCREENSHOTS%,}]"

# 11. Write JS Data File
echo "[*] Generating report-data.js for HTML report..."
cat > "$JS_DIR/report-data.js" <<EOF
window.reportData = {
  domain: "$DOMAIN",
  toolVersions: \`$VERSIONS\`,
  stats: {
    subdomains: $SUBS,
    alive: $ALIVE,
    aliveWeb: $ALIVE_WEB,
    urls: $URLS,
    newSubs: $NEW_SUBS
  },
  newSubdomains: \`$(if [ -f "$DATA_DIR/prev-subs.txt" ]; then grep -vxFf "$DATA_DIR/prev-subs.txt" "$DATA_DIR/all-subs.txt"; else cat "$DATA_DIR/all-subs.txt"; fi)\`,
  endpoints: \`$(head -30 "$DATA_DIR/all-urls.txt")\`,
  parameters: \`$(head -30 "$DATA_DIR/params.txt")\`,
  vulnerabilities: {
    nuclei: \`$(cat "$DATA_DIR/nuclei.txt" 2>/dev/null | head -30)\`,
    dalfox: \`$(cat "$DATA_DIR/dalfox.txt" 2>/dev/null | head -30)\`,
    kxss: \`$(cat "$DATA_DIR/kxss.txt" 2>/dev/null | head -30)\`
  },
  screenshots: $SCREENSHOTS
};
EOF
echo "[+] report-data.js generated."

cp "$DATA_DIR/all-subs.txt" "$DATA_DIR/prev-subs.txt"

echo
echo "=== Recon Complete! ==="
echo "Open $REPORT_DIR/index.html in your browser to view the report."
