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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=== Recon Report Automation ===${NC}"
echo -e "${CYAN}Target: $DOMAIN${NC}"
echo

# 1. Subdomain Enumeration
echo -e "${CYAN}[*] Running Amass (subdomain enumeration)...${NC}"
amass enum -passive -d "$DOMAIN" -o "$DATA_DIR/amass.txt" > /dev/null 2>&1
echo -e "${GREEN}[+] Amass done.${NC}"

echo -e "${CYAN}[*] Running Subfinder (subdomain enumeration)...${NC}"
subfinder -d "$DOMAIN" -o "$DATA_DIR/subfinder.txt" > /dev/null 2>&1
echo -e "${GREEN}[+] Subfinder done.${NC}"

echo -e "${CYAN}[*] Running Assetfinder (subdomain enumeration)...${NC}"
assetfinder --subs-only "$DOMAIN" > "$DATA_DIR/assetfinder.txt" 2> /dev/null
echo -e "${GREEN}[+] Assetfinder done.${NC}"

echo -e "${CYAN}[*] Running Findomain (subdomain enumeration)...${NC}"
findomain -t "$DOMAIN" -u "$DATA_DIR/findomain.txt" > /dev/null 2>&1
echo -e "${GREEN}[+] Findomain done.${NC}"

# 2. Merge and Deduplicate Subdomains
echo -e "${CYAN}[*] Merging and deduplicating subdomains...${NC}"
cat "$DATA_DIR/"*.txt | sort -u > "$DATA_DIR/all-subs.txt"
echo -e "${GREEN}[+] Subdomain list created: $DATA_DIR/all-subs.txt ($(wc -l < "$DATA_DIR/all-subs.txt") lines)${NC}"

# 3. Probe for Alive Hosts
echo -e "${CYAN}[*] Running dnsx (alive DNS hosts)...${NC}"
cat "$DATA_DIR/all-subs.txt" | dnsx -silent -a -resp-only > "$DATA_DIR/alive.txt" 2> /dev/null
echo -e "${GREEN}[+] dnsx done: $DATA_DIR/alive.txt ($(wc -l < "$DATA_DIR/alive.txt") lines)${NC}"

echo -e "${CYAN}[*] Running httpx (alive HTTP/S hosts)...${NC}"
cat "$DATA_DIR/alive.txt" | httpx -silent -status-code -title -tech-detect -threads 50 > "$DATA_DIR/alive-web.txt" 2> /dev/null
echo -e "${GREEN}[+] httpx done: $DATA_DIR/alive-web.txt ($(wc -l < "$DATA_DIR/alive-web.txt") lines)${NC}"

# 4. URL collection
echo -e "${CYAN}[*] Running waybackurls (historical URLs)...${NC}"
cat "$DATA_DIR/all-subs.txt" | waybackurls > "$DATA_DIR/waybackurls.txt" 2> /dev/null
echo -e "${GREEN}[+] waybackurls done.${NC}"

echo -e "${CYAN}[*] Running gau (GetAllUrls)...${NC}"
cat "$DATA_DIR/all-subs.txt" | gau > "$DATA_DIR/gau.txt" 2> /dev/null
echo -e "${GREEN}[+] gau done.${NC}"

echo -e "${CYAN}[*] Merging and deduplicating URLs...${NC}"
cat "$DATA_DIR/waybackurls.txt" "$DATA_DIR/gau.txt" | sort -u > "$DATA_DIR/all-urls.txt"
echo -e "${GREEN}[+] URL list created: $DATA_DIR/all-urls.txt ($(wc -l < "$DATA_DIR/all-urls.txt") lines)${NC}"

# 5. Parameter discovery
echo -e "${CYAN}[*] Extracting parameters from URLs...${NC}"
grep -oP '\?\K[^=]+' "$DATA_DIR/all-urls.txt" | sort -u > "$DATA_DIR/params.txt"
echo -e "${GREEN}[+] Parameters extracted: $DATA_DIR/params.txt ($(wc -l < "$DATA_DIR/params.txt") lines)${NC}"

# 6. Vulnerability scans
echo -e "${CYAN}[*] Running nuclei (vulnerability scanning)...${NC}"
cat "$DATA_DIR/alive-web.txt" | nuclei -silent -o "$DATA_DIR/nuclei.txt" > /dev/null 2>&1
echo -e "${GREEN}[+] nuclei done.${NC}"

echo -e "${CYAN}[*] Running dalfox (XSS scanning)...${NC}"
cat "$DATA_DIR/all-urls.txt" | dalfox pipe --skip-bav -o "$DATA_DIR/dalfox.txt" > /dev/null 2>&1
echo -e "${GREEN}[+] dalfox done.${NC}"

echo -e "${CYAN}[*] Running kxss (reflected parameter detection)...${NC}"
cat "$DATA_DIR/all-urls.txt" | kxss > "$DATA_DIR/kxss.txt" 2> /dev/null
echo -e "${GREEN}[+] kxss done.${NC}"

# 7. Screenshots (Aquatone)
echo -e "${CYAN}[*] Running Aquatone (screenshots)...${NC}"
cat "$DATA_DIR/alive-web.txt" | awk '{print $1}' | aquatone -out "$REPORT_DIR/aquatone" > /dev/null 2>&1
echo -e "${GREEN}[+] Aquatone screenshots saved.${NC}"

# 8. Tool Versions
echo -e "${CYAN}[*] Collecting tool versions...${NC}"
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
echo -e "${CYAN}[*] Generating report-data.js for HTML report...${NC}"
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
echo -e "${GREEN}[+] report-data.js generated.${NC}"

cp "$DATA_DIR/all-subs.txt" "$DATA_DIR/prev-subs.txt"

echo
echo -e "${GREEN}=== Recon Complete! ===${NC}"
echo -e "${CYAN}Open $REPORT_DIR/index.html in your browser to view the report.${NC}"
