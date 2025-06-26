#!/bin/bash
# Recon script - runs tools, parses results, builds HTML report
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

# 1. Passive Subdomain Enumeration
amass enum -passive -d "$DOMAIN" -o "$DATA_DIR/amass.txt"
subfinder -d "$DOMAIN" -o "$DATA_DIR/subfinder.txt"
assetfinder --subs-only "$DOMAIN" > "$DATA_DIR/assetfinder.txt"
findomain -t "$DOMAIN" -u "$DATA_DIR/findomain.txt"

# 2. Merge and deduplicate subdomains
cat "$DATA_DIR/"*.txt | sort -u > "$DATA_DIR/all-subs.txt"

# 3. Probe for alive hosts
cat "$DATA_DIR/all-subs.txt" | dnsx -silent -a -resp-only > "$DATA_DIR/alive.txt"
cat "$DATA_DIR/alive.txt" | httpx -silent -status-code -title -tech-detect -threads 50 > "$DATA_DIR/alive-web.txt"

# 4. URL collection
cat "$DATA_DIR/all-subs.txt" | waybackurls > "$DATA_DIR/waybackurls.txt"
cat "$DATA_DIR/all-subs.txt" | gau > "$DATA_DIR/gau.txt"
cat "$DATA_DIR/waybackurls.txt" "$DATA_DIR/gau.txt" | sort -u > "$DATA_DIR/all-urls.txt"

# 5. Parameter discovery
grep -oP '\?\K[^=]+' "$DATA_DIR/all-urls.txt" | sort -u > "$DATA_DIR/params.txt"

# 6. Vulnerability scans
cat "$DATA_DIR/alive-web.txt" | nuclei -silent -o "$DATA_DIR/nuclei.txt"
cat "$DATA_DIR/all-urls.txt" | dalfox pipe --skip-bav -o "$DATA_DIR/dalfox.txt"
cat "$DATA_DIR/all-urls.txt" | kxss > "$DATA_DIR/kxss.txt"

# 7. Screenshots (Aquatone)
cat "$DATA_DIR/alive-web.txt" | awk '{print $1}' | aquatone -out "$REPORT_DIR/aquatone"

# 8. Get tool versions
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
NEW_SUBS=$(grep -vxFf "$DATA_DIR/prev-subs.txt" "$DATA_DIR/all-subs.txt" | wc -l 2>/dev/null || echo "$SUBS")

# 10. Prepare screenshots list for JS
SCREENSHOTS=""
for shot in "$SCREENSHOTS_DIR"/*.png; do
    [ -e "$shot" ] || continue
    fname=$(basename "$shot")
    SCREENSHOTS="${SCREENSHOTS}{file: \"../aquatone/screenshots/$fname\", label: \"$fname\"},"
done
SCREENSHOTS="[${SCREENSHOTS%,}]"

# 11. Build report-data.js
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
  newSubdomains: \`$(grep -vxFf "$DATA_DIR/prev-subs.txt" "$DATA_DIR/all-subs.txt" 2>/dev/null || cat "$DATA_DIR/all-subs.txt")\`,
  endpoints: \`$(head -20 "$DATA_DIR/all-urls.txt")\`,
  parameters: \`$(head -20 "$DATA_DIR/params.txt")\`,
  vulnerabilities: {
    nuclei: \`$(cat "$DATA_DIR/nuclei.txt" 2>/dev/null | head -20)\`,
    dalfox: \`$(cat "$DATA_DIR/dalfox.txt" 2>/dev/null | head -20)\`,
    kxss: \`$(cat "$DATA_DIR/kxss.txt" 2>/dev/null | head -20)\`
  },
  screenshots: $SCREENSHOTS
};
EOF

cp "$DATA_DIR/all-subs.txt" "$DATA_DIR/prev-subs.txt"

echo "Recon complete. Open $REPORT_DIR/index.html in your browser!"
