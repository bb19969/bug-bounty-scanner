#!/bin/bash
set -e

# --- SECTION FLAGS ---
RUN_SUBDOMAINS=false
RUN_PROBES=false
RUN_URLS=false
RUN_GF=false
RUN_PARAMS=false
RUN_VULNSCAN=false
RUN_SCREENSHOTS=false
RUN_REPORT=false
ANY_SECTION=false

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- HELP ---
show_help() {
  echo "Usage: $0 [flags] -d <domain>"
  echo "Section flags:"
  echo "  --full               Run all sections (same as default)"
  echo "  --subdomains         Run subdomain enumeration"
  echo "  --probes             Run DNS/HTTP probing"
  echo "  --urls               Run URL collection"
  echo "  --gf                 Run gf patterns on collected URLs"
  echo "  --params             Run parameter discovery"
  echo "  --vulnscan           Run vulnerability scanning"
  echo "  --screenshots        Run screenshots"
  echo "  --report             Generate report"
  echo "General:"
  echo "  -d, --domain DOMAIN  Target domain"
  echo "  --no-color           Disable colored output"
  echo "  --help               Show this message"
  echo
  echo "If no section flag is provided, all sections run."
}

# --- ARGUMENT PARSING ---
DOMAIN=""
NO_COLOR=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)
      RUN_SUBDOMAINS=true
      RUN_PROBES=true
      RUN_URLS=true
      RUN_GF=true
      RUN_PARAMS=true
      RUN_VULNSCAN=true
      RUN_SCREENSHOTS=true
      RUN_REPORT=true
      ANY_SECTION=true
      shift
      ;;
    --subdomains) RUN_SUBDOMAINS=true; ANY_SECTION=true; shift ;;
    --probes) RUN_PROBES=true; ANY_SECTION=true; shift ;;
    --urls) RUN_URLS=true; ANY_SECTION=true; shift ;;
    --gf) RUN_GF=true; ANY_SECTION=true; shift ;;
    --params) RUN_PARAMS=true; ANY_SECTION=true; shift ;;
    --vulnscan) RUN_VULNSCAN=true; ANY_SECTION=true; shift ;;
    --screenshots) RUN_SCREENSHOTS=true; ANY_SECTION=true; shift ;;
    --report) RUN_REPORT=true; ANY_SECTION=true; shift ;;
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    --no-color) NO_COLOR=true; shift ;;
    --help) show_help; exit 0 ;;
    *) echo "Unknown flag: $1"; show_help; exit 1 ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  show_help
  exit 1
fi

if [ "$NO_COLOR" = true ]; then
  RED=""; GREEN=""; CYAN=""; YELLOW=""; NC=""
fi

# If no section flag specified, run all
if ! $ANY_SECTION; then
  RUN_SUBDOMAINS=true
  RUN_PROBES=true
  RUN_URLS=true
  RUN_GF=true
  RUN_PARAMS=true
  RUN_VULNSCAN=true
  RUN_SCREENSHOTS=true
  RUN_REPORT=true
fi

# --- DIRS ---
DATA_DIR="data"
REPORT_DIR="report"
JS_DIR="$REPORT_DIR/js"
SCREENSHOTS_DIR="$REPORT_DIR/aquatone/screenshots"
mkdir -p "$DATA_DIR" "$JS_DIR" "$SCREENSHOTS_DIR"

echo -e "${CYAN}=== Recon Script ===${NC}"
echo -e "${CYAN}Target: $DOMAIN${NC}"
echo

# --- 1. SUBDOMAIN ENUMERATION ---
if $RUN_SUBDOMAINS; then
  echo -e "${CYAN}[*] Subdomain enumeration...${NC}"
  amass enum -passive -d "$DOMAIN" -o "$DATA_DIR/amass.txt" > /dev/null 2>&1
  echo -e "${GREEN}[+] Amass done.${NC}"
  subfinder -d "$DOMAIN" -o "$DATA_DIR/subfinder.txt" > /dev/null 2>&1
  echo -e "${GREEN}[+] Subfinder done.${NC}"
  assetfinder --subs-only "$DOMAIN" > "$DATA_DIR/assetfinder.txt" 2> /dev/null
  echo -e "${GREEN}[+] Assetfinder done.${NC}"
  findomain -t "$DOMAIN" -u "$DATA_DIR/findomain.txt" > /dev/null 2>&1
  echo -e "${GREEN}[+] Findomain done.${NC}"
  cat "$DATA_DIR/"*.txt | sort -u > "$DATA_DIR/all-subs.txt"
  echo -e "${YELLOW}[#] Unique subdomains: $(wc -l < "$DATA_DIR/all-subs.txt")${NC}"
  echo
fi

# --- 2. PROBING ---
if $RUN_PROBES; then
  echo -e "${CYAN}[*] DNS/HTTP probing...${NC}"
  if [ ! -f "$DATA_DIR/all-subs.txt" ]; then
    echo -e "${RED}[!] No subdomains file found. Run --subdomains first.${NC}"
    exit 1
  fi
  cat "$DATA_DIR/all-subs.txt" | dnsx -silent -a -resp-only > "$DATA_DIR/alive.txt" 2> /dev/null
  echo -e "${GREEN}[+] dnsx done: $DATA_DIR/alive.txt ($(wc -l < "$DATA_DIR/alive.txt"))${NC}"
  cat "$DATA_DIR/alive.txt" | httpx -silent -status-code -title -tech-detect -threads 50 > "$DATA_DIR/alive-web.txt" 2> /dev/null
  echo -e "${GREEN}[+] httpx done: $DATA_DIR/alive-web.txt ($(wc -l < "$DATA_DIR/alive-web.txt"))${NC}"
  echo
fi

# --- 3. URL COLLECTION ---
if $RUN_URLS; then
  echo -e "${CYAN}[*] URL collection...${NC}"
  if [ ! -f "$DATA_DIR/all-subs.txt" ]; then
    echo -e "${RED}[!] No subdomains file found. Run --subdomains first.${NC}"
    exit 1
  fi
  cat "$DATA_DIR/all-subs.txt" | waybackurls > "$DATA_DIR/waybackurls.txt" 2> /dev/null
  echo -e "${GREEN}[+] waybackurls done.${NC}"
  cat "$DATA_DIR/all-subs.txt" | gau > "$DATA_DIR/gau.txt" 2> /dev/null
  echo -e "${GREEN}[+] gau done.${NC}"
  cat "$DATA_DIR/waybackurls.txt" "$DATA_DIR/gau.txt" | sort -u > "$DATA_DIR/all-urls.txt"
  echo -e "${YELLOW}[#] Unique URLs: $(wc -l < "$DATA_DIR/all-urls.txt")${NC}"
  echo
fi

# --- 4. GF PATTERNS ---
if $RUN_GF; then
  echo -e "${CYAN}[*] Running gf patterns...${NC}"
  if [ ! -f "$DATA_DIR/all-urls.txt" ]; then
    echo -e "${RED}[!] No URLs file found. Run --urls first.${NC}"
    exit 1
  fi
  declare -a patterns=(xss sqli redirect lfi ssti ssrf rce idor)
  for pattern in "${patterns[@]}"; do
    if command -v gf >/dev/null 2>&1; then
      gf "$pattern" "$DATA_DIR/all-urls.txt" > "$DATA_DIR/gf-$pattern.txt" 2>/dev/null
      echo -e "${GREEN}[+] gf $pattern: ${YELLOW}$(wc -l < "$DATA_DIR/gf-$pattern.txt") hits${NC}"
    else
      echo -e "${YELLOW}[!] gf not found in PATH, skipping...${NC}"
      break
    fi
  done
  echo
fi

# --- 5. PARAMETER DISCOVERY ---
if $RUN_PARAMS; then
  echo -e "${CYAN}[*] Parameter discovery...${NC}"
  if [ ! -f "$DATA_DIR/all-urls.txt" ]; then
    echo -e "${RED}[!] No URLs file found. Run --urls first.${NC}"
    exit 1
  fi
  grep -oP '\?\K[^=]+' "$DATA_DIR/all-urls.txt" | sort -u > "$DATA_DIR/params.txt"
  echo -e "${YELLOW}[#] Unique parameters: $(wc -l < "$DATA_DIR/params.txt")${NC}"
  echo
fi

# --- 6. VULNERABILITY SCANNING ---
if $RUN_VULNSCAN; then
  echo -e "${CYAN}[*] Vulnerability scanning...${NC}"
  if [ ! -f "$DATA_DIR/alive-web.txt" ]; then
    echo -e "${RED}[!] No alive web hosts found. Run --probes first.${NC}"
    exit 1
  fi
  cat "$DATA_DIR/alive-web.txt" | nuclei -silent -o "$DATA_DIR/nuclei.txt" > /dev/null 2>&1
  echo -e "${GREEN}[+] nuclei done.${NC}"
  if [ ! -f "$DATA_DIR/all-urls.txt" ]; then
    echo -e "${RED}[!] No URLs file found. Run --urls first.${NC}"
    exit 1
  fi
  cat "$DATA_DIR/all-urls.txt" | dalfox pipe --skip-bav -o "$DATA_DIR/dalfox.txt" > /dev/null 2>&1
  echo -e "${GREEN}[+] dalfox done.${NC}"
  cat "$DATA_DIR/all-urls.txt" | kxss > "$DATA_DIR/kxss.txt" 2> /dev/null
  echo -e "${GREEN}[+] kxss done.${NC}"
  echo
fi

# --- 7. SCREENSHOTS ---
if $RUN_SCREENSHOTS; then
  echo -e "${CYAN}[*] Screenshotting...${NC}"
  if [ ! -f "$DATA_DIR/alive-web.txt" ]; then
    echo -e "${RED}[!] No alive web hosts found. Run --probes first.${NC}"
    exit 1
  fi
  cat "$DATA_DIR/alive-web.txt" | awk '{print $1}' | aquatone -out "$REPORT_DIR/aquatone" > /dev/null 2>&1
  echo -e "${GREEN}[+] Aquatone screenshots saved.${NC}"
  echo
fi

# --- 8. REPORT GENERATION ---
if $RUN_REPORT; then
  echo -e "${CYAN}[*] Generating report...${NC}"

  # Tool versions
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
aquatone: $(aquatone --version 2>&1 | head -1)
gf: $(if command -v gf >/dev/null 2>&1; then gf -h 2>&1 | head -1; else echo "not found"; fi)
EOV
)

  SUBS=$(wc -l < "$DATA_DIR/all-subs.txt" 2>/dev/null || echo 0)
  ALIVE=$(wc -l < "$DATA_DIR/alive.txt" 2>/dev/null || echo 0)
  ALIVE_WEB=$(wc -l < "$DATA_DIR/alive-web.txt" 2>/dev/null || echo 0)
  URLS=$(wc -l < "$DATA_DIR/all-urls.txt" 2>/dev/null || echo 0)
  PARAMS=$(wc -l < "$DATA_DIR/params.txt" 2>/dev/null || echo 0)
  NEW_SUBS=0
  if [ -f "$DATA_DIR/prev-subs.txt" ]; then
    NEW_SUBS=$(grep -vxFf "$DATA_DIR/prev-subs.txt" "$DATA_DIR/all-subs.txt" | wc -l)
  else
    cp "$DATA_DIR/all-subs.txt" "$DATA_DIR/prev-subs.txt"
  fi

  # Screenshots for JS
  SCREENSHOTS=""
  for shot in "$SCREENSHOTS_DIR"/*.png; do
    [ -e "$shot" ] || continue
    fname=$(basename "$shot")
    SCREENSHOTS="${SCREENSHOTS}{file: \"../aquatone/screenshots/$fname\", label: \"$fname\"},"
  done
  SCREENSHOTS="[${SCREENSHOTS%,}]"

  cat > "$JS_DIR/report-data.js" <<EOF
window.reportData = {
  domain: "$DOMAIN",
  toolVersions: \`$VERSIONS\`,
  stats: {
    subdomains: $SUBS,
    alive: $ALIVE,
    aliveWeb: $ALIVE_WEB,
    urls: $URLS,
    params: $PARAMS,
    newSubs: $NEW_SUBS
  },
  newSubdomains: \`$(if [ -f "$DATA_DIR/prev-subs.txt" ]; then grep -vxFf "$DATA_DIR/prev-subs.txt" "$DATA_DIR/all-subs.txt"; else cat "$DATA_DIR/all-subs.txt"; fi)\`,
  endpoints: \`$(head -30 "$DATA_DIR/all-urls.txt" 2>/dev/null)\`,
  parameters: \`$(head -30 "$DATA_DIR/params.txt" 2>/dev/null)\`,
  vulnerabilities: {
    nuclei: \`$(cat "$DATA_DIR/nuclei.txt" 2>/dev/null | head -30)\`,
    dalfox: \`$(cat "$DATA_DIR/dalfox.txt" 2>/dev/null | head -30)\`,
    kxss: \`$(cat "$DATA_DIR/kxss.txt" 2>/dev/null | head -30)\`
  },
  gf: {
    xss: \`$(cat "$DATA_DIR/gf-xss.txt" 2>/dev/null | head -20)\`,
    sqli: \`$(cat "$DATA_DIR/gf-sqli.txt" 2>/dev/null | head -20)\`,
    redirect: \`$(cat "$DATA_DIR/gf-redirect.txt" 2>/dev/null | head -20)\`,
    lfi: \`$(cat "$DATA_DIR/gf-lfi.txt" 2>/dev/null | head -20)\`,
    ssti: \`$(cat "$DATA_DIR/gf-ssti.txt" 2>/dev/null | head -20)\`,
    ssrf: \`$(cat "$DATA_DIR/gf-ssrf.txt" 2>/dev/null | head -20)\`,
    rce: \`$(cat "$DATA_DIR/gf-rce.txt" 2>/dev/null | head -20)\`,
    idor: \`$(cat "$DATA_DIR/gf-idor.txt" 2>/dev/null | head -20)\`
  },
  screenshots: $SCREENSHOTS
};
EOF

  cp "$DATA_DIR/all-subs.txt" "$DATA_DIR/prev-subs.txt"

  echo -e "${GREEN}[+] report-data.js generated.${NC}"
  echo -e "${CYAN}Open $REPORT_DIR/index.html in your browser to view the report.${NC}"
  echo
fi

echo -e "${GREEN}=== Recon Complete ===${NC}"
