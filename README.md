# Recon Bug Bounty Scanner

A powerful, modular, and scriptable automation tool for bug bounty reconnaissance, asset discovery, and vulnerability scanning. Recon Live Stats combines the best open-source recon tools with live stats, flexible presets, and detailed reporting—making it easier than ever to scale your bug bounty or penetration testing workflow.

---

## ✨ Features

- **Automated Subdomain Enumeration**
- **Alive Host Probing**
- **URL Collection (Waybackurls, GAU)**
- **Vulnerability Scanning (Nuclei, Dalfox, KXSS, GF patterns, CVE detection)**
- **JavaScript Recon (LinkFinder, SecretFinder, custom grep)**
- **Screenshot Capture (Aquatone)**
- **Flexible Preset System for Custom Scans**
- **Live Progress & Stats using [rich](https://github.com/Textualize/rich)**
- **Modular, Extensible, and Easy to Integrate**

---

## 🚀 Installation

Clone this repository and run the installer script to set up all dependencies:

```bash
git clone https://github.com/YOUR-USERNAME/recon-live-stats.git
cd recon-live-stats
chmod +x install_tools.sh
./install_tools.sh
```

Recon install 
```
git clone https://github.com/bb19969/bug-bounty-scanner
cd bug-boungty-scanner
chmod +x recon.py
```
> **Note:** The installer will set up all required Go, Rust, and Python tools, as well as necessary system dependencies.

---

## ⚡️ Quick Start

```bash
python3 recon_live_stats.py -d example.com
```

This will run the **full recon pipeline** against `example.com` and output data and reports to the `output/` directory.

---

## 🛠️ Usage & Options

```bash
python3 recon.py -d <domain> [OPTIONS]
```

**Options:**

| Flag                | Description                                          |
|---------------------|------------------------------------------------------|
| `-d`, `--domain`    | **(Required)** Target domain to scan                 |
| `-o`, `--output`    | Output directory (default: `output/`)                |
| `--verbose`         | Verbose output/logging                               |
| `--log`             | Log to file                                          |
| `--dry-run`         | Show what would run, but **don’t** execute           |
| `--no-wayback`      | Skip Waybackurls URL collection                      |
| `--no-gau`          | Skip GAU URL collection                              |
| `--no-gf`           | Skip GF patterns matching                            |
| `--no-nuclei`       | Skip Nuclei scan                                     |
| `--no-dalfox`       | Skip Dalfox scan                                     |
| `--no-kxss`         | Skip KXSS scan                                       |
| `--no-screenshots`  | Skip screenshot capture                              |
| `--no-js`           | Skip JavaScript recon                                |
| `--cve-scan`        | Run Nuclei with CVE templates for CVE detection      |
| `--preset <name>`   | Use a saved preset (see below)                       |
| `--save-preset`     | Save the current flag list as a named preset         |
| `--flags "<flags>"` | Flags string to save for the preset                  |

---

## 🏷️ Presets

You can save and reuse your favorite scan combinations with **presets**:

**Save a preset:**
```bash
python3 recon.py --save-preset js-cve-nuclei --flags "--no-wayback --no-gau --no-gf --no-dalfox --no-kxss --no-screenshots --cve-scan"
```

**Use a preset:**
```bash
python3 recon.py -d example.com --preset js-cve-nuclei
```

---

## 📝 Example Workflows

**Full recon:**
```bash
python3 recon.py -d example.com
```

**Fast scan (skip screenshots, JS, Dalfox, KXSS):**
```bash
python3 recon -d example.com --no-screenshots --no-js --no-dalfox --no-kxss
```

**Custom CVE & JS only:**
```bash
python3 recon -d example.com --no-wayback --no-gau --no-gf --no-dalfox --no-kxss --no-screenshots --cve-scan
```

---

## 📂 Output

- All data is organized in the `output/` directory (or as specified with `-o`).
- HTML and raw results are in `output/report/` and `output/data/`.

---

## 🐞 Troubleshooting

- Ensure all dependencies are installed with `./install_tools.sh`
- For missing tools or errors, check the logs or re-run with `--verbose`.

---

## 📚 Credits

- [subfinder](https://github.com/projectdiscovery/subfinder)
- [assetfinder](https://github.com/tomnomnom/assetfinder)
- [findomain](https://github.com/findomain/findomain)
- [dnsx](https://github.com/projectdiscovery/dnsx)
- [httpx](https://github.com/projectdiscovery/httpx)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [gau](https://github.com/lc/gau)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [dalfox](https://github.com/hahwul/dalfox)
- [kxss](https://github.com/Emoe/kxss)
- [aquatone](https://github.com/michenriksen/aquatone)
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
- [SecretFinder](https://github.com/m4ll0k/SecretFinder)
- [rich](https://github.com/Textualize/rich)

---

## 🖥️ Main Repository Description

> **Recon Live Stats**: Modular, scriptable automation for bug bounty recon and scanning. Subdomain discovery, alive host probing, URL collection, Nuclei/Dalfox/CVE/JS/other scans, screenshots, live stats, and customizable presets—all in one tool.

---

## 📄 License

This project is licensed under the MIT License.
