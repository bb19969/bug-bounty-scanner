**bug bounty scanner** is a modern, modular automation framework for bug bounty reconnaissance and penetration testing. It orchestrates top open-source recon tools into a single workflow—handling subdomain discovery, asset probing, URL collection, vulnerability scanning (Nuclei, Dalfox, GF patterns, KXSS, CVE checks), JavaScript analysis, screenshots, and more—while providing live stats and rich reporting.

- Customizable with flexible presets and command-line flags
- Live progress and statistics with a beautiful terminal UI (powered by [rich](https://github.com/Textualize/rich))
- Output organized for easy triage and reporting

**Ideal for bug bounty hunters, pentesters, and anyone who needs scalable, scriptable recon.**

---

**Quick Example:**

```bash
python3 recon_live_stats.py -d example.com
```

**Save and use custom scan presets:**

```bash
python3 recon_live_stats.py --save-preset fast-scan --flags "--no-screenshots --no-js --no-dalfox --no-kxss"
python3 recon_live_stats.py -d example.com --preset fast-scan
```

---

Automate more, hunt smarter.
