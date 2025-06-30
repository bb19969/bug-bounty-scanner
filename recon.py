import argparse
import logging
import os
import sys
import shutil
import subprocess
import re
import time
import json
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn
from rich.panel import Panel

REQUIRED_TOOLS = [
    "subfinder", "assetfinder", "findomain", "dnsx", "httpx",
    "waybackurls", "gau", "nuclei", "dalfox", "kxss", "aquatone", "curl",
    "python3"
]

console = Console()
PRESET_FILE = os.path.expanduser("~/.recon_presets.json")

def load_presets():
    if os.path.exists(PRESET_FILE):
        with open(PRESET_FILE) as f:
            return json.load(f)
    return {}

def save_preset(name, flags):
    presets = load_presets()
    presets[name] = flags
    with open(PRESET_FILE, "w") as f:
        json.dump(presets, f, indent=2)
    print(f"Preset '{name}' saved: {flags}")

def apply_preset(name):
    presets = load_presets()
    if name in presets:
        return presets[name].split()
    else:
        print(f"Preset '{name}' not found.")
        sys.exit(1)

def check_dependencies():
    missing = [tool for tool in REQUIRED_TOOLS if not shutil.which(tool)]
    if missing:
        console.print(f"[bold red]Missing required tools: {', '.join(missing)}[/bold red]")
        sys.exit(1)

def run_cmd(cmd, outfile=None, verbose=False, append=False, shell=False):
    logging.debug(f"Running command: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    if outfile:
        mode = "a" if append else "w"
        with open(outfile, mode) as out:
            subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT if verbose else subprocess.DEVNULL, shell=shell, check=True)
    else:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT if verbose else subprocess.DEVNULL, shell=shell, check=True)

def setup_logging(logfile=None, verbose=False):
    handlers = [logging.StreamHandler()]
    if logfile:
        handlers.append(logging.FileHandler(logfile))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers
    )

def make_output_dirs(output_dir):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    (Path(output_dir) / "data").mkdir(exist_ok=True)
    (Path(output_dir) / "report" / "js").mkdir(parents=True, exist_ok=True)
    (Path(output_dir) / "report" / "aquatone" / "screenshots").mkdir(parents=True, exist_ok=True)

def combine_unique(*files, outfile):
    all_lines = set()
    for f in files:
        fp = Path(f)
        if fp.exists():
            with open(fp) as fh:
                all_lines.update(line.strip() for line in fh if line.strip())
    with open(outfile, "w") as out:
        for line in sorted(all_lines):
            out.write(line + "\n")

def enumerate_subdomains(domain, output_dir, verbose, progress, stats):
    data_dir = Path(output_dir) / "data"
    all_subs_file = data_dir / "all-subs.txt"
    if all_subs_file.exists() and all_subs_file.stat().st_size > 0:
        logging.info(f"Skipping subdomain enumeration: {all_subs_file} already exists and is non-empty")
        with open(all_subs_file) as f:
            stats["subdomains"] = sum(1 for _ in f)
        return all_subs_file

    file_map = {
        "subfinder": data_dir / "subfinder.txt",
        "assetfinder": data_dir / "assetfinder.txt",
        "findomain": data_dir / "findomain.txt"
    }
    tools = [
        ("subfinder", ["subfinder", "-d", domain, "-o", str(file_map["subfinder"])]),
        ("assetfinder", ["assetfinder", "--subs-only", domain], file_map["assetfinder"]),
        ("findomain", ["findomain", "-t", domain, "-u", str(file_map["findomain"])])
    ]
    task = progress.add_task("[cyan]Subdomain tools", total=len(tools))
    for t in tools:
        tool_name = t[0]
        try:
            if len(t) == 3:
                run_cmd(t[1], outfile=str(t[2]), verbose=verbose)
            else:
                run_cmd(t[1], verbose=verbose)
            stats["subdomain_tools"] += 1
        except Exception as e:
            logging.error(f"{tool_name} failed: {e}")
        progress.update(task, advance=1)
    combine_unique(
        file_map["subfinder"],
        file_map["assetfinder"],
        file_map["findomain"],
        outfile=all_subs_file
    )
    if all_subs_file.exists():
        with open(all_subs_file) as f:
            stats["subdomains"] = sum(1 for _ in f)
    else:
        stats["subdomains"] = 0
    return all_subs_file

def probe_subdomains(all_subs_file, output_dir, verbose, progress, stats):
    data_dir = Path(output_dir) / "data"
    alive_file = data_dir / "alive.txt"
    if not Path(all_subs_file).exists():
        stats["probed"] = 0
        stats["alive_hosts"] = 0
        return alive_file
    with open(all_subs_file) as f:
        subdomains = [line.strip() for line in f if line.strip()]
    task = progress.add_task("[green]Probing subdomains", total=len(subdomains))
    batch_size = 1000
    alive_hosts = set()
    for i in range(0, len(subdomains), batch_size):
        batch = subdomains[i:i+batch_size]
        batch_file = data_dir / f"batch_{i}.txt"
        with open(batch_file, "w") as out:
            for sub in batch:
                out.write(sub + "\n")
        tmp_out = str(batch_file) + ".out"
        run_cmd(["httpx", "-l", str(batch_file), "-silent", "-o", tmp_out], verbose=verbose)
        if Path(tmp_out).exists():
            with open(tmp_out) as res:
                for line in res:
                    alive_hosts.add(line.strip())
        stats["probed"] += len(batch)
        progress.update(task, advance=len(batch))
        try:
            os.remove(batch_file)
            os.remove(tmp_out)
        except Exception:
            pass
    with open(alive_file, "w") as out:
        for h in sorted(alive_hosts):
            out.write(h + "\n")
    stats["alive_hosts"] = len(alive_hosts)
    return alive_file

def is_domain(host):
    return not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)

def collect_urls(alive_file, output_dir, verbose, progress, stats, no_wayback=False, no_gau=False):
    data_dir = Path(output_dir) / "data"
    wayback_file = data_dir / "waybackurls.txt"
    gau_file = data_dir / "gau.txt"
    urls_file = data_dir / "urls.txt"
    if not Path(alive_file).exists():
        stats["wayback"] = 0
        stats["gau"] = 0
        stats["urls"] = 0
        return urls_file, wayback_file, gau_file
    with open(alive_file) as f:
        hosts = [line.strip() for line in f if line.strip()]
    total_tasks = 0
    if not no_wayback:
        total_tasks += len(hosts)
    if not no_gau:
        total_tasks += len(hosts)
    task = progress.add_task("[yellow]Collecting URLs", total=total_tasks)
    for host in hosts:
        if host.startswith("http://") or host.startswith("https://"):
            domain = host.split("//", 1)[1]
        else:
            domain = host
        if not is_domain(domain):
            if not no_wayback:
                progress.update(task, advance=1)
            if not no_gau:
                progress.update(task, advance=1)
            continue
        if not no_wayback:
            try:
                run_cmd(["waybackurls", domain], outfile=wayback_file, verbose=verbose, append=True)
                stats["wayback"] += 1
            except Exception as e:
                logging.error(f"waybackurls failed for {domain}: {e}")
            progress.update(task, advance=1)
        if not no_gau:
            try:
                run_cmd(["gau", domain], outfile=gau_file, verbose=verbose, append=True)
                stats["gau"] += 1
            except Exception as e:
                logging.error(f"gau failed for {domain}: {e}")
            progress.update(task, advance=1)
        time.sleep(0.2)
    combine_files = []
    if not no_wayback:
        combine_files.append(wayback_file)
    if not no_gau:
        combine_files.append(gau_file)
    combine_unique(*combine_files, outfile=urls_file)
    if Path(urls_file).exists():
        with open(urls_file) as f:
            stats["urls"] = sum(1 for _ in f)
    else:
        stats["urls"] = 0
    return urls_file, wayback_file, gau_file

def run_gf_patterns(urls_file, output_dir, verbose, progress, stats, no_gf=False):
    if no_gf:
        return {}
    data_dir = Path(output_dir) / "data"
    patterns = {
        "xss": data_dir / "gf-xss.txt",
        "sqli": data_dir / "gf-sqli.txt",
        "lfi": data_dir / "gf-lfi.txt",
        "ssrf": data_dir / "gf-ssrf.txt"
    }
    task = progress.add_task("[magenta]GF Patterns", total=len(patterns))
    for pattern, outfile in patterns.items():
        cmd = f"gf {pattern} < {urls_file} > {outfile}"
        run_cmd(cmd, shell=True)
        stats[f"gf_{pattern}"] = sum(1 for _ in open(outfile)) if Path(outfile).exists() else 0
        progress.update(task, advance=1)
    return patterns

def extract_params(urls_file, output_dir, verbose, progress, stats):
    data_dir = Path(output_dir) / "data"
    params_file = data_dir / "params.txt"
    total = 0
    if Path(urls_file).exists():
        with open(urls_file) as f, open(params_file, "w") as out:
            for url in f:
                if "?" in url:
                    out.write(url)
                    total += 1
    stats["params"] = total
    progress.add_task("[cyan]Param extraction", total=1, completed=1)
    return params_file

def vuln_scan(alive_file, params_file, output_dir, verbose, progress, stats, run_nuclei=True, run_dalfox=True, chunk_size=100):
    data_dir = Path(output_dir) / "data"
    nuclei_out = data_dir / "nuclei.txt"
    dalfox_out = data_dir / "dalfox.txt"
    task_total = int(run_nuclei) + int(run_dalfox)
    if task_total == 0:
        return None, None
    task = progress.add_task("[red]Vuln Scans", total=task_total)
    if run_nuclei:
        chunk_dir = data_dir / "nuclei_chunks"
        chunk_dir.mkdir(exist_ok=True)
        chunk_files = []
        with open(alive_file) as f:
            hosts = [line.strip() for line in f if line.strip()]
        for i in range(0, len(hosts), chunk_size):
            chunk_path = chunk_dir / f"alive_{i}.txt"
            with open(chunk_path, "w") as cf:
                cf.write("\n".join(hosts[i:i+chunk_size]) + "\n")
            chunk_files.append(chunk_path)
        for chunk in chunk_files:
            chunk_output = chunk.with_suffix(".nuclei.txt")
            try:
                run_cmd(["nuclei", "-l", str(chunk), "-o", str(chunk_output)], verbose=verbose)
            except Exception as e:
                logging.error(f"Nuclei failed on chunk {chunk}: {e}")
        with open(nuclei_out, "w") as outf:
            for chunk in chunk_files:
                chunk_output = chunk.with_suffix(".nuclei.txt")
                if chunk_output.exists():
                    with open(chunk_output) as cf:
                        outf.write(cf.read())
        stats["nuclei"] = sum(1 for _ in open(nuclei_out)) if nuclei_out.exists() else 0
        progress.update(task, advance=1)
    if run_dalfox:
        run_cmd(["dalfox", "file", str(params_file), "--output", str(dalfox_out)], verbose=verbose)
        stats["dalfox"] = sum(1 for _ in open(dalfox_out)) if dalfox_out.exists() else 0
        progress.update(task, advance=1)
    return nuclei_out, dalfox_out

def cve_nuclei_scan(alive_file, output_dir, verbose, progress, stats):
    data_dir = Path(output_dir) / "data"
    cve_out = data_dir / "cve_nuclei.txt"
    if not Path(alive_file).exists() or Path(alive_file).stat().st_size == 0:
        stats["cve_nuclei"] = 0
        return cve_out
    task = progress.add_task("[red]Nuclei CVE Scan", total=1)
    try:
        run_cmd([
            "nuclei", "-l", str(alive_file),
            "-t", "cves/",
            "-o", str(cve_out),
            "--json"
        ], verbose=verbose)
    except Exception as e:
        logging.error(f"Nuclei CVE scan failed: {e}")
    stats["cve_nuclei"] = sum(1 for _ in open(cve_out)) if cve_out.exists() else 0
    progress.update(task, advance=1)
    return cve_out

def kxss_scan(params_file, output_dir, verbose, progress, stats):
    data_dir = Path(output_dir) / "data"
    kxss_out = data_dir / "kxss.txt"
    run_cmd(["kxss", "-l", str(params_file)], outfile=str(kxss_out), verbose=verbose)
    stats["kxss"] = sum(1 for _ in open(kxss_out)) if Path(kxss_out).exists() else 0
    progress.add_task("[yellow]KXSS", total=1, completed=1)
    return kxss_out

def screenshots(alive_file, output_dir, verbose, progress, stats):
    outdir = Path(output_dir) / "report" / "aquatone"
    aquatone_cmd = f"cat {alive_file} | aquatone -out {outdir}"
    subprocess.run(aquatone_cmd, shell=True, check=True)
    screenshots_path = outdir / "screenshots"
    shot_count = len(list(screenshots_path.glob("*"))) if screenshots_path.exists() else 0
    stats["screenshots"] = shot_count
    progress.add_task("[green]Screenshots", total=1, completed=1)
    return outdir

def js_recon(urls_file, output_dir, verbose, progress, stats):
    data_dir = Path(output_dir) / "data"
    js_urls_file = data_dir / "js-urls.txt"
    js_dir = data_dir / "jsfiles"
    js_dir.mkdir(exist_ok=True)
    linkfinder_out = data_dir / "js-linkfinder.txt"
    secretfinder_out = data_dir / "js-secretfinder.txt"
    customgrep_out = data_dir / "js-customgrep.txt"
    # 1. Extract JS URLs
    with open(urls_file) as f, open(js_urls_file, "w") as out:
        for url in f:
            if ".js" in url and url.strip().startswith("http"):
                out.write(url)
    # 2. Download JS files
    js_urls = []
    with open(js_urls_file) as f:
        for url in f:
            url = url.strip()
            if not url:
                continue
            js_urls.append(url)
    task = progress.add_task("[blue]Downloading JS", total=len(js_urls))
    js_files = []
    for url in js_urls:
        fname = url.split("?")[0].split("/")[-1]
        if not fname.endswith(".js"):
            fname += ".js"
        out_path = js_dir / fname
        try:
            run_cmd(["curl", "-sL", url, "-o", str(out_path)], verbose=verbose)
            if out_path.exists() and out_path.stat().st_size > 0:
                js_files.append(out_path)
        except Exception as e:
            logging.error(f"Failed to download JS {url}: {e}")
        progress.update(task, advance=1)
    stats["js_files"] = len(js_files)
    # 3. Advanced analysis (LinkFinder, SecretFinder, custom grep)
    # --- LinkFinder
    with open(linkfinder_out, "w") as lfout:
        for js_file in js_files:
            try:
                proc = subprocess.run(
                    ["python3", "LinkFinder/linkfinder.py", "-i", str(js_file), "-o", "cli", "--json"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
                )
                results = json.loads(proc.stdout.strip() or "{}")
                for endpoint in results.get("urls", []):
                    lfout.write(f"{js_file.name}: {endpoint}\n")
            except Exception as e:
                logging.error(f"LinkFinder failed for {js_file}: {e}")
    # --- SecretFinder
    with open(secretfinder_out, "w") as sfout:
        for js_file in js_files:
            try:
                proc = subprocess.run(
                    ["python3", "SecretFinder/SecretFinder.py", "-i", str(js_file), "-o", "cli"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
                )
                sfout.write(f"\n## {js_file.name}\n")
                sfout.write(proc.stdout)
            except Exception as e:
                logging.error(f"SecretFinder failed for {js_file}: {e}")
    # --- Custom grep for secrets and dangerous functions
    dangerous_patterns = [
        r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
        r"(?i)secret\s*[:=]\s*['\"][A-Za-z0-9_\-]{8,}['\"]",
        r"(?i)token\s*[:=]\s*['\"][A-Za-z0-9_\-]{8,}['\"]",
        r"eval\s*\(",
        r"document\.write\s*\(",
        r"window\.location",
        r"localStorage\s*\.",
        r"sessionStorage\s*\.",
        r"innerHTML\s*="
    ]
    import re as pyre
    with open(customgrep_out, "w") as cgout:
        for js_file in js_files:
            cgout.write(f"\n## {js_file.name}\n")
            try:
                with open(js_file) as f:
                    content = f.read()
                    for patt in dangerous_patterns:
                        for match in pyre.findall(patt, content):
                            cgout.write(f"Pattern: {patt} | Found: {match}\n")
            except Exception as e:
                logging.error(f"Custom grep failed for {js_file}: {e}")
    stats["js_linkfinder"] = sum(1 for _ in open(linkfinder_out)) if linkfinder_out.exists() else 0
    stats["js_secretfinder"] = sum(1 for _ in open(secretfinder_out)) if secretfinder_out.exists() else 0
    stats["js_customgrep"] = sum(1 for _ in open(customgrep_out)) if customgrep_out.exists() else 0
    return js_dir

def generate_report(output_dir):
    report_dir = Path(output_dir) / "report"
    html_report = report_dir / "index.html"
    data_dir = Path(output_dir) / "data"
    cve_out = data_dir / "cve_nuclei.txt"

    with open(html_report, "w") as f:
        f.write("<!DOCTYPE html><html><head><title>Recon Report</title></head><body>")
        f.write("<h1>Recon Report</h1>")
        f.write("<p>See data directory for detailed raw results.</p>")
        
        # Add CVE scan summary if exists
        if cve_out.exists() and cve_out.stat().st_size > 0:
            f.write("<h2>CVE Scan Results (Nuclei)</h2>")
            f.write("<pre>")
            with open(cve_out) as cvef:
                html_cve = cvef.read().replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                f.write(html_cve)
            f.write("</pre>")
        else:
            f.write("<h2>CVE Scan Results (Nuclei)</h2><p>No CVE matches found or scan not run.</p>")
        
        f.write("</body></html>")
    return html_report

def make_stats_panel(stats):
    return Panel(f"""
[cyan]Subdomain tools run:[/cyan] {stats['subdomain_tools']}
[cyan]Subdomains found:[/cyan] {stats['subdomains']}
[green]Hosts probed:[/green] {stats['probed']}
[green]Alive hosts:[/green] {stats['alive_hosts']}
[yellow]Wayback hits:[/yellow] {stats['wayback']}
[yellow]GAU hits:[/yellow] {stats['gau']}
[magenta]URLs collected:[/magenta] {stats['urls']}
[magenta]GF XSS:[/magenta] {stats['gf_xss']}  [magenta]GF SQLi:[/magenta] {stats['gf_sqli']}  [magenta]GF LFI:[/magenta] {stats['gf_lfi']}  [magenta]GF SSRF:[/magenta] {stats['gf_ssrf']}
[cyan]Params extracted:[/cyan] {stats['params']}
[red]Nuclei findings:[/red] {stats['nuclei']}
[red]Dalfox findings:[/red] {stats['dalfox']}
[yellow]KXSS findings:[/yellow] {stats['kxss']}
[blue]JS files:[/blue] {stats.get('js_files', 0)}
[blue]JS LinkFinder:[/blue] {stats.get('js_linkfinder', 0)}
[blue]JS SecretFinder:[/blue] {stats.get('js_secretfinder', 0)}
[blue]JS CustomGrep:[/blue] {stats.get('js_customgrep', 0)}
[red]CVE matches (Nuclei):[/red] {stats.get('cve_nuclei', 0)}
[green]Screenshots taken:[/green] {stats['screenshots']}
""", title="Live Recon Stats", expand=False)

def main():
    # --- Handle presets before argument parsing ---
    if "--save-preset" in sys.argv:
        i = sys.argv.index("--save-preset")
        try:
            preset_name = sys.argv[i+1]
            flags = []
            if "--flags" in sys.argv:
                j = sys.argv.index("--flags")
                flags = sys.argv[j+1]
            else:
                print("You must provide --flags flaglist for saving a preset.")
                sys.exit(1)
            save_preset(preset_name, flags)
            sys.exit(0)
        except IndexError:
            print("Usage: --save-preset <name> --flags \"<flags>\"")
            sys.exit(1)

    if "--preset" in sys.argv:
        i = sys.argv.index("--preset")
        try:
            preset_name = sys.argv[i+1]
            preset_flags = apply_preset(preset_name)
            # Remove --preset and its arg first
            del sys.argv[i:i+2]
            # Insert preset flags into sys.argv (after script name & domain)
            sys.argv = sys.argv[:1] + preset_flags + sys.argv[1:]
        except IndexError:
            print("Usage: --preset <name>")
            sys.exit(1)
    # --- End preset logic ---

    parser = argparse.ArgumentParser(description="Python Recon Framework with Live Stats (rich)")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("--log", help="Log file")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Show what would run, but don’t run")
    parser.add_argument("--no-wayback", action="store_true", help="Skip waybackurls")
    parser.add_argument("--no-gau", action="store_true", help="Skip gau")
    parser.add_argument("--no-gf", action="store_true", help="Skip gf patterns")
    parser.add_argument("--no-nuclei", action="store_true", help="Skip Nuclei scan")
    parser.add_argument("--no-dalfox", action="store_true", help="Skip Dalfox scan")
    parser.add_argument("--no-kxss", action="store_true", help="Skip KXSS scan")
    parser.add_argument("--no-screenshots", action="store_true", help="Skip screenshots")
    parser.add_argument("--no-js", action="store_true", help="Skip JavaScript recon")
    parser.add_argument("--cve-scan", action="store_true", help="Run CVE matching using nuclei CVE templates")
    parser.add_argument("--preset", help="Use a preset scan type (see ~/.recon_presets.json)")
    parser.add_argument("--save-preset", help="Save the current flag list as a named preset")
    parser.add_argument("--flags", help="Flags string to save for the preset")
    args = parser.parse_args()

    setup_logging(args.log, args.verbose)
    check_dependencies()
    make_output_dirs(args.output)

    if args.dry_run:
        console.print("[yellow]Dry run: would start all sections now.[/yellow]")
        sys.exit(0)

    stats = {
        "subdomain_tools": 0,
        "subdomains": 0,
        "probed": 0,
        "alive_hosts": 0,
        "wayback": 0,
        "gau": 0,
        "urls": 0,
        "gf_xss": 0,
        "gf_sqli": 0,
        "gf_lfi": 0,
        "gf_ssrf": 0,
        "params": 0,
        "nuclei": 0,
        "dalfox": 0,
        "kxss": 0,
        "js_files": 0,
        "js_linkfinder": 0,
        "js_secretfinder": 0,
        "js_customgrep": 0,
        "cve_nuclei": 0,
        "screenshots": 0
    }

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True
    ) as progress:
        all_subs_file = enumerate_subdomains(args.domain, args.output, args.verbose, progress, stats)
        console.print(make_stats_panel(stats))
        alive_file = probe_subdomains(all_subs_file, args.output, args.verbose, progress, stats)
        console.print(make_stats_panel(stats))
        urls_file, wayback_file, gau_file = collect_urls(
            alive_file, args.output, args.verbose, progress, stats,
            no_wayback=args.no_wayback, no_gau=args.no_gau
        )
        console.print(make_stats_panel(stats))
        run_gf_patterns(
            urls_file, args.output, args.verbose, progress, stats,
            no_gf=args.no_gf
        )
        console.print(make_stats_panel(stats))
        params_file = extract_params(urls_file, args.output, args.verbose, progress, stats)
        console.print(make_stats_panel(stats))
        nuclei_flag = not args.no_nuclei
        dalfox_flag = not args.no_dalfox
        if nuclei_flag or dalfox_flag:
            vuln_scan(alive_file, params_file, args.output, args.verbose, progress, stats,
                      run_nuclei=nuclei_flag, run_dalfox=dalfox_flag)
        console.print(make_stats_panel(stats))
        if args.cve_scan:
            cve_nuclei_scan(alive_file, args.output, args.verbose, progress, stats)
            console.print(make_stats_panel(stats))
        if not args.no_kxss:
            kxss_scan(params_file, args.output, args.verbose, progress, stats)
            console.print(make_stats_panel(stats))
        if not args.no_js:
            js_recon(urls_file, args.output, args.verbose, progress, stats)
            console.print(make_stats_panel(stats))
        if not args.no_screenshots:
            screenshots(alive_file, args.output, args.verbose, progress, stats)
            console.print(make_stats_panel(stats))
        generate_report(args.output)
        console.print(make_stats_panel(stats))

    console.print("[bold green]Recon complete. See the data and report directory for results.[/bold green]")

if __name__ == "__main__":
    main()
