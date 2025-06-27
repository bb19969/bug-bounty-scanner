import argparse
import logging
import os
import sys
import shutil
import subprocess
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn
from rich.panel import Panel

REQUIRED_TOOLS = [
    # "amass",  # Amass is commented out for faster runs
    "subfinder", "assetfinder", "findomain", "dnsx", "httpx",
    "waybackurls", "gau", "nuclei", "dalfox", "kxss", "aquatone"
]

console = Console()

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
    file_map = {
        # "amass": data_dir / "amass.txt",  # Amass is commented out for faster runs
        "subfinder": data_dir / "subfinder.txt",
        "assetfinder": data_dir / "assetfinder.txt",
        "findomain": data_dir / "findomain.txt"
    }
    tools = [
        # ("amass", ["amass", "enum", "-passive", "-d", domain, "-o", str(file_map["amass"])]), # Amass is commented out
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
    all_subs_file = data_dir / "all-subs.txt"
    combine_unique(
        # file_map["amass"],  # Amass output not needed if amass is skipped
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

def collect_urls(alive_file, output_dir, verbose, progress, stats):
    data_dir = Path(output_dir) / "data"
    wayback_file = data_dir / "waybackurls.txt"
    gau_file = data_dir / "gau.txt"
    urls_file = data_dir / "urls.txt"
    if not Path(alive_file).exists():
        stats["wayback"] = 0
        stats["gau"] = 0
        stats["urls"] = 0
        return urls_file
    with open(alive_file) as f:
        hosts = [line.strip() for line in f if line.strip()]
    task = progress.add_task("[yellow]Collecting URLs", total=len(hosts)*2)
    for host in hosts:
        # Remove protocol if present
        if host.startswith("http://") or host.startswith("https://"):
            domain = host.split("//", 1)[1]
        else:
            domain = host
        run_cmd(["waybackurls", domain], outfile=wayback_file, verbose=verbose, append=True)
        stats["wayback"] += 1
        progress.update(task, advance=1)
        run_cmd(["gau", domain], outfile=gau_file, verbose=verbose, append=True)
        stats["gau"] += 1
        progress.update(task, advance=1)
    combine_unique(wayback_file, gau_file, outfile=urls_file)
    if Path(urls_file).exists():
        with open(urls_file) as f:
            stats["urls"] = sum(1 for _ in f)
    else:
        stats["urls"] = 0
    return urls_file

def run_gf_patterns(urls_file, output_dir, verbose, progress, stats):
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

def vuln_scan(alive_file, params_file, output_dir, verbose, progress, stats):
    data_dir = Path(output_dir) / "data"
    nuclei_out = data_dir / "nuclei.txt"
    dalfox_out = data_dir / "dalfox.txt"
    task = progress.add_task("[red]Vuln Scans", total=2)
    run_cmd(["nuclei", "-l", str(alive_file), "-o", str(nuclei_out)], verbose=verbose)
    stats["nuclei"] = sum(1 for _ in open(nuclei_out)) if Path(nuclei_out).exists() else 0
    progress.update(task, advance=1)
    run_cmd(["dalfox", "file", str(params_file), "--output", str(dalfox_out)], verbose=verbose)
    stats["dalfox"] = sum(1 for _ in open(dalfox_out)) if Path(dalfox_out).exists() else 0
    progress.update(task, advance=1)
    return nuclei_out, dalfox_out

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

def generate_report(output_dir):
    report_dir = Path(output_dir) / "report"
    html_report = report_dir / "index.html"
    with open(html_report, "w") as f:
        f.write("<!DOCTYPE html><html><head><title>Recon Report</title></head><body><h1>Recon Report</h1><p>See data directory for results.</p></body></html>")
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
[green]Screenshots taken:[/green] {stats['screenshots']}
""", title="Live Recon Stats", expand=False)

def main():
    parser = argparse.ArgumentParser(description="Python Recon Framework with Live Stats (rich)")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("--log", help="Log file")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Show what would run, but don’t run")
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
        urls_file = collect_urls(alive_file, args.output, args.verbose, progress, stats)
        console.print(make_stats_panel(stats))
        gf_patterns = run_gf_patterns(urls_file, args.output, args.verbose, progress, stats)
        console.print(make_stats_panel(stats))
        params_file = extract_params(urls_file, args.output, args.verbose, progress, stats)
        console.print(make_stats_panel(stats))
        nuclei_out, dalfox_out = vuln_scan(alive_file, params_file, args.output, args.verbose, progress, stats)
        console.print(make_stats_panel(stats))
        kxss_out = kxss_scan(params_file, args.output, args.verbose, progress, stats)
        console.print(make_stats_panel(stats))
        screenshots_dir = screenshots(alive_file, args.output, args.verbose, progress, stats)
        console.print(make_stats_panel(stats))
        report_file = generate_report(args.output)
        console.print(make_stats_panel(stats))

    console.print("[bold green]Recon complete. See the data and report directory for results.[/bold green]")

if __name__ == "__main__":
    main()
