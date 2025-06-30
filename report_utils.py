import json

def pretty_print_cve_results(cve_file, f):
    """
    Writes a nice HTML table of CVE results to an open file handle `f`.
    Expects `cve_file` to be a Path object pointing to a nuclei JSONL output file.
    """
    if not cve_file.exists() or cve_file.stat().st_size == 0:
        f.write("<h2>CVE Scan Results (Nuclei)</h2><p>No CVE matches found or scan not run.</p>")
        return

    f.write("<h2>CVE Scan Results (Nuclei)</h2>")
    f.write("<table border='1' cellpadding='4' cellspacing='0'>")
    f.write("<tr><th>Host</th><th>CVE/Template</th><th>Severity</th><th>Description</th></tr>")
    with open(cve_file) as cvef:
        for line in cvef:
            try:
                entry = json.loads(line)
                host = entry.get('host', '')
                template = entry.get('template', '') or entry.get('template-id', '')
                info = entry.get('info', {})
                severity = info.get('severity', '')
                name = info.get('name', template)
                desc = info.get('description', '')
                color = {
                    'critical': '#ff4c4c',
                    'high': '#ff9900',
                    'medium': '#ffcc00',
                    'low': '#4caf50'
                }.get(severity, '#bdbdbd')
                f.write(
                    f"<tr>"
                    f"<td>{host}</td>"
                    f"<td>{name}</td>"
                    f"<td style='color:{color};font-weight:bold'>{severity.title()}</td>"
                    f"<td>{desc}</td>"
                    f"</tr>"
                )
            except Exception:
                continue
    f.write("</table>")
