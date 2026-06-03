# reporter.py
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from .utils import ScanContext, html_escape, now_stamp, overall_risk, safe_slug, severity_breakdown, sort_findings


# ── Public entry point ────────────────────────────────────────────────────────

def generate(ctx: ScanContext, console, report_format: str = "html") -> Path:
    """Generate the report in the requested format and return its path.

    Parameters
    ----------
    ctx           : ScanContext
    console       : rich Console
    report_format : "html" or "pdf"
    """
    console.rule("[bold cyan]📄  Phase 7 – Report Generation")
    reports_dir = Path(__file__).resolve().parents[1] / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    slug  = safe_slug(ctx.analyst)
    stamp = now_stamp()
    html_path = reports_dir / f"malak-Scanner-{slug}-{stamp}.html"

    # Always render HTML first (PDF is derived from it)
    html_content = _render(ctx)
    html_path.write_text(html_content, encoding="utf-8")
    console.print(f"[bold green]HTML report saved:[/] {html_path}")

    if report_format == "pdf":
        pdf_path = _html_to_pdf(html_path, console)
        if pdf_path:
            console.print(f"[bold green]PDF report saved:[/]  {pdf_path}")
            return pdf_path
        else:
            console.print(
                "[yellow]PDF conversion failed — falling back to HTML report.[/]\n"
                "[dim]Install weasyprint or wkhtmltopdf to enable PDF export.[/]"
            )
            return html_path

    return html_path


# ── PDF conversion ────────────────────────────────────────────────────────────

def _html_to_pdf(html_path: Path, console) -> Path | None:
    """Convert an HTML file to PDF.

    Tries (in order): weasyprint → wkhtmltopdf → pdfkit.
    Returns the Path of the created PDF, or None on failure.
    """
    pdf_path = html_path.with_suffix(".pdf")

    # 1. weasyprint (pure Python, best CSS support)
    try:
        from weasyprint import HTML  # type: ignore
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return pdf_path
    except ImportError:
        pass
    except Exception as exc:
        console.print(f"[dim]weasyprint error: {exc}[/]")

    # 2. wkhtmltopdf via subprocess
    try:
        result = subprocess.run(
            ["wkhtmltopdf", "--quiet", "--no-stop-slow-scripts",
             str(html_path), str(pdf_path)],
            timeout=120,
            capture_output=True,
        )
        if result.returncode == 0 and pdf_path.exists():
            return pdf_path
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # 3. pdfkit wrapper around wkhtmltopdf
    try:
        import pdfkit  # type: ignore
        pdfkit.from_file(str(html_path), str(pdf_path))
        if pdf_path.exists():
            return pdf_path
    except ImportError:
        pass
    except Exception as exc:
        console.print(f"[dim]pdfkit error: {exc}[/]")

    return None


# ── HTML rendering ────────────────────────────────────────────────────────────

def _render(ctx: ScanContext) -> str:
    counts   = severity_breakdown(ctx.findings)
    findings = sort_findings(ctx.findings)
    risk     = overall_risk(ctx.findings)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Malak-Cyber Report – {html_escape(ctx.target_input)}</title>
<style>
:root {{
  color-scheme: dark;
  --bg:      #0b0d10;
  --panel:   #151922;
  --muted:   #9ca3af;
  --line:    #2a3140;
  --text:    #f3f4f6;
  --cyan:    #22d3ee;
  --red:     #ef4444;
  --orange:  #f97316;
  --yellow:  #eab308;
  --blue:    #3b82f6;
  --grey:    #6b7280;
  --green:   #22c55e;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: "Segoe UI", Arial, sans-serif;
  line-height: 1.6;
}}
main {{ width: min(1200px, calc(100% - 40px)); margin: 0 auto; padding: 40px 0 80px; }}

/* ── Cover ── */
.cover {{
  min-height: 55vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  border-bottom: 2px solid var(--cyan);
  padding-bottom: 32px;
  margin-bottom: 40px;
}}
.cover h1 {{
  font-size: 52px;
  letter-spacing: -1px;
  background: linear-gradient(135deg, var(--cyan), var(--blue));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 12px;
}}
.cover .subtitle {{ color: var(--muted); font-size: 15px; margin-bottom: 24px; }}
.risk-pill {{
  display: inline-block;
  padding: 6px 18px;
  border-radius: 999px;
  font-weight: 700;
  font-size: 15px;
  margin-top: 14px;
}}
.risk-Critical {{ background: rgba(239,68,68,.2);  color: #fca5a5; border: 1px solid #ef4444; }}
.risk-High     {{ background: rgba(249,115,22,.2); color: #fdba74; border: 1px solid #f97316; }}
.risk-Medium   {{ background: rgba(234,179,8,.2);  color: #fde68a; border: 1px solid #eab308; }}
.risk-Low      {{ background: rgba(59,130,246,.2); color: #bfdbfe; border: 1px solid #3b82f6; }}
.risk-Info     {{ background: rgba(107,114,128,.2);color: #e5e7eb; border: 1px solid #6b7280; }}

/* ── Sections ── */
section {{ margin: 40px 0; }}
h2 {{
  font-size: 22px;
  border-bottom: 1px solid var(--line);
  padding-bottom: 10px;
  margin-bottom: 20px;
  color: var(--cyan);
}}
h3 {{ font-size: 16px; margin: 20px 0 10px; color: #e2e8f0; }}

/* ── Grid ── */
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }}
.panel {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 20px;
}}

/* ── Severity badges ── */
.badges {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0; }}
.badge {{
  display: inline-flex;
  align-items: center;
  gap: 8px;
  border-radius: 999px;
  padding: 6px 14px;
  font-weight: 700;
  font-size: 13px;
}}
.Critical {{ background: rgba(239,68,68,.16);  color: #fecaca; border: 1px solid rgba(239,68,68,.5); }}
.High     {{ background: rgba(249,115,22,.16); color: #fed7aa; border: 1px solid rgba(249,115,22,.5); }}
.Medium   {{ background: rgba(234,179,8,.16);  color: #fef3c7; border: 1px solid rgba(234,179,8,.5); }}
.Low      {{ background: rgba(59,130,246,.16); color: #bfdbfe; border: 1px solid rgba(59,130,246,.5); }}
.Info     {{ background: rgba(107,114,128,.20);color: #e5e7eb; border: 1px solid rgba(107,114,128,.6); }}

/* ── Tables ── */
table {{ width: 100%; border-collapse: collapse; border-radius: 10px; overflow: hidden; font-size: 14px; }}
th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }}
th {{ background: #111827; color: #bae6fd; font-size: 13px; text-transform: uppercase; letter-spacing: .5px; }}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: rgba(255,255,255,.02); }}

/* ── Finding cards ── */
.finding {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 22px;
  margin-bottom: 20px;
  border-left: 4px solid var(--line);
}}
.finding.sev-Critical {{ border-left-color: var(--red); }}
.finding.sev-High     {{ border-left-color: var(--orange); }}
.finding.sev-Medium   {{ border-left-color: var(--yellow); }}
.finding.sev-Low      {{ border-left-color: var(--blue); }}
.finding.sev-Info     {{ border-left-color: var(--grey); }}
.finding h3 {{ margin-top: 10px; font-size: 18px; }}
.finding p  {{ margin: 8px 0; font-size: 14px; color: #d1d5db; }}

code, pre {{
  font-family: Consolas, "Courier New", monospace;
  font-size: 13px;
}}
pre {{
  background: #080a0f;
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 14px;
  color: #d1d5db;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 400px;
  overflow-y: auto;
}}
a {{ color: var(--cyan); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
ol, ul {{ padding-left: 22px; }}
li {{ margin: 4px 0; font-size: 14px; }}
.muted {{ color: var(--muted); font-size: 14px; }}

/* ── Stat pills in summary ── */
.stat-grid {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 14px; }}
.stat {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 12px 20px;
  min-width: 110px;
  text-align: center;
}}
.stat .num {{ font-size: 28px; font-weight: 700; }}
.stat .lbl {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}

/* ── Print / PDF ── */
@media print {{
  body {{ background: #fff; color: #111; }}
  main {{ padding: 20px; }}
  .panel, .finding {{ background: #f9f9f9; border-color: #ccc; page-break-inside: avoid; }}
  pre {{ max-height: none; background: #f4f4f4; }}
  h2 {{ color: #1e3a8a; border-color: #93c5fd; }}
  a {{ color: #1d4ed8; }}
}}
</style>
</head>
<body>
<main>

<!-- ── Cover ── -->
<section class="cover">
  <h1>Malak-Cyber</h1>
  <div class="subtitle">
    Security Assessment Report &nbsp;|&nbsp;
    Analyst: <strong>{html_escape(ctx.analyst)}</strong> &nbsp;|&nbsp;
    Target: <strong>{html_escape(ctx.target_input)}</strong><br>
    Scan date: {html_escape(ctx.started_at.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"))} &nbsp;|&nbsp;
    Mode: {html_escape(ctx.mode)}
  </div>
  <div class="badges">
    {_badge("Critical", counts["Critical"])}
    {_badge("High",     counts["High"])}
    {_badge("Medium",   counts["Medium"])}
    {_badge("Low",      counts["Low"])}
    {_badge("Info",     counts["Info"])}
  </div>
  <div>
    Overall risk:
    <span class="risk-pill risk-{risk}">{risk}</span>
  </div>
</section>

<!-- ── Executive Summary ── -->
<section>
  <h2>Executive Summary</h2>
  <p>Malak-Cyber assessed <strong>{html_escape(ctx.target_input)}</strong> and produced
  <strong>{len(ctx.findings)}</strong> findings across passive reconnaissance, active enumeration,
  web application checks, and configuration review.</p>
  <div class="stat-grid">
    <div class="stat"><div class="num" style="color:var(--red)">{counts["Critical"]}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="num" style="color:var(--orange)">{counts["High"]}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="num" style="color:var(--yellow)">{counts["Medium"]}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num" style="color:var(--blue)">{counts["Low"]}</div><div class="lbl">Low</div></div>
    <div class="stat"><div class="num" style="color:var(--grey)">{counts["Info"]}</div><div class="lbl">Info</div></div>
    <div class="stat"><div class="num">{len(ctx.open_ports)}</div><div class="lbl">Open Ports</div></div>
    <div class="stat"><div class="num">{len(ctx.subdomains)}</div><div class="lbl">Subdomains</div></div>
  </div>
</section>

<!-- ── Attack Surface ── -->
<section>
  <h2>Attack Surface Overview</h2>
  <div class="grid">
    <div class="panel"><h3>Open Ports</h3>{_ports(ctx)}</div>
    <div class="panel"><h3>Live Subdomains</h3>{_list([n for n, d in ctx.subdomains.items() if d.get("live")])}</div>
    <div class="panel"><h3>Detected Technologies</h3>{_list(sorted(ctx.technologies))}</div>
    <div class="panel"><h3>Sensitive Paths</h3>{_paths(ctx)}</div>
  </div>
</section>

<!-- ── Passive Recon ── -->
<section>
  <h2>Passive Recon Summary</h2>
  <h3>WHOIS</h3>{_dict_table(ctx.whois)}
  <h3>DNS Records</h3>{_dict_table(ctx.dns_records)}
  <h3>Certificate Transparency</h3>{_certs(ctx)}
  <h3>Manual Dorking Checklist</h3>{_list(ctx.google_dorks)}
</section>

<!-- ── Findings ── -->
<section>
  <h2>Findings – Full Detail</h2>
  {''.join(_finding(item) for item in findings) or '<p class="muted">No findings were recorded.</p>'}
</section>

<!-- ── CVE Correlation ── -->
<section>
  <h2>CVE Correlation Table</h2>
  {_cves(ctx)}
</section>

<!-- ── Remediation ── -->
<section>
  <h2>Remediation Roadmap</h2>
  {_roadmap(findings)}
</section>

<!-- ── Appendix ── -->
<section>
  <h2>Appendix</h2>
  <h3>Full Port Scan Raw Output</h3>
  <pre>{html_escape(ctx.raw_outputs.get("nmap", ""))}</pre>
  <h3>All Discovered URLs / Endpoints</h3>
  {_list(ctx.crawl.get("urls", []) + ctx.crawl.get("api_endpoints", []))}
  <h3>All Tested Payloads</h3>
  {_list(ctx.tested_payloads)}
  <h3>Subdomain Enumeration</h3>
  {_subdomains(ctx)}
  <h3>Scan Parameters</h3>
  <pre>Malak-Cyber version : 1.1.0
Mode                : {html_escape(ctx.mode)}
Target              : {html_escape(ctx.target_input)}
Host                : {html_escape(ctx.host)}
Base URL            : {html_escape(ctx.base_url or "")}</pre>
  <h3>Warnings</h3>
  {_list(ctx.warnings)}
</section>

</main>
</body>
</html>"""


# ── Rendering helpers ─────────────────────────────────────────────────────────

def _badge(name: str, count: int) -> str:
    return f'<span class="badge {name}">{name.upper()} {count}</span>'


def _list(items) -> str:
    values = list(items or [])
    if not values:
        return '<p class="muted">None recorded.</p>'
    return "<ul>" + "".join(f"<li>{html_escape(item)}</li>" for item in values[:500]) + "</ul>"


def _dict_table(data: dict) -> str:
    if not data:
        return '<p class="muted">None recorded.</p>'
    rows = "".join(
        f"<tr><th>{html_escape(k)}</th><td>{html_escape(v)}</td></tr>"
        for k, v in data.items()
    )
    return f"<table>{rows}</table>"


def _ports(ctx: ScanContext) -> str:
    if not ctx.open_ports:
        return '<p class="muted">None recorded.</p>'
    rows = "".join(
        f"<tr>"
        f"<td>{html_escape(p['port'])}/{html_escape(p['protocol'])}</td>"
        f"<td>{html_escape(p['service'])}</td>"
        f"<td>{html_escape(p['version'])}</td>"
        f"<td>{html_escape(p['risk'])}</td>"
        f"</tr>"
        for p in ctx.open_ports
    )
    return f"<table><tr><th>Port</th><th>Service</th><th>Version</th><th>Risk</th></tr>{rows}</table>"


def _paths(ctx: ScanContext) -> str:
    if not ctx.sensitive_paths:
        return '<p class="muted">None recorded.</p>'
    rows = "".join(
        f"<tr>"
        f"<td>{html_escape(p['path'])}</td>"
        f"<td>{html_escape(p['status'])}</td>"
        f"<td>{html_escape(p.get('location',''))}</td>"
        f"</tr>"
        for p in ctx.sensitive_paths
    )
    return f"<table><tr><th>Path</th><th>Status</th><th>Redirect</th></tr>{rows}</table>"


def _certs(ctx: ScanContext) -> str:
    if not ctx.certificates:
        return '<p class="muted">None recorded.</p>'
    rows = "".join(
        f"<tr>"
        f"<td>{html_escape(c.get('issuer', ''))}</td>"
        f"<td>{html_escape(c.get('not_before', ''))}</td>"
        f"<td>{html_escape(c.get('not_after', ''))}</td>"
        f"<td>{html_escape(', '.join(c.get('names', [])[:12]))}</td>"
        f"</tr>"
        for c in ctx.certificates[:100]
    )
    return f"<table><tr><th>Issuer</th><th>Not Before</th><th>Not After</th><th>Names</th></tr>{rows}</table>"


def _finding(item) -> str:
    refs = "".join(
        f'<li><a href="{html_escape(ref)}" target="_blank">{html_escape(ref)}</a></li>'
        for ref in item.references
    )
    mitigation = "".join(f"<li>{html_escape(step)}</li>" for step in item.mitigation)
    return f"""<article class="finding sev-{html_escape(item.severity)}">
  <span class="badge {html_escape(item.severity)}">{html_escape(item.severity)}</span>
  <h3>{html_escape(item.name)}</h3>
  <p>
    <strong>CVSS:</strong> {item.cvss}
    <span class="muted">{html_escape(item.vector)}</span>
    &nbsp;|&nbsp; <strong>CVE:</strong> {html_escape(item.cve or "N/A")}
    &nbsp;|&nbsp; <strong>Category:</strong> {html_escape(item.category)}
  </p>
  <p><strong>Description:</strong> {html_escape(item.description)}</p>
  <p><strong>Evidence:</strong></p>
  <pre>{html_escape(item.evidence)}</pre>
  <p><strong>Risk:</strong> {html_escape(item.risk)}</p>
  <p><strong>Mitigation:</strong></p><ol>{mitigation}</ol>
  <p><strong>References:</strong></p>
  <ul>{refs or '<li>N/A</li>'}</ul>
</article>"""


def _cves(ctx: ScanContext) -> str:
    if not ctx.cves:
        return '<p class="muted">None recorded.</p>'
    rows = "".join(
        f"<tr>"
        f"<td>{html_escape(c['id'])}</td>"
        f"<td>{html_escape(c['service'])}</td>"
        f"<td>{html_escape(str(c['cvss']))}</td>"
        f"<td>{html_escape(c['description'])}</td>"
        f"<td><a href='{html_escape(c['link'])}' target='_blank'>NVD ↗</a></td>"
        f"</tr>"
        for c in ctx.cves
    )
    return (
        f"<table><tr>"
        f"<th>CVE ID</th><th>Affected Service</th><th>CVSS</th>"
        f"<th>Description</th><th>Link</th>"
        f"</tr>{rows}</table>"
    )


def _roadmap(findings) -> str:
    groups = {
        "🔴 Fix Immediately (Critical + High)": [f for f in findings if f.severity in {"Critical", "High"}],
        "🟡 Fix Soon (Medium)":                  [f for f in findings if f.severity == "Medium"],
        "🔵 Fix When Possible (Low)":             [f for f in findings if f.severity == "Low"],
        "⚪ Informational (Info)":               [f for f in findings if f.severity == "Info"],
    }
    parts: list[str] = []
    for title, items in groups.items():
        parts.append(f"<h3>{html_escape(title)}</h3>")
        parts.append(_list([
            f"{item.name}: {item.mitigation[0] if item.mitigation else 'Review finding.'}"
            for item in items
        ]))
    return "".join(parts)


def _subdomains(ctx: ScanContext) -> str:
    if not ctx.subdomains:
        return '<p class="muted">None recorded.</p>'
    rows = "".join(
        f"<tr>"
        f"<td>{html_escape(name)}</td>"
        f"<td>{html_escape(str(data.get('ips', [])))}</td>"
        f"<td>{html_escape(str(data.get('live', '')))}</td>"
        f"<td>{html_escape(data.get('source', 'dns'))}</td>"
        f"</tr>"
        for name, data in ctx.subdomains.items()
    )
    return (
        f"<table><tr>"
        f"<th>Subdomain</th><th>IPs</th><th>Live</th><th>Source</th>"
        f"</tr>{rows}</table>"
    )