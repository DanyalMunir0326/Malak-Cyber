# malak-cyber.py
from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path


REQUIRED_MODULES = {
    "requests":     "requests",
    "nmap":         "python-nmap",
    "whois":        "python-whois",
    "dns":          "dnspython",
    "rich":         "rich",
    "colorama":     "colorama",
    "bs4":          "beautifulsoup4",
    "urllib3":      "urllib3",
    "OpenSSL":      "pyOpenSSL",
    "cryptography": "cryptography",
    "paramiko":     "paramiko",
}

# Optional but recommended – warn rather than abort if missing
OPTIONAL_MODULES = {
    "pymongo":    "pymongo",
    "weasyprint": "weasyprint",   # PDF export (primary)
    "pdfkit":     "pdfkit",       # PDF export (fallback)
}


def _missing_dependencies() -> list[str]:
    missing = []
    for module, package in REQUIRED_MODULES.items():
        if importlib.util.find_spec(module) is None:
            missing.append(package)
    return missing


def _warn_optional() -> None:
    """Print info-level warnings for useful-but-optional packages."""
    missing_opt = [
        pkg for mod, pkg in OPTIONAL_MODULES.items()
        if importlib.util.find_spec(mod) is None
    ]
    if missing_opt:
        print(
            "[info] Optional packages not installed (non-fatal): "
            + ", ".join(sorted(missing_opt))
        )
        print(
            "       Install them for extra features:\n"
            "         pymongo    → unauthenticated MongoDB enumeration\n"
            "         weasyprint → PDF report export\n"
        )


def _bootstrap() -> None:
    missing = _missing_dependencies()
    if missing:
        print("Run: pip install -r requirements.txt")
        print("Missing required packages: " + ", ".join(sorted(set(missing))))
        raise SystemExit(1)
    if shutil.which("nmap") is None:
        print("Install nmap from https://nmap.org/download then re-run.")
        raise SystemExit(1)
    _warn_optional()


def main() -> None:
    _bootstrap()

    from rich.console import Console
    from rich.panel import Panel

    from modules import active_recon, enumeration, passive_recon, reporter, vuln_assessment, web_tester
    from modules.banner import show_banner
    from modules.utils import ScanContext, normalize_target
    from modules.wizard import run_wizard

    console = Console()
    show_banner(console)
    console.print(Panel(
        "[bold yellow]For authorized security testing only.[/]\n"
        "Only scan systems you own or have explicit written permission to test.",
        border_style="yellow",
    ))

    # Wizard now returns a 4-tuple (analyst, target, mode, report_format)
    analyst, target, mode, report_format = run_wizard(console)

    normalized = normalize_target(target)
    ctx = ScanContext(
        analyst=analyst,
        target_input=target,
        mode=mode,
        normalized_target=str(normalized["raw"]),
        domain=normalized["domain"],
        host=str(normalized["host"]),
        base_url=normalized["base_url"],
    )

    if mode in {"Full Assessment", "Passive Recon Only"}:
        passive_recon.run(ctx, console)

    if mode in {"Full Assessment", "Active Recon + Enumeration"}:
        active_recon.run(ctx, console)
        enumeration.run(ctx, console)

    if mode in {"Full Assessment", "Vulnerability Assessment Only"}:
        if not ctx.crawl.get("urls") and ctx.base_url:
            ctx.crawl["urls"].append(ctx.base_url)
        web_tester.run(ctx, console)

    if mode in {"Full Assessment", "Vulnerability Assessment Only", "Active Recon + Enumeration"}:
        vuln_assessment.run(ctx, console)

    # Pass the chosen format to the reporter
    path = reporter.generate(ctx, console, report_format=report_format)

    ext = path.suffix.upper().lstrip(".")
    console.print(
        f"\n[bold cyan]✔  Scan complete.[/] "
        f"Open the {ext} report:\n[underline]{path}[/]"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
        raise SystemExit(130)