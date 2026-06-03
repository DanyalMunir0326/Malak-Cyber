# wizard.py
from __future__ import annotations

import sys
from contextlib import contextmanager

from rich.prompt import Prompt
from rich.table import Table
from rich import box


MODES = {
    "1": "Full Assessment",
    "2": "Passive Recon Only",
    "3": "Active Recon + Enumeration",
    "4": "Vulnerability Assessment Only",
}

REPORT_FORMATS = {
    "1": "html",
    "2": "pdf",
}


def run_wizard(console) -> tuple[str, str, str, str]:
    """Run the interactive setup wizard.

    Returns
    -------
    analyst : str
    target  : str
    mode    : str
    report_format : str   — "html" or "pdf"
    """
    name = Prompt.ask("[bold cyan]Enter your name[/]").strip() or "Analyst"
    target = Prompt.ask("[bold cyan]Enter target (IP, domain, or URL)[/]").strip()

    # Scan mode table
    mode_table = Table(title="Scan Mode", show_header=True, header_style="bold cyan", box=box.ROUNDED)
    mode_table.add_column("Option", justify="center", style="bold yellow")
    mode_table.add_column("Mode")
    for key, value in MODES.items():
        mode_table.add_row(key, value)
    console.print(mode_table)
    mode_choice = Prompt.ask(
        "[bold cyan]Choose scan mode[/]",
        choices=list(MODES.keys()),
        default="1",
    )

    # Report format table
    fmt_table = Table(title="Report Format", show_header=True, header_style="bold cyan", box=box.ROUNDED)
    fmt_table.add_column("Option", justify="center", style="bold yellow")
    fmt_table.add_column("Format")
    fmt_table.add_row("1", "HTML  (interactive, opens in browser)")
    fmt_table.add_row("2", "PDF   (portable, printable)")
    console.print(fmt_table)
    fmt_choice = Prompt.ask(
        "[bold cyan]Choose report format[/]",
        choices=list(REPORT_FORMATS.keys()),
        default="1",
    )

    return name, target, MODES[mode_choice], REPORT_FORMATS[fmt_choice]


class PhaseProgress:
    """Context manager that prints a rich live-progress bar for a scan phase.

    Each call to :meth:`step` advances the progress bar and prints what is
    currently happening so the operator always knows which sub-task is running.
    """

    # Per-phase colour / icon palette so the console is easy to read at a glance
    _PHASE_STYLE: dict[str, tuple[str, str]] = {
        "passive": ("cyan",   "🔍"),
        "active":  ("yellow", "⚡"),
        "enum":    ("green",  "🔎"),
        "web":     ("blue",   "🌐"),
        "vuln":    ("red",    "💀"),
        "report":  ("magenta","📄"),
    }

    def __init__(self, console, phase_title: str) -> None:
        self._console = console
        self._phase_title = phase_title
        self._style, self._icon = self._resolve_style(phase_title)
        self._step_num = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _resolve_style(self, title: str) -> tuple[str, str]:
        t = title.lower()
        if "passive" in t:
            return self._PHASE_STYLE["passive"]
        if "active" in t:
            return self._PHASE_STYLE["active"]
        if "enumerat" in t:
            return self._PHASE_STYLE["enum"]
        if "web" in t or "application" in t:
            return self._PHASE_STYLE["web"]
        if "vuln" in t:
            return self._PHASE_STYLE["vuln"]
        if "report" in t:
            return self._PHASE_STYLE["report"]
        return ("white", "▶")

    def _print(self, msg: str, style: str = "") -> None:
        self._console.print(msg, style=style or self._style)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def __enter__(self) -> "PhaseProgress":
        self._console.rule(f"[bold {self._style}]{self._icon}  {self._phase_title}[/]")
        return self

    def __exit__(self, *_) -> None:
        pass  # done() is called explicitly by each phase

    def step(self, description: str) -> None:
        """Print the currently-running sub-task with a spinner-style prefix."""
        self._step_num += 1
        self._console.print(
            f"  [{self._style}]▶[/] [{self._style}]{description}[/]"
        )

    def warn(self, message: str) -> None:
        """Print a yellow warning that a sub-task was skipped or failed."""
        self._console.print(f"  [yellow]⚠  {message}[/]")

    def done(self) -> None:
        """Print a completion line for the phase."""
        self._console.print(
            f"  [bold {self._style}]✔  {self._phase_title} complete[/]"
        )
        self._console.print()