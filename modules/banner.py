from __future__ import annotations
import datetime
from rich.align import Align
from rich.columns import Columns
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

BANNER = r"""
███╗   ███╗ █████╗ ██╗      █████╗ ██╗  ██╗     ██████╗██╗   ██╗██████╗ ███████╗██████╗ 
████╗ ████║██╔══██╗██║     ██╔══██╗██║ ██╔╝    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
██╔████╔██║███████║██║     ███████║█████╔╝     ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
██║╚██╔╝██║██╔══██║██║     ██╔══██║██╔═██╗     ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║  ██║███████╗██║  ██║██║  ██╗    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
"""

_VERSION   = "1.0.0"
_AUTHOR    = "DanyalMunir0326"
_GITHUB    = "github.com/DanyalMunir0326/Malak-Cyber"
_MODULES   = ["Passive Recon", "Active Recon", "Enumeration", "Web Testing", "Vuln Assessment", "HTML Report"]


def show_banner(console) -> None:
    # ── ASCII art ──────────────────────────────────────────────────────────
    art = Text(BANNER, style="bold cyan")
    console.print(
        Panel(
            Align.center(art),
            border_style="cyan",
            title=f"[bold white] v{_VERSION} [/]",
            subtitle=f"[dim cyan]{_GITHUB}[/]",
            padding=(0, 2),
        )
    )

    # ── Info strip ─────────────────────────────────────────────────────────
    now = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    info = Table(box=box.SIMPLE, show_header=False, padding=(0, 3), expand=True)
    info.add_column(justify="left")
    info.add_column(justify="center")
    info.add_column(justify="right")
    info.add_row(
        f"[dim]Author :[/] [bold cyan]{_AUTHOR}[/]",
        f"[dim]Version :[/] [bold white]{_VERSION}[/]",
        f"[dim]Started :[/] [bold white]{now}[/]",
    )
    console.print(info)

    # ── Module capability pills ────────────────────────────────────────────
    pills: list[Text] = []
    colors = ["cyan", "green", "yellow", "magenta", "blue", "white"]
    for i, mod in enumerate(_MODULES):
        t = Text()
        t.append(f" {mod} ", style=f"bold {colors[i % len(colors)]} on grey11")
        pills.append(t)

    console.print(Align.center(Columns(pills, equal=False, expand=False)))
    console.print()