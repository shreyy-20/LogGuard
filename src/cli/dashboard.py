import os
import sys
import time
import platform
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

from src.config import load_config
from src.database import DatabaseManager

console = Console()

class DashboardUI:
    def __init__(self, config_path: str):
        self.config = load_config(config_path)
        self.db = DatabaseManager(
            db_path=self.config.database.db_path,
            batch_size=self.config.database.batch_size,
            flush_interval=self.config.database.flush_interval_seconds
        )
        self.db.stop()  # Stop async writing, we only read in the dashboard UI
        self.layout = Layout()
        self._setup_layout()

    def _setup_layout(self):
        """Creates the split screen panels structure."""
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3)
        )
        self.layout["body"].split_column(
            Layout(name="upper", ratio=3),
            Layout(name="lower", ratio=2)
        )
        self.layout["body"]["upper"].split_row(
            Layout(name="stats", ratio=2),
            Layout(name="alerts", ratio=3)
        )

    def generate_header(self) -> Panel:
        """Renders header bar with time and system details."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sys_info = f"OS: {platform.system()} {platform.release()} | Python: {platform.python_version()}"
        
        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right", ratio=1)
        grid.add_row(
            "[bold green]🛡️  LOGGUARD CONTROL CENTER[/bold green]",
            f"[dim]{sys_info}[/dim]",
            f"[bold cyan]⏰ {now}[/bold cyan]"
        )
        return Panel(grid, style="bold white on black", box=ROUNDED)

    def generate_stats_panel(self) -> Panel:
        """Renders real-time charts/tables showing parsed counts."""
        try:
            stats = self.db.get_stats()
        except Exception:
            stats = {"total_logs": 0, "total_alerts": 0, "levels": {}, "top_programs": {}}

        grid = Table.grid(expand=True, padding=(0, 2))
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)

        # Totals list
        totals_table = Table(show_header=False, box=None)
        totals_table.add_row("Total Ingested:", f"[bold cyan]{stats.get('total_logs', 0)}[/bold cyan]")
        totals_table.add_row("Security Alerts:", f"[bold red]{stats.get('total_alerts', 0)}[/bold red]")
        totals_table.add_row("DB Path:", f"[dim]{self.config.database.db_path}[/dim]")
        
        # Level distribution table
        level_table = Table(title="Severity Metrics", title_style="bold yellow", box=ROUNDED, expand=True)
        level_table.add_column("Severity")
        level_table.add_column("Count", justify="right")
        
        levels = stats.get("levels", {})
        for lvl in ["INFO", "WARNING", "ERROR", "CRITICAL"]:
            count = levels.get(lvl, 0)
            color = "green"
            if lvl == "WARNING":
                color = "yellow"
            elif lvl == "ERROR":
                color = "red"
            elif lvl == "CRITICAL":
                color = "bold white on red"
            level_table.add_row(f"[{color}]{lvl}[/{color}]", str(count))

        # Top Programs Table
        prog_table = Table(title="Top Sources", title_style="bold yellow", box=ROUNDED, expand=True)
        prog_table.add_column("Program")
        prog_table.add_column("Count", justify="right")
        for prog, cnt in stats.get("top_programs", {}).items():
            prog_table.add_row(f"[blue]{prog}[/blue]", str(cnt))

        grid.add_row(level_table, prog_table)
        
        # Package inside a parent layout grid
        main_grid = Table.grid(expand=True)
        main_grid.add_row(Panel(totals_table, title="Log Summary", box=ROUNDED))
        main_grid.add_row(grid)

        return Panel(main_grid, title="System Metrics Dashboard", box=ROUNDED, border_style="cyan")

    def generate_alerts_panel(self) -> Panel:
        """Renders rolling warnings list."""
        try:
            alerts = self.db.get_alerts(limit=10)
        except Exception:
            alerts = []

        table = Table(show_header=True, header_style="bold red", box=ROUNDED, expand=True)
        table.add_column("Time", style="cyan", no_wrap=True)
        table.add_column("Type", style="bold yellow")
        table.add_column("Severity", style="bold")
        table.add_column("Message", ratio=1)

        for a in alerts:
            sev = a["severity"]
            sev_fmt = f"[bold white on red]{sev}[/bold white on red]" if sev == "CRITICAL" else f"[bold yellow]{sev}[/bold yellow]"
            
            # Truncate alert message
            msg = a["message"]
            if len(msg) > 60:
                msg = msg[:57] + "..."
                
            table.add_row(
                a["timestamp"][11:], # Show only time part HH:MM:SS
                a["alert_type"],
                sev_fmt,
                msg
            )
            
        return Panel(table, title="🚨 Active Threat Alerts", box=ROUNDED, border_style="red")

    def generate_lower_panel(self) -> Panel:
        """Renders real-time tailing logs."""
        try:
            logs = self.db.query_logs(limit=15)
        except Exception:
            logs = []

        table = Table(show_header=True, header_style="bold magenta", box=ROUNDED, expand=True)
        table.add_column("Time", style="cyan", no_wrap=True)
        table.add_column("Level", style="bold")
        table.add_column("Program", style="blue")
        table.add_column("Message", ratio=1)

        for l in reversed(logs):
            lvl = l["log_level"]
            lvl_fmt = f"[bold green]{lvl}[/bold green]"
            if lvl == "WARNING":
                lvl_fmt = f"[bold yellow]{lvl}[/bold yellow]"
            elif lvl == "ERROR":
                lvl_fmt = f"[bold red]{lvl}[/bold red]"
            elif lvl == "CRITICAL":
                lvl_fmt = f"[bold white on red]{lvl}[/bold white on red]"

            # Truncate message
            msg = l["message"]
            if len(msg) > 100:
                msg = msg[:97] + "..."

            table.add_row(
                l["timestamp"],
                lvl_fmt,
                l["program"],
                msg
            )

        return Panel(table, title="📋 Live Ingested System Logs", box=ROUNDED, border_style="magenta")

    def generate_footer(self) -> Panel:
        """Footer bar with keybind guides."""
        grid = Table.grid(expand=True)
        grid.add_column(justify="center")
        grid.add_row(
            "[dim]Press [/dim][bold yellow]Ctrl+C[/bold yellow][dim] to exit dashboard | Run daemon in background to feed data[/dim]"
        )
        return Panel(grid, box=ROUNDED)

    def update_dashboard(self):
        """Queries database and refreshes layout panels."""
        self.layout["header"].update(self.generate_header())
        self.layout["body"]["upper"]["stats"].update(self.generate_stats_panel())
        self.layout["body"]["upper"]["alerts"].update(self.generate_alerts_panel())
        self.layout["body"]["lower"].update(self.generate_lower_panel())
        self.layout["footer"].update(self.generate_footer())

def run_dashboard(config_path: str):
    """Executes the terminal dashboard loop."""
    ui = DashboardUI(config_path)
    
    # Enable full terminal alternate screen buffer
    try:
        with Live(ui.layout, refresh_per_second=1, screen=True) as live:
            while True:
                ui.update_dashboard()
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        console.clear()
        console.print("[bold green]Returned to shell successfully.[/bold green]")
