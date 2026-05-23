import os
import sys
import click
import csv
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns

from src.config import load_config
from src.database import DatabaseManager
from src.main import LogGuardDaemon

console = Console()

@click.group()
@click.option("--config", "-c", default="config/config.yaml", help="Path to config.yaml")
@click.pass_context
def cli(ctx, config):
    """LogGuard: A production-ready Linux Log Monitoring & Analysis CLI."""
    ctx.ensure_object(dict)
    ctx.obj["CONFIG_PATH"] = config
    try:
        ctx.obj["CONFIG"] = load_config(config)
        # Instantiate DB Manager using config settings
        ctx.obj["DB"] = DatabaseManager(
            db_path=ctx.obj["CONFIG"].database.db_path,
            batch_size=ctx.obj["CONFIG"].database.batch_size,
            flush_interval=ctx.obj["CONFIG"].database.flush_interval_seconds
        )
    except Exception as e:
        console.print(f"[bold red]Error loading configuration/database:[/bold red] {e}")
        sys.exit(1)

@cli.command()
@click.pass_context
def start(ctx):
    """Start the real-time LogGuard monitoring daemon."""
    console.print("[bold green]Starting LogGuard Daemon...[/bold green]")
    console.print(f"Reading logs as configured in '{ctx.obj['CONFIG_PATH']}'")
    console.print("Writing entries to SQLite database in Write-Ahead Log (WAL) mode.")
    console.print("Press Ctrl+C to terminate.")
    
    # Run the main daemon loop
    daemon = LogGuardDaemon(ctx.obj["CONFIG_PATH"])
    daemon.start()
    
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        daemon.stop()
        console.print("\n[bold yellow]Daemon stopped successfully.[/bold yellow]")

@cli.command()
@click.option("--since", help="Start timestamp (YYYY-MM-DD HH:MM:SS)")
@click.option("--until", help="End timestamp (YYYY-MM-DD HH:MM:SS)")
@click.option("--level", "-l", help="Log level (INFO, WARNING, ERROR, CRITICAL)")
@click.option("--source", "-s", help="Filter by log file source name")
@click.option("--program", "-p", help="Filter by program/process name")
@click.option("--keyword", "-k", help="FTS search keyword")
@click.option("--limit", default=50, show_default=True, help="Max results count")
@click.option("--offset", default=0, show_default=True, help="Results page offset")
@click.pass_context
def search(ctx, since, until, level, source, program, keyword, limit, offset):
    """Search and filter logs stored in the SQLite database."""
    db: DatabaseManager = ctx.obj["DB"]
    
    try:
        logs = db.query_logs(
            since=since,
            until=until,
            log_level=level,
            source_file=source,
            program=program,
            keyword=keyword,
            limit=limit,
            offset=offset
        )
        
        # Stop DB background thread cleanly
        db.stop()
        
        if not logs:
            console.print("[yellow]No logs match your filter criteria.[/yellow]")
            return

        table = Table(title="Log Search Results", show_header=True, header_style="bold magenta")
        table.add_column("Time", style="cyan", no_wrap=True)
        table.add_column("Level", style="bold")
        table.add_column("Source", style="green")
        table.add_column("Program", style="blue")
        table.add_column("PID", style="dim")
        table.add_column("Message", ratio=3)

        for log in logs:
            # Color levels
            lvl = log["log_level"]
            lvl_fmt = f"[bold green]{lvl}[/bold green]"
            if lvl == "WARNING":
                lvl_fmt = f"[bold yellow]{lvl}[/bold yellow]"
            elif lvl == "ERROR":
                lvl_fmt = f"[bold red]{lvl}[/bold red]"
            elif lvl == "CRITICAL":
                lvl_fmt = f"[bold white on red]{lvl}[/bold white on red]"
            elif lvl == "DEBUG":
                lvl_fmt = f"[dim]{lvl}[/dim]"

            table.add_row(
                log["timestamp"],
                lvl_fmt,
                log["source_file"],
                log["program"],
                str(log["pid"]) if log["pid"] else "-",
                log["message"]
            )
            
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Query failed:[/bold red] {e}")

@cli.command()
@click.pass_context
def stats(ctx):
    """View real-time log ingestion metrics and tables."""
    db: DatabaseManager = ctx.obj["DB"]
    try:
        metrics = db.get_stats()
        db.stop()
        
        # Total counts panel
        totals_table = Table(show_header=False, box=None)
        totals_table.add_row("Total Logs Parsed:", f"[bold cyan]{metrics['total_logs']}[/bold cyan]")
        totals_table.add_row("Total Alerts Triggered:", f"[bold red]{metrics['total_alerts']}[/bold red]")
        
        panel_totals = Panel(totals_table, title="General Metrics", expand=False)

        # Log Levels Table
        level_table = Table(title="Level Distribution")
        level_table.add_column("Level", style="bold")
        level_table.add_column("Count", style="green")
        for lvl, cnt in metrics.get("levels", {}).items():
            level_table.add_row(lvl, str(cnt))

        # Top Programs Table
        prog_table = Table(title="Top Log Contributors")
        prog_table.add_column("Program", style="bold cyan")
        prog_table.add_column("Log Count", style="green")
        for prog, cnt in metrics.get("top_programs", {}).items():
            prog_table.add_row(prog, str(cnt))

        console.print(Panel("[bold green]LogGuard Real-Time Statistics[/bold green]", expand=False))
        console.print(Columns([panel_totals, level_table, prog_table]))
    except Exception as e:
        console.print(f"[bold red]Failed to fetch statistics:[/bold red] {e}")

@cli.command()
@click.option("--limit", default=30, show_default=True, help="Number of alerts to show")
@click.option("--unresolved", is_flag=True, help="Show unresolved alerts only")
@click.pass_context
def alerts(ctx, limit, unresolved):
    """View security threats and critical anomaly alerts."""
    db: DatabaseManager = ctx.obj["DB"]
    try:
        alerts_list = db.get_alerts(limit=limit, unresolved_only=unresolved)
        db.stop()

        if not alerts_list:
            console.print("[green]No alerts triggered yet! System secure.[/green]")
            return

        table = Table(title="Security & System Alerts", show_header=True, header_style="bold red")
        table.add_column("ID", style="dim")
        table.add_column("Timestamp", style="cyan")
        table.add_column("Alert Type", style="bold yellow")
        table.add_column("Severity", style="bold")
        table.add_column("Message", ratio=2)
        table.add_column("Status")

        for a in alerts_list:
            sev = a["severity"]
            sev_fmt = f"[bold white on red]{sev}[/bold white on red]" if sev == "CRITICAL" else f"[bold yellow]{sev}[/bold yellow]"
            status = "[green]Resolved[/green]" if a["resolved"] == 1 else "[bold red]Unresolved[/bold red]"
            
            table.add_row(
                str(a["id"]),
                a["timestamp"],
                a["alert_type"],
                sev_fmt,
                a["message"],
                status
            )
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Failed to fetch alerts:[/bold red] {e}")

@cli.command()
@click.option("--format", "-f", type=click.Choice(["csv", "json"]), default="csv", show_default=True, help="Output format")
@click.option("--output", "-o", required=True, help="Output file path")
@click.option("--since", help="Start timestamp")
@click.option("--until", help="End timestamp")
@click.option("--level", help="Log level")
@click.option("--source", help="Source file")
@click.option("--program", help="Program")
@click.option("--keyword", help="FTS search keyword")
@click.pass_context
def export(ctx, format, output, since, until, level, source, program, keyword):
    """Export log query results to CSV or JSON formats."""
    db: DatabaseManager = ctx.obj["DB"]
    try:
        logs = db.query_logs(
            since=since,
            until=until,
            log_level=level,
            source_file=source,
            program=program,
            keyword=keyword,
            limit=1000000  # High limit to fetch all matches
        )
        db.stop()

        if not logs:
            console.print("[yellow]No logs found to export.[/yellow]")
            return

        if format == "csv":
            with open(output, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=logs[0].keys())
                writer.writeheader()
                writer.writerows(logs)
            console.print(f"[green]Exported {len(logs)} logs to CSV file: '{output}'[/green]")
        elif format == "json":
            with open(output, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)
            console.print(f"[green]Exported {len(logs)} logs to JSON file: '{output}'[/green]")
    except Exception as e:
        console.print(f"[bold red]Export failed:[/bold red] {e}")

@cli.command()
@click.pass_context
def dashboard(ctx):
    """Launch the interactive terminal dashboard (TUI)."""
    # Make sure DB doesn't process queue asynchronously while dashboard is active
    # (The dashboard will initialize its own dashboard UI cycle)
    ctx.obj["DB"].stop()
    
    from src.cli.dashboard import run_dashboard
    run_dashboard(ctx.obj["CONFIG_PATH"])

def main():
    cli(obj={})

if __name__ == "__main__":
    main()
