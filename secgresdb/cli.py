import argparse
import json
import sys
from datetime import datetime
from typing import Dict, List, Any
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box
from rich.text import Text
from rich.json import JSON
from .postgre_connector import PostgreConnector
from .scanner import SensitiveDataScanner

# Initialize rich console
console = Console()


def parse_args():
    parser = argparse.ArgumentParser(
        description="SecgresDB - PostgreSQL sensitive data scanner for compliance audits",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
[Examples]
  python main.py --host localhost --port 5432 --database mydb --user postgres --password secret
  python main.py --host localhost --database mydb --user postgres --password secret --output-format json
  python main.py --host localhost --database mydb --user postgres --password secret --schema myapp --sample-limit 200 --summary-only
"""
    )
    parser.add_argument("--host", required=True, help="Database host")
    parser.add_argument("--port", type=int, default=5432, help="Database port (default: 5432)")
    parser.add_argument("--database", required=True, help="Database name")
    parser.add_argument("--user", required=True, help="Database user")
    parser.add_argument("--password", required=True, help="Database password")
    parser.add_argument("--schema", default="public", help="Schema to scan (default: public)")
    parser.add_argument("--sample-limit", type=int, default=100,
                        help="Number of sample values per column (default: 100)")
    parser.add_argument("--patterns", default="config/sensitive_patterns.json",
                        help="Path to patterns JSON file (default: config/sensitive_patterns.json)")
    parser.add_argument("--output-format", choices=["table", "json"], default="table",
                        help="Output format (default: table)")
    parser.add_argument("--summary-only", action="store_true", help="Only show summary, not detailed table")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output and banners")
    return parser.parse_args()


def load_patterns_info(patterns_file: str) -> Dict[str, Any]:
    """Load patterns and return a dict mapping pattern name -> regulations list and confidence."""
    try:
        with open(patterns_file, 'r') as f:
            data = json.load(f)
        mapping = {}
        for p in data.get('patterns', []):
            mapping[p['name']] = {
                'regulations': p.get('regulations', []),
                'confidence': p.get('confidence', 'low')
            }
        return mapping
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] Patterns file not found at '{patterns_file}'")
        sys.exit(1)


def get_column_types(connector: PostgreConnector, schema_name: str, table_name: str) -> Dict[str, str]:
    """Fetch accurate data types for columns in a specific table using information_schema."""
    try:
        # Assumes connector has the underlying DB connection exposed as .connection
        # If your connector uses a different property name, update 'connection' below.
        if hasattr(connector, 'connection') and connector.connection:
            cursor = connector.connection.cursor()
            cursor.execute(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = %s",
                (schema_name, table_name)
            )
            types = {row[0]: row[1] for row in cursor.fetchall()}
            cursor.close()
            return types
    except Exception as e:
        pass
    return {}


def format_confidence(confidence: str) -> str:
    """Return a color-coded string based on confidence level."""
    conf_lower = confidence.lower()
    if conf_lower == "high":
        return f"[bold red]{confidence.upper()}[/bold red]"
    elif conf_lower == "medium":
        return f"[bold yellow]{confidence.upper()}[/bold yellow]"
    return f"[bold green]{confidence.upper()}[/bold green]"


def print_summary(results: Dict[str, Dict[str, List[str]]], patterns_info: Dict[str, Any], total_tables: int):
    """Print a polished dashboard-style summary panel."""
    total_sensitive_columns = sum(len(cols) for cols in results.values())
    unique_regulations = set()
    confidence_counts = {'high': 0, 'medium': 0, 'low': 0}

    for table_columns in results.values():
        for tags in table_columns.values():
            for tag in tags:
                info = patterns_info.get(tag, {})
                unique_regulations.update(info.get('regulations', []))
                conf = info.get('confidence', 'low').lower()
                if conf in confidence_counts:
                    confidence_counts[conf] += 1

    stats_table = Table.grid(padding=(0, 2))
    stats_table.add_row("[cyan]Total tables scanned:[/cyan]", str(total_tables))
    stats_table.add_row("[cyan]Tables with sensitive data:[/cyan]", str(len(results)))
    stats_table.add_row("[cyan]Total sensitive columns:[/cyan]", str(total_sensitive_columns))

    risk_table = Table.grid(padding=(0, 2))
    risk_table.add_row("[bold red]High Risk:[/bold red]", str(confidence_counts['high']))
    risk_table.add_row("[bold yellow]Medium Risk:[/bold yellow]", str(confidence_counts['medium']))
    risk_table.add_row("[bold green]Low Risk:[/bold green]", str(confidence_counts['low']))

    regs_text = ", ".join(unique_regulations) if unique_regulations else "None identified"

    summary_group = Group(
        Text("Scan Statistics", style="bold underline"),
        stats_table,
        Text("\nRisk Distribution (by Confidence)", style="bold underline"),
        risk_table,
        Text("\nRegulations Impacted", style="bold underline"),
        Text(regs_text, style="magenta")
    )

    panel = Panel(summary_group, title="[bold]SecgresDB Scan Report[/bold]", border_style="cyan", padding=(1, 2))
    console.print(panel)


def print_detailed_table(results: Dict[str, Dict[str, List[str]]], patterns_info: Dict[str, Any],
                         schema_types: Dict[str, Dict[str, str]]):
    """Print detailed results using a rich, color-coded table with real data types."""
    if not results:
        console.print("\n[bold green]✓ No sensitive data found.[/bold green]\n")
        return

    table = Table(
        title="Sensitive Data Map",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        title_justify="left"
    )

    table.add_column("Table", style="dim")
    table.add_column("Column", style="cyan bold")
    table.add_column("Data Type", style="white")
    table.add_column("Sensitive Tags", style="magenta")
    table.add_column("Regulations", style="green")
    table.add_column("Confidence")

    for table_name, columns in results.items():
        for col_name, tags in columns.items():
            regs_set = set()
            confidence_set = set()

            for tag in tags:
                info = patterns_info.get(tag, {})
                regs_set.update(info.get('regulations', []))
                confidence_set.add(info.get('confidence', 'low'))

            tags_str = "\n".join(f"• {t}" for t in tags)
            regs_str = "\n".join(sorted(regs_set))

            sorted_conf = sorted(list(confidence_set),
                                 key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.lower(), 3))
            conf_str = "\n".join(format_confidence(c) for c in sorted_conf)

            # Fetch the dynamic data type, default to "Unknown" if it couldn't be mapped
            col_type = schema_types.get(table_name, {}).get(col_name, "Unknown")

            table.add_row(table_name, col_name, col_type, tags_str, regs_str, conf_str)
            table.add_section()

    console.print()
    console.print(table)


def print_json_output(results: Dict, patterns_info: Dict, metadata: Dict, schema_types: Dict):
    """Print syntax-highlighted JSON output including data types."""
    enhanced = {
        "metadata": metadata,
        "results": {}
    }
    for table, columns in results.items():
        enhanced["results"][table] = {}
        for col, tags in columns.items():
            tag_details = []
            for tag in tags:
                info = patterns_info.get(tag, {})
                tag_details.append({
                    "name": tag,
                    "regulations": info.get('regulations', []),
                    "confidence": info.get('confidence', 'low')
                })
            enhanced["results"][table][col] = {
                "data_type": schema_types.get(table, {}).get(col, "Unknown"),
                "findings": tag_details
            }

    json_str = json.dumps(enhanced, indent=2)
    console.print(JSON(json_str))


def print_banner():
    """Print an eye-catching CLI banner."""
    banner = """
  ____                            ____  ____  
 / ___|  ___  ___ __ _ _ __ ___  |  _ \\| __ ) 
 \\___ \\ / _ \\/ __/ _` | '__/ _ \\ | | | |  _ \\ 
  ___) |  __/ (_| (_| | | |  __/ | |_| | |_) |
 |____/ \\___|\\___\\__, |_|  \\___| |____/|____/ 
                 |___/                        
    """
    console.print(Text(banner, style="bold cyan"), justify="left")
    console.print("[dim]PostgreSQL Sensitive Data Scanner[/dim]\n")


def main():
    args = parse_args()
    patterns_info = load_patterns_info(args.patterns)

    if not args.quiet and args.output_format != "json":
        print_banner()

    connector = PostgreConnector(
        host=args.host,
        port=args.port,
        database=args.database,
        user=args.user,
        password=args.password
    )

    try:
        connector.connect()
        tables = connector.get_tables(args.schema)
        total_tables = len(tables)

        if total_tables == 0:
            console.print(f"[yellow]Warning:[/yellow] No tables found in schema '{args.schema}'.")
            return 0

        scanner = SensitiveDataScanner(connector, args.patterns)
        results = {}
        schema_types = {}

        if args.quiet or args.output_format == "json":
            # Silent execution
            for table in tables:
                table_results = scanner.scan_table(table, args.schema, args.sample_limit)
                if table_results:
                    results[table] = table_results
                    schema_types[table] = get_column_types(connector, args.schema, table)
        else:
            # Interactive Progress Bar
            with Progress(
                    SpinnerColumn(spinner_name="dots", style="bold cyan"),
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(bar_width=40, style="blue", complete_style="cyan"),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("•"),
                    TextColumn("[dim]Scanning: {task.fields[current_table]}[/dim]"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
            ) as progress:

                task = progress.add_task("Analyzing Database...", total=total_tables, current_table="Initializing...")

                for table in tables:
                    progress.update(task, current_table=table)
                    table_results = scanner.scan_table(table, args.schema, args.sample_limit)
                    if table_results:
                        results[table] = table_results
                        # Fetch the data types for the table now that we found sensitive data
                        schema_types[table] = get_column_types(connector, args.schema, table)
                    progress.advance(task)

        metadata = {
            "database": args.database,
            "schema": args.schema,
            "scan_time": datetime.now().isoformat(),
            "sample_limit": args.sample_limit,
            "patterns_file": args.patterns,
            "total_tables": total_tables,
            "tables_with_sensitive": len(results),
            "total_sensitive_columns": sum(len(cols) for cols in results.values())
        }

        if args.output_format == "json":
            print_json_output(results, patterns_info, metadata, schema_types)
        else:
            if not args.summary_only:
                print_detailed_table(results, patterns_info, schema_types)
            print_summary(results, patterns_info, total_tables)

    except Exception as e:
        console.print(f"\n[bold white on red] ERROR [/bold white on red] {e}")
        return 1
    finally:
        connector.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(main())