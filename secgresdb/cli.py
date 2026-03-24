import argparse
import json
import sys
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box
from rich.text import Text
from .postgre_connector import PostgreConnector
from .scanner import SensitiveDataScanner

console = Console()

def parse_args():
    parser = argparse.ArgumentParser(
        description="SecgresDB - PostgreSQL sensitive data scanner for compliance audits",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
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
    parser.add_argument("--summary-only", action="store_true",
                        help="Only show summary, not detailed table")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress progress output")
    return parser.parse_args()

def load_patterns_info(patterns_file):
    """Load patterns and return a dict mapping pattern name -> regulations list and confidence."""
    with open(patterns_file, 'r') as f:
        data = json.load(f)
    mapping = {}
    for p in data.get('patterns', []):
        mapping[p['name']] = {
            'regulations': p.get('regulations', []),
            'confidence': p.get('confidence', 'low')
        }
    return mapping

def print_summary(results: Dict[str, Dict[str, List[str]]], patterns_info: Dict[str, Any], total_tables: int):
    """Print a summary panel with statistics."""
    total_sensitive_columns = sum(len(cols) for cols in results.values())
    unique_regulations = set()
    confidence_counts = {'high': 0, 'medium': 0, 'low': 0}
    for table_columns in results.values():
        for tags in table_columns.values():
            for tag in tags:
                info = patterns_info.get(tag, {})
                regs = info.get('regulations', [])
                unique_regulations.update(regs)
                conf = info.get('confidence', 'low')
                confidence_counts[conf] += 1
    summary_text = f"""
[bold]Database Scan Summary[/bold]
Total tables scanned: {total_tables}
Tables with sensitive data: {len(results)}
Total sensitive columns found: {total_sensitive_columns}

[bold]Regulations Impacted[/bold]
{', '.join(unique_regulations) if unique_regulations else 'None'}

[bold]Risk Distribution (by confidence)[/bold]
High: {confidence_counts['high']}
Medium: {confidence_counts['medium']}
Low: {confidence_counts['low']}
    """
    panel = Panel(Text.from_markup(summary_text), title="HeimdallDB Scan Report", border_style="green")
    console.print(panel)

def print_detailed_table(results: Dict[str, Dict[str, List[str]]], patterns_info: Dict[str, Any]):
    """Print detailed results using a rich table."""
    if not results:
        console.print("[yellow]No sensitive data found.[/yellow]")
        return

    table = Table(title="Sensitive Data Scan Results", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Table", style="dim")
    table.add_column("Column", style="cyan")
    table.add_column("Data Type", style="white")
    table.add_column("Sensitive Tags", style="magenta")
    table.add_column("Regulations", style="green")
    table.add_column("Confidence", style="yellow")

    for table_name, columns in results.items():
        for col_name, tags in columns.items():
            # For simplicity, we'll combine multiple tags into one row
            # But each column might have multiple tags; we can list them separated by newline
            # Better: create a row per tag? Might get too many rows. For clarity, combine with newlines.
            # We'll use newline-separated strings.
            tags_str = "\n".join(tags)
            regs_set = set()
            confidence_set = set()
            for tag in tags:
                info = patterns_info.get(tag, {})
                regs_set.update(info.get('regulations', []))
                confidence_set.add(info.get('confidence', 'low'))
            regs_str = "\n".join(sorted(regs_set))
            conf_str = "\n".join(sorted(confidence_set))
            table.add_row(table_name, col_name, "text", tags_str, regs_str, conf_str)
    console.print(table)

def print_json_output(results, patterns_info, metadata):
    """Print JSON output with enhanced metadata."""
    # Build enhanced results with regulations and confidence
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
            enhanced["results"][table][col] = tag_details
    console.print(json.dumps(enhanced, indent=2))

def main():
    args = parse_args()
    patterns_info = load_patterns_info(args.patterns)

    connector = PostgreConnector(
        host=args.host,
        port=args.port,
        database=args.database,
        user=args.user,
        password=args.password
    )
    try:
        if not args.quiet:
            console.print("[bold green]HeimdallDB[/bold green] - PostgreSQL Sensitive Data Scanner\n")
        connector.connect()

        # Get tables
        tables = connector.get_tables(args.schema)
        total_tables = len(tables)

        scanner = SensitiveDataScanner(connector, args.patterns)

        results = {}
        # Use progress bar
        if args.quiet:
            for table in tables:
                table_results = scanner.scan_table(table, args.schema, args.sample_limit)
                if table_results:
                    results[table] = table_results
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            ) as progress:
                task = progress.add_task("[cyan]Scanning tables...", total=total_tables)
                for table in tables:
                    table_results = scanner.scan_table(table, args.schema, args.sample_limit)
                    if table_results:
                        results[table] = table_results
                    progress.update(task, advance=1)

        # Prepare metadata for JSON
        metadata = {
            "database": args.database,
            "schema": args.schema,
            "scan_time": None,  # Could add datetime
            "sample_limit": args.sample_limit,
            "patterns_file": args.patterns,
            "total_tables": total_tables,
            "tables_with_sensitive": len(results),
            "total_sensitive_columns": sum(len(cols) for cols in results.values())
        }

        if args.output_format == "json":
            print_json_output(results, patterns_info, metadata)
        else:
            if not args.summary_only:
                print_detailed_table(results, patterns_info)
            print_summary(results, patterns_info, total_tables)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        return 1
    finally:
        connector.disconnect()
    return 0

if __name__ == "__main__":
    sys.exit(main())