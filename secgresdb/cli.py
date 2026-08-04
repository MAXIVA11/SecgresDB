import argparse
import fnmatch
import getpass
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Set, Tuple

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box
from rich.text import Text

from . import __version__
from .postgre_connector import PostgreConnector
from .scanner import SensitiveDataScanner, summarize

console = Console(
    # Rich's "legacy Windows" console writer talks to the Win32 console API
    # directly and encodes with the active codepage using strict error
    # handling - any character outside it (even Rich's own truncation
    # ellipsis) raises UnicodeEncodeError and crashes the whole CLI on an
    # interactive terminal that isn't running a UTF-8 codepage. Forcing this
    # off routes everything through plain ANSI escapes over stdout instead,
    # which Python's own console I/O layer handles safely on modern Windows.
    legacy_windows=False,
)

# Settings that fall back to a built-in default if neither the CLI nor the
# config file specify them. Anything not listed here must come from the user.
_DEFAULTS = {
    "port": 5432,
    "schema": "public",
    "sample_limit": 100,
    "patterns": "config/sensitive_patterns.json",
    "sslmode": "prefer",
    "connect_timeout": 10,
    "output_format": "table",
}
_LIST_FIELDS = ["exclude_tables", "include_tables", "exclude_columns"]
_REQUIRED_FIELDS = ["host", "database", "user"]


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecgresDB - PostgreSQL sensitive data scanner for compliance audits",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
[Examples]
  python main.py --host localhost --database mydb --user postgres
  PGPASSWORD=secret python main.py --host localhost --database mydb --user postgres --output-format json
  python main.py --config myscan.json --output-format html --output-file report.html
  python main.py --host localhost --database mydb --user postgres --all-schemas --exclude-table 'pg_*' --fail-on-high
"""
    )
    parser.add_argument("--host", default=None, help="Database host")
    parser.add_argument("--port", type=int, default=None, help="Database port (default: 5432)")
    parser.add_argument("--database", default=None, help="Database name")
    parser.add_argument("--user", default=None, help="Database user")
    parser.add_argument("--password", default=None,
                        help="Database password. Insecure (visible in shell history/process list) - "
                             "prefer the PGPASSWORD env var, or omit this flag to be prompted interactively.")
    parser.add_argument("--sslmode", default=None,
                        choices=["disable", "allow", "prefer", "require", "verify-ca", "verify-full"],
                        help="libpq SSL mode (default: prefer)")
    parser.add_argument("--connect-timeout", type=int, default=None, help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--schema", default=None, help="Schema to scan (default: public)")
    parser.add_argument("--all-schemas", action="store_true", help="Scan every non-system schema (overrides --schema)")
    parser.add_argument("--sample-limit", type=int, default=None,
                        help="Number of sample rows per table (default: 100)")
    parser.add_argument("--patterns", default=None,
                        help="Path to patterns JSON file (default: config/sensitive_patterns.json)")
    parser.add_argument("--config", default=None,
                        help="Path to a JSON config file providing defaults for the options above. "
                             "CLI flags always win over the config file. A 'password' key, if present, is ignored.")
    parser.add_argument("--exclude-table", dest="exclude_tables", action="append", default=None, metavar="GLOB",
                        help="Exclude tables matching this glob, e.g. 'audit_*' (repeatable)")
    parser.add_argument("--include-table", dest="include_tables", action="append", default=None, metavar="GLOB",
                        help="Only scan tables matching this glob (repeatable). Applied before --exclude-table.")
    parser.add_argument("--exclude-column", dest="exclude_columns", action="append", default=None,
                        metavar="[TABLE.]COLUMN",
                        help="Exclude a column by name, or 'table.column' for a specific table (repeatable)")
    parser.add_argument("--output-format", choices=["table", "json", "csv", "html"], default=None,
                        help="Output format (default: table)")
    parser.add_argument("--output-file", default=None,
                        help="Write the report to this path (csv/html get a timestamped default name if omitted)")
    parser.add_argument("--summary-only", action="store_true", help="Show only summary, not detailed table")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output and banners")
    parser.add_argument("--fail-on-high", action="store_true",
                        help="Exit with status 2 if any high-confidence finding is present (useful for CI gates)")
    parser.add_argument("--version", action="version", version=f"SecgresDB {__version__}")
    return parser.parse_args(argv)


def load_config(path: str) -> Dict[str, Any]:
    """Load a JSON config file. A 'password' key is always dropped - secrets don't belong in config files on disk."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] Config file not found at '{path}'")
        sys.exit(1)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid JSON in config file '{path}': {e}")
        sys.exit(1)

    if "password" in data:
        console.print("[yellow]Warning:[/yellow] Ignoring 'password' in config file - "
                      "use the PGPASSWORD env var or --password instead.")
        data.pop("password")
    return data


def apply_config(args: argparse.Namespace, config: Dict[str, Any]) -> argparse.Namespace:
    """Fill in any CLI option left unset (None / empty list) from the config file."""
    for key, value in config.items():
        if not hasattr(args, key):
            console.print(f"[yellow]Warning:[/yellow] Unknown config key '{key}' ignored")
            continue
        current = getattr(args, key)
        if key in _LIST_FIELDS:
            if not current:
                setattr(args, key, value)
        elif current is None:
            setattr(args, key, value)
    return args


def apply_defaults(args: argparse.Namespace) -> argparse.Namespace:
    for key, value in _DEFAULTS.items():
        if getattr(args, key, None) is None:
            setattr(args, key, value)
    for key in _LIST_FIELDS:
        if getattr(args, key, None) is None:
            setattr(args, key, [])
    return args


def validate_required(args: argparse.Namespace) -> None:
    missing = [f for f in _REQUIRED_FIELDS if not getattr(args, f, None)]
    if missing:
        flags = ", ".join(f"--{m}" for m in missing)
        console.print(f"[bold red]Error:[/bold red] missing required setting(s): {flags} "
                      f"(supply via CLI flag or --config file)")
        sys.exit(2)


def resolve_password(args: argparse.Namespace) -> str:
    if args.password:
        return args.password

    env_password = os.environ.get("PGPASSWORD") or os.environ.get("SECGRESDB_PASSWORD")
    if env_password:
        return env_password

    if not sys.stdin.isatty():
        console.print("[bold red]Error:[/bold red] No password available. "
                      "Pass --password, set PGPASSWORD, or run in an interactive terminal.")
        sys.exit(1)

    try:
        return getpass.getpass(f"Password for {args.user}@{args.host}: ")
    except (EOFError, KeyboardInterrupt):
        console.print("\n[bold red]Error:[/bold red] Password entry cancelled.")
        sys.exit(1)


def setup_logging(quiet: bool) -> None:
    logging.basicConfig(level=logging.WARNING if quiet else logging.INFO, format="%(message)s")


def filter_tables(tables: List[str], include_globs: List[str], exclude_globs: List[str]) -> List[str]:
    if include_globs:
        tables = [t for t in tables if any(fnmatch.fnmatch(t, g) for g in include_globs)]
    if exclude_globs:
        tables = [t for t in tables if not any(fnmatch.fnmatch(t, g) for g in exclude_globs)]
    return tables


def build_exclude_columns(entries: List[str], table: str) -> Set[str]:
    """'colname' excludes that column everywhere; 'table.colname' excludes it only for that table."""
    excluded = set()
    for entry in entries:
        if "." in entry:
            table_part, col_part = entry.split(".", 1)
            if table_part in (table, "*"):
                excluded.add(col_part)
        else:
            excluded.add(entry)
    return excluded


def resolve_patterns_path(path: str) -> str:
    """
    Resolve the patterns file relative to the current working directory first
    (the documented usage); if that misses and the caller left the option at
    its default, fall back to the copy shipped alongside the installed
    package so `secgresdb` works from any cwd under an editable/dev install.
    """
    if os.path.exists(path):
        return path
    if path == _DEFAULTS["patterns"]:
        bundled = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "config", "sensitive_patterns.json"))
        if os.path.exists(bundled):
            return bundled
    return path


def default_output_filename(database: str, ext: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"secgresdb_report_{database}_{timestamp}.{ext}"


def column_type_map(connector: PostgreConnector, schema: str, table: str) -> Dict[str, str]:
    return {c["name"]: c["data_type"] for c in connector.get_columns(table, schema)}


def format_confidence(confidence: str) -> str:
    conf_lower = confidence.lower()
    if conf_lower == "high":
        return f"[bold red]{confidence.upper()}[/bold red]"
    elif conf_lower == "medium":
        return f"[bold yellow]{confidence.upper()}[/bold yellow]"
    return f"[bold green]{confidence.upper()}[/bold green]"


def print_summary(summary: Dict[str, Any], total_tables: int) -> None:
    stats_table = Table.grid(padding=(0, 2))
    stats_table.add_row("[cyan]Total tables scanned:[/cyan]", str(total_tables))
    stats_table.add_row("[cyan]Tables with sensitive data:[/cyan]", str(summary["tables_with_sensitive_data"]))
    stats_table.add_row("[cyan]Total sensitive columns:[/cyan]", str(summary["total_sensitive_columns"]))

    counts = summary["confidence_counts"]
    risk_table = Table.grid(padding=(0, 2))
    risk_table.add_row("[bold red]High Risk:[/bold red]", str(counts["high"]))
    risk_table.add_row("[bold yellow]Medium Risk:[/bold yellow]", str(counts["medium"]))
    risk_table.add_row("[bold green]Low Risk:[/bold green]", str(counts["low"]))

    regs_text = ", ".join(summary["unique_regulations"]) if summary["unique_regulations"] else "None identified"

    overall_risk = summary["overall_risk"]
    risk_style = {"High": "bold red", "Medium": "bold yellow", "Low": "bold green", "None": "bold green"}.get(
        overall_risk, "bold white")

    summary_group = Group(
        Text(f"Overall Risk: {overall_risk}", style=risk_style),
        Text("\nScan Statistics", style="bold underline"),
        stats_table,
        Text("\nRisk Distribution (by Confidence)", style="bold underline"),
        risk_table,
        Text("\nRegulations Impacted", style="bold underline"),
        Text(regs_text, style="magenta"),
    )

    panel = Panel(summary_group, title="[bold]SecgresDB Scan Report[/bold]", border_style="cyan", padding=(1, 2))
    console.print(panel)


def print_detailed_table(results: Dict[str, Dict[str, List[Dict[str, Any]]]],
                         schema_types: Dict[str, Dict[str, str]]) -> None:
    if not results:
        console.print("\n[bold green]No sensitive data found.[/bold green]\n")
        return

    table = Table(
        title="Sensitive Data Map",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
        title_justify="left",
    )
    table.add_column("Table", style="dim")
    table.add_column("Column", style="cyan bold")
    table.add_column("Data Type", style="white")
    table.add_column("Sensitive Tags", style="magenta")
    table.add_column("Regulations", style="green")
    table.add_column("Confidence")

    for table_name, columns in results.items():
        for col_name, findings in columns.items():
            regs_set = set()
            for finding in findings:
                regs_set.update(finding["regulations"])

            tags_str = "\n".join(f"- {f['name']} ({f['match_count']}/{f['sample_count']})" for f in findings)
            regs_str = "\n".join(sorted(regs_set))

            sorted_findings = sorted(findings, key=lambda f: {"high": 0, "medium": 1, "low": 2}.get(f["confidence"], 3))
            conf_str = "\n".join(format_confidence(f["confidence"]) for f in sorted_findings)

            col_type = schema_types.get(table_name, {}).get(col_name, "Unknown")
            table.add_row(table_name, col_name, col_type, tags_str, regs_str, conf_str)
            table.add_section()

    console.print()
    console.print(table)


def build_json_payload(results: Dict[str, Dict[str, List[Dict[str, Any]]]],
                       schema_types: Dict[str, Dict[str, str]],
                       metadata: Dict[str, Any], summary: Dict[str, Any]) -> Dict[str, Any]:
    output_results = {}
    for table_name, columns in results.items():
        output_results[table_name] = {}
        for col_name, findings in columns.items():
            output_results[table_name][col_name] = {
                "data_type": schema_types.get(table_name, {}).get(col_name, "Unknown"),
                "findings": findings,
            }
    return {"metadata": metadata, "summary": summary, "results": output_results}


def print_json_output(payload: Dict[str, Any]) -> None:
    """
    Write plain, machine-parseable JSON to stdout. Deliberately bypasses
    Rich's JSON renderable: it word-wraps string values to the console width,
    which injects literal newlines into string literals and produces invalid
    JSON as soon as it's piped into anything (jq, a file, another program).
    """
    sys.stdout.write(json.dumps(payload, indent=2, default=str))
    sys.stdout.write("\n")


def print_banner() -> None:
    banner = """
  ____                            ____  ____
 / ___|  ___  ___ __ _ _ __ ___  |  _ \\| __ )
 \\___ \\ / _ \\/ __/ _` | '__/ _ \\ | | | |  _ \\
  ___) |  __/ (_| (_| | | |  __/ | |_| | |_) |
 |____/ \\___|\\___\\__, |_|  \\___| |____/|____/
                 |___/
    """
    console.print(Text(banner, style="bold cyan"), justify="left")
    console.print(f"[dim]PostgreSQL Sensitive Data Scanner  -  v{__version__}[/dim]\n")


def collect_targets(connector: PostgreConnector, args: argparse.Namespace) -> List[Tuple[str, str]]:
    """Return the (schema, table) pairs to scan, after --all-schemas/--include-table/--exclude-table filtering."""
    schemas = connector.get_schemas() if args.all_schemas else [args.schema]
    targets = []
    for schema in schemas:
        tables = filter_tables(connector.get_tables(schema), args.include_tables, args.exclude_tables)
        for table in tables:
            targets.append((schema, table))
    return targets


def result_key(schema: str, table: str, multi_schema: bool) -> str:
    return f"{schema}.{table}" if multi_schema else table


def main(argv=None) -> int:
    args = parse_args(argv)

    if args.config:
        args = apply_config(args, load_config(args.config))
    args = apply_defaults(args)
    validate_required(args)

    setup_logging(args.quiet)

    if not args.quiet and args.output_format == "table":
        print_banner()

    # Validate the patterns file before we ever touch the network - no point
    # opening a DB connection just to fail on a typo'd --patterns path.
    try:
        scanner = SensitiveDataScanner(None, resolve_patterns_path(args.patterns))
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] Patterns file not found at '{args.patterns}'")
        return 1
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid JSON in patterns file '{args.patterns}': {e}")
        return 1

    password = resolve_password(args)

    connector = PostgreConnector(
        host=args.host,
        port=args.port,
        database=args.database,
        user=args.user,
        password=password,
        sslmode=args.sslmode,
        connect_timeout=args.connect_timeout,
    )

    try:
        connector.connect()
    except ConnectionError as e:
        console.print(f"\n[bold white on red] ERROR [/bold white on red] {e}")
        return 1

    scanner.connector = connector

    try:
        targets = collect_targets(connector, args)
        total_tables = len(targets)
        multi_schema = args.all_schemas

        if total_tables == 0:
            console.print("[yellow]Warning:[/yellow] No tables matched the scan criteria.")
            return 0

        results: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        schema_types: Dict[str, Dict[str, str]] = {}

        def scan_one(schema: str, table: str):
            key = result_key(schema, table, multi_schema)
            exclude_cols = build_exclude_columns(args.exclude_columns, table)
            table_results = scanner.scan_table(table, schema, args.sample_limit, exclude_cols)
            if table_results:
                results[key] = table_results
                schema_types[key] = column_type_map(connector, schema, table)

        if args.quiet or args.output_format in ("json", "csv", "html"):
            for schema, table in targets:
                scan_one(schema, table)
        else:
            with Progress(
                    SpinnerColumn(spinner_name="dots", style="bold cyan"),
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(bar_width=40, style="blue", complete_style="cyan"),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("-"),
                    TextColumn("[dim]Scanning: {task.fields[current_table]}[/dim]"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
            ) as progress:
                task = progress.add_task("Analyzing Database...", total=total_tables, current_table="Initializing...")
                for schema, table in targets:
                    progress.update(task, current_table=result_key(schema, table, multi_schema))
                    scan_one(schema, table)
                    progress.advance(task)

        summary = summarize(results)
        metadata = {
            "database": args.database,
            "schema": "ALL" if args.all_schemas else args.schema,
            "scan_time": datetime.now().isoformat(),
            "sample_limit": args.sample_limit,
            "patterns_file": args.patterns,
            "total_tables": total_tables,
            "tables_with_sensitive": summary["tables_with_sensitive_data"],
            "total_sensitive_columns": summary["total_sensitive_columns"],
        }

        if args.output_format == "json":
            payload = build_json_payload(results, schema_types, metadata, summary)
            if args.output_file:
                with open(args.output_file, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, default=str)
                if not args.quiet:
                    console.print(f"[green]Done:[/green] JSON report written to {args.output_file}")
            else:
                print_json_output(payload)
        elif args.output_format == "csv":
            from . import report
            path = args.output_file or default_output_filename(args.database, "csv")
            report.write_csv(results, schema_types, metadata, path)
            console.print(f"[green]Done:[/green] CSV report written to {path}")
            if not args.quiet:
                print_summary(summary, total_tables)
        elif args.output_format == "html":
            from . import report
            path = args.output_file or default_output_filename(args.database, "html")
            report.write_html(results, schema_types, metadata, summary, path)
            console.print(f"[green]Done:[/green] HTML report written to {path}")
            if not args.quiet:
                print_summary(summary, total_tables)
        else:
            if not args.summary_only:
                print_detailed_table(results, schema_types)
            print_summary(summary, total_tables)

        if args.fail_on_high and summary["confidence_counts"]["high"] > 0:
            return 2
        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        return 1
    except Exception as e:
        console.print(f"\n[bold white on red] ERROR [/bold white on red] {e}")
        return 1
    finally:
        connector.disconnect()


if __name__ == "__main__":
    sys.exit(main())
