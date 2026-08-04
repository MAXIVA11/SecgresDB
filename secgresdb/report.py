"""
File exports for compliance evidence: a flat CSV (for spreadsheets/ticketing
systems) and a self-contained HTML report (for sharing with stakeholders who
don't want to open a CSV). Both are built from the same scan results +
scanner.summarize() output that drives the console summary, so all three
surfaces (console, CSV, HTML) always agree with each other.
"""
import csv
import html
from typing import Dict, Any

_CONFIDENCE_COLOR = {
    "high": "#c0392b",
    "medium": "#b8860b",
    "low": "#2e7d32",
}


def write_csv(results: Dict[str, Dict[str, list]], schema_types: Dict[str, Dict[str, str]],
              metadata: Dict[str, Any], path: str) -> None:
    """Write one row per (table, column, finding) — the flattest useful shape for a DPO to file."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "database", "schema", "table", "column", "data_type",
            "pattern", "confidence", "regulations", "match_count",
            "sample_count", "coverage_pct", "name_hint_matched",
        ])
        for table, columns in results.items():
            for col, findings in columns.items():
                data_type = schema_types.get(table, {}).get(col, "unknown")
                for finding in findings:
                    sample_count = finding["sample_count"]
                    coverage = (finding["match_count"] / sample_count * 100) if sample_count else 0.0
                    writer.writerow([
                        metadata.get("database", ""),
                        metadata.get("schema", ""),
                        table,
                        col,
                        data_type,
                        finding["name"],
                        finding["confidence"],
                        ";".join(finding["regulations"]),
                        finding["match_count"],
                        sample_count,
                        f"{coverage:.1f}",
                        finding.get("name_hint_matched", False),
                    ])


def _badge(confidence: str) -> str:
    color = _CONFIDENCE_COLOR.get(confidence, "#555")
    label = html.escape(confidence.upper())
    return f'<span class="badge" style="background:{color}">{label}</span>'


def write_html(results: Dict[str, Dict[str, list]], schema_types: Dict[str, Dict[str, str]],
               metadata: Dict[str, Any], summary: Dict[str, Any], path: str) -> None:
    """Render a standalone, printable HTML compliance report (no external assets)."""
    db = html.escape(str(metadata.get("database", "")))
    schema = html.escape(str(metadata.get("schema", "")))
    scan_time = html.escape(str(metadata.get("scan_time", "")))
    overall_risk = summary["overall_risk"]
    risk_color = {"High": "#c0392b", "Medium": "#b8860b", "Low": "#2e7d32", "None": "#2e7d32"}.get(overall_risk, "#555")

    regs = summary["unique_regulations"]
    regs_html = "".join(f'<span class="chip">{html.escape(r)}</span>' for r in regs) or '<span class="muted">None identified</span>'

    rows_html = []
    for table, columns in results.items():
        table_esc = html.escape(table)
        for col, findings in columns.items():
            col_esc = html.escape(col)
            data_type = html.escape(schema_types.get(table, {}).get(col, "unknown"))
            for finding in findings:
                sample_count = finding["sample_count"]
                coverage = (finding["match_count"] / sample_count * 100) if sample_count else 0.0
                rows_html.append(f"""
                <tr>
                  <td>{table_esc}</td>
                  <td><code>{col_esc}</code></td>
                  <td>{data_type}</td>
                  <td>{html.escape(finding['name'])}</td>
                  <td>{_badge(finding['confidence'])}</td>
                  <td>{html.escape(', '.join(finding['regulations']) or '—')}</td>
                  <td>{finding['match_count']}/{sample_count} ({coverage:.0f}%)</td>
                </tr>""")
    table_body = "".join(rows_html) if rows_html else (
        '<tr><td colspan="7" class="muted">No sensitive data found.</td></tr>'
    )

    counts = summary["confidence_counts"]

    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecgresDB Compliance Report — {db}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
          background: #f4f5f7; color: #1a1a1a; margin: 0; padding: 2rem; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  .meta {{ color: #555; margin-bottom: 1.5rem; font-size: 0.9rem; }}
  .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
  .card {{ background: #fff; border-radius: 8px; padding: 1rem 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08);
           min-width: 150px; flex: 1; }}
  .card .label {{ font-size: 0.75rem; text-transform: uppercase; color: #777; letter-spacing: 0.03em; }}
  .card .value {{ font-size: 1.6rem; font-weight: 700; margin-top: 0.25rem; }}
  .risk-value {{ color: {risk_color}; }}
  .chip {{ display: inline-block; background: #eef1f5; border-radius: 999px; padding: 0.15rem 0.7rem;
           margin: 0.15rem; font-size: 0.8rem; }}
  .badge {{ color: #fff; border-radius: 4px; padding: 0.15rem 0.5rem; font-size: 0.72rem; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden;
           box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  th, td {{ text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid #eee; font-size: 0.88rem; }}
  th {{ background: #fafbfc; font-size: 0.75rem; text-transform: uppercase; color: #666; letter-spacing: 0.03em; }}
  code {{ background: #f1f2f4; padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.85em; }}
  .muted {{ color: #999; }}
  h2 {{ font-size: 1.1rem; margin: 1.75rem 0 0.75rem; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>SecgresDB Compliance Scan Report</h1>
  <div class="meta">Database <strong>{db}</strong> · schema <strong>{schema}</strong> · scanned {scan_time}</div>

  <div class="cards">
    <div class="card"><div class="label">Overall Risk</div><div class="value risk-value">{html.escape(overall_risk)}</div></div>
    <div class="card"><div class="label">Tables Scanned</div><div class="value">{metadata.get('total_tables', 0)}</div></div>
    <div class="card"><div class="label">Tables With Findings</div><div class="value">{summary['tables_with_sensitive_data']}</div></div>
    <div class="card"><div class="label">Sensitive Columns</div><div class="value">{summary['total_sensitive_columns']}</div></div>
    <div class="card"><div class="label">High / Medium / Low</div>
      <div class="value">{counts['high']} / {counts['medium']} / {counts['low']}</div></div>
  </div>

  <h2>Regulations Impacted</h2>
  <div>{regs_html}</div>

  <h2>Findings</h2>
  <table>
    <thead>
      <tr><th>Table</th><th>Column</th><th>Data Type</th><th>Pattern</th><th>Confidence</th><th>Regulations</th><th>Coverage</th></tr>
    </thead>
    <tbody>{table_body}</tbody>
  </table>
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
