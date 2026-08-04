import csv

from secgresdb import report
from secgresdb.scanner import summarize

RESULTS = {
    "customers": {
        "email": [{
            "name": "Email", "description": "", "confidence": "high",
            "regulations": ["GDPR"], "match_count": 2, "sample_count": 2,
            "name_hint_matched": True,
        }],
    }
}
SCHEMA_TYPES = {"customers": {"email": "text"}}
METADATA = {"database": "testdb", "schema": "public", "scan_time": "2026-01-01T00:00:00", "total_tables": 1}


def test_write_csv_produces_one_row_per_finding(tmp_path):
    path = tmp_path / "report.csv"
    report.write_csv(RESULTS, SCHEMA_TYPES, METADATA, str(path))

    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == 1
    assert rows[0]["table"] == "customers"
    assert rows[0]["column"] == "email"
    assert rows[0]["pattern"] == "Email"
    assert rows[0]["confidence"] == "high"
    assert rows[0]["coverage_pct"] == "100.0"


def test_write_html_escapes_and_includes_key_fields(tmp_path):
    path = tmp_path / "report.html"
    summary = summarize(RESULTS)
    report.write_html(RESULTS, SCHEMA_TYPES, METADATA, summary, str(path))

    content = path.read_text(encoding="utf-8")
    assert "customers" in content
    assert "email" in content
    assert "Email" in content
    assert "GDPR" in content
    assert "<script>" not in content


def test_write_html_escapes_malicious_table_name(tmp_path):
    malicious_results = {
        "<script>alert(1)</script>": {
            "col": [{"name": "X", "description": "", "confidence": "low", "regulations": [],
                     "match_count": 1, "sample_count": 1, "name_hint_matched": False}]
        }
    }
    path = tmp_path / "report.html"
    summary = summarize(malicious_results)
    report.write_html(malicious_results, {}, METADATA, summary, str(path))

    content = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content
