from secgresdb.scanner import SensitiveDataScanner, summarize


def _col(name, data_type="text"):
    return {"name": name, "data_type": data_type, "nullable": True}


def test_detects_email_and_boosts_confidence_from_name_hint(make_connector, patterns_path):
    connector = make_connector(
        columns=[_col("email")],
        samples={"email": ["alice@example.com", "bob@example.com"]},
    )
    scanner = SensitiveDataScanner(connector, patterns_path)
    results = scanner.scan_table("customers")

    assert "email" in results
    finding = next(f for f in results["email"] if f["name"] == "Email")
    assert finding["confidence"] == "high"
    assert finding["match_count"] == 2
    assert finding["sample_count"] == 2
    assert "GDPR" in finding["regulations"]


def test_noisy_pattern_stays_silent_without_name_hint(make_connector, patterns_path):
    connector = make_connector(
        columns=[_col("random_number")],
        samples={"random_number": ["12345", "67890", "54321"]},
    )
    scanner = SensitiveDataScanner(connector, patterns_path)
    results = scanner.scan_table("t")

    assert results == {}


def test_noisy_pattern_fires_when_column_name_corroborates(make_connector, patterns_path):
    connector = make_connector(
        columns=[_col("zip_code")],
        samples={"zip_code": ["12345", "90210"]},
    )
    scanner = SensitiveDataScanner(connector, patterns_path)
    results = scanner.scan_table("t")

    finding = next(f for f in results["zip_code"] if f["name"] == "US ZIP Code")
    # base confidence is "low"; a corroborating column name bumps it one level
    assert finding["confidence"] == "medium"


def test_credit_card_validator_rejects_luhn_failure(make_connector, patterns_path):
    connector = make_connector(
        columns=[_col("credit_card")],
        samples={"credit_card": ["4111111111111112"]},  # Visa-shaped, bad checksum
    )
    scanner = SensitiveDataScanner(connector, patterns_path)
    results = scanner.scan_table("t")

    assert results == {}


def test_credit_card_validator_accepts_valid_luhn(make_connector, patterns_path):
    connector = make_connector(
        columns=[_col("credit_card")],
        samples={"credit_card": ["4111111111111111"]},  # canonical valid Visa test number
    )
    scanner = SensitiveDataScanner(connector, patterns_path)
    results = scanner.scan_table("t")

    assert "credit_card" in results
    assert any(f["name"] == "Credit Card - Visa" for f in results["credit_card"])


def test_non_scannable_column_types_are_skipped(make_connector, patterns_path):
    connector = make_connector(
        columns=[_col("is_active", "boolean")],
        samples={"is_active": ["alice@example.com"]},  # would match if scanned
    )
    scanner = SensitiveDataScanner(connector, patterns_path)
    results = scanner.scan_table("t")

    assert results == {}


def test_exclude_columns_skips_named_column(make_connector, patterns_path):
    connector = make_connector(
        columns=[_col("email")],
        samples={"email": ["alice@example.com"]},
    )
    scanner = SensitiveDataScanner(connector, patterns_path)
    results = scanner.scan_table("t", exclude_columns={"email"})

    assert results == {}


def test_summarize_computes_overall_risk_and_counts():
    results = {
        "customers": {
            "email": [{"name": "Email", "confidence": "high", "regulations": ["GDPR"]}],
            "zip": [{"name": "ZIP", "confidence": "low", "regulations": []}],
        },
        "logs": {
            "ip": [{"name": "IP", "confidence": "medium", "regulations": ["GDPR"]}],
        },
    }
    summary = summarize(results)

    assert summary["confidence_counts"] == {"high": 1, "medium": 1, "low": 1}
    assert summary["overall_risk"] == "High"
    assert summary["unique_regulations"] == ["GDPR"]
    assert summary["tables_with_sensitive_data"] == 2
    assert summary["total_sensitive_columns"] == 3
    assert summary["table_risk"] == {"customers": "high", "logs": "medium"}


def test_summarize_handles_empty_results():
    summary = summarize({})
    assert summary["overall_risk"] == "None"
    assert summary["confidence_counts"] == {"high": 0, "medium": 0, "low": 0}
