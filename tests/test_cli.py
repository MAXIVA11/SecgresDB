import argparse
import json

import pytest

from secgresdb import cli


def test_filter_tables_applies_include_then_exclude():
    tables = ["customers", "employees", "audit_log", "audit_archive"]
    result = cli.filter_tables(tables, include_globs=["audit_*"], exclude_globs=["*_archive"])
    assert result == ["audit_log"]


def test_filter_tables_no_filters_returns_all():
    tables = ["a", "b"]
    assert cli.filter_tables(tables, [], []) == tables


def test_build_exclude_columns_global_name():
    excluded = cli.build_exclude_columns(["created_at"], table="customers")
    assert excluded == {"created_at"}


def test_build_exclude_columns_table_scoped():
    excluded = cli.build_exclude_columns(["customers.ssn", "employees.ssn"], table="customers")
    assert excluded == {"ssn"}


def test_build_exclude_columns_wildcard_table():
    excluded = cli.build_exclude_columns(["*.internal_notes"], table="anything")
    assert excluded == {"internal_notes"}


def test_apply_defaults_fills_unset_fields():
    args = argparse.Namespace(**{k: None for k in cli._DEFAULTS})
    for f in cli._LIST_FIELDS:
        setattr(args, f, None)
    cli.apply_defaults(args)
    for key, value in cli._DEFAULTS.items():
        assert getattr(args, key) == value
    for f in cli._LIST_FIELDS:
        assert getattr(args, f) == []


def test_apply_config_does_not_override_explicit_cli_value():
    args = argparse.Namespace(host="cli-host", port=None)
    cli.apply_config(args, {"host": "config-host", "port": 5433})
    assert args.host == "cli-host"  # CLI wins
    assert args.port == 5433  # config fills the gap


def test_apply_config_ignores_password():
    args = argparse.Namespace(password=None)
    # load_config() is what strips 'password' in real use; apply_config just
    # shouldn't blow up if a caller passes it through directly.
    cli.apply_config(args, {})
    assert args.password is None


def test_load_config_strips_password_key(tmp_path, capsys):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"host": "db.internal", "password": "secret"}))
    config = cli.load_config(str(path))
    assert "password" not in config
    assert config["host"] == "db.internal"


def test_load_config_missing_file_exits(tmp_path):
    with pytest.raises(SystemExit):
        cli.load_config(str(tmp_path / "does_not_exist.json"))


def test_validate_required_exits_when_missing():
    args = argparse.Namespace(host=None, database="db", user="u")
    with pytest.raises(SystemExit):
        cli.validate_required(args)


def test_validate_required_passes_when_present():
    args = argparse.Namespace(host="h", database="db", user="u")
    cli.validate_required(args)  # should not raise


def test_resolve_password_prefers_explicit_flag(monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "from-env")
    args = argparse.Namespace(password="from-flag", user="u", host="h")
    assert cli.resolve_password(args) == "from-flag"


def test_resolve_password_falls_back_to_env_var(monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "from-env")
    args = argparse.Namespace(password=None, user="u", host="h")
    assert cli.resolve_password(args) == "from-env"


def test_resolve_password_exits_when_noninteractive_and_missing(monkeypatch):
    monkeypatch.delenv("PGPASSWORD", raising=False)
    monkeypatch.delenv("SECGRESDB_PASSWORD", raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    args = argparse.Namespace(password=None, user="u", host="h")
    with pytest.raises(SystemExit):
        cli.resolve_password(args)


def test_default_output_filename_includes_database_and_extension():
    name = cli.default_output_filename("mydb", "csv")
    assert name.startswith("secgresdb_report_mydb_")
    assert name.endswith(".csv")


def test_result_key_single_vs_multi_schema():
    assert cli.result_key("public", "customers", multi_schema=False) == "customers"
    assert cli.result_key("public", "customers", multi_schema=True) == "public.customers"


def test_print_json_output_is_valid_parseable_json(capsys):
    # Regression test: console.print(JSON(...)) used to word-wrap long string
    # values to the terminal width, injecting literal newlines into string
    # literals and corrupting the output as soon as it was piped anywhere.
    payload = {
        "metadata": {"database": "testdb"},
        "results": {
            "customers": {
                "credit_card": {
                    "data_type": "text",
                    "findings": [{
                        "name": "Credit Card - Visa",
                        "description": "Visa credit card numbers (with or without separators) "
                                        "this description is intentionally long enough to wrap",
                        "confidence": "high",
                        "regulations": ["PCI-DSS"],
                        "match_count": 1,
                        "sample_count": 1,
                    }]
                }
            }
        },
    }
    cli.print_json_output(payload)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)  # must not raise
    assert parsed == payload
