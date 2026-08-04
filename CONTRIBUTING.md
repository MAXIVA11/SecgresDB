# Contributing to SecgresDB

Thanks for considering a contribution — patches, new detection patterns, bug reports, and README fixes are all welcome.

## Getting set up

```bash
git clone https://github.com/MAXIVA11/SecgresDB.git
cd SecgresDB
pip install -e ".[dev]"
pytest -v
```

The test suite runs against a mocked database connector, so no PostgreSQL instance is required to develop or run `pytest`. If you're changing scanning/sampling behavior, also validate against a real database before opening a PR — see the **Real end-to-end testing** section in the [README](README.md#-testing). This matters: several real bugs (checksum edge cases, an invalid-JSON-on-pipe bug, a Windows console crash) only showed up against a live database, never in the mocked suite.

## Making a change

1. Open an issue first for anything non-trivial (new patterns, behavior changes) so we can agree on the approach before you invest time.
2. Add or update tests for whatever you change — `tests/test_scanner.py`, `tests/test_validators.py`, `tests/test_patterns.py`, `tests/test_cli.py`, and `tests/test_report.py` cover the respective modules.
3. Run `pytest -v` and make sure everything passes.
4. Keep PRs focused — one change per PR is easier to review than a bundle of unrelated fixes.

## Adding a detection pattern

Patterns live in `config/sensitive_patterns.json`. See **Extending the pattern library** in the README for the schema (`name_hints`, `requires_name_hint`, `validator`). A few guidelines:

- If your pattern is noisy on its own (matches common non-sensitive data — bare digit sequences, short alphanumeric codes), set `"requires_name_hint": true` so it only fires when the column name corroborates it.
- If a checksum or format validator exists for the data type (Luhn, IBAN mod-97, etc.), wire it up via `"validator"` in `secgresdb/validators.py` rather than relying on regex shape alone — regex-only patterns produce false positives (see `valid_iban`'s docstring for a real example: a loose IBAN regex also matched vehicle VINs).
- Add a test in `tests/test_scanner.py` showing both a true positive and, if the pattern is prone to false positives, a case it correctly rejects.

## Reporting bugs

Open a GitHub issue with: what you ran (command/flags, not real credentials), what you expected, what happened instead, and your PostgreSQL/Python versions. If it's a detection accuracy issue (false positive/negative), include the column name and a *fake* example value that reproduces it — never paste real sensitive data into an issue.

## Where to start

Good entry points if you want to contribute but aren't sure where:

- **New patterns**: AWS secret access keys (not just access key IDs), Stripe/GitHub token formats, generic high-entropy secret detection with an entropy threshold.
- **Sampling**: currently one query per table; a `--max-concurrent-tables` flag to scan multiple tables in parallel would speed up scans of wide schemas.
- **Output**: a Markdown report format (between the console table and the full HTML report) for pasting into tickets/PRs.
- **Docs**: a walkthrough GIF/asciinema recording of a full scan for the README.
- **Validators**: a national-insurance-number or IBAN-adjacent validator for a region not yet covered.

Comment on an existing issue (or open one) before starting so effort doesn't collide.

## Code style

Plain, readable Python — type hints on function signatures, no comments explaining *what* code does (names should do that), comments only for non-obvious *why*. Match the existing structure: connection/query logic in `postgre_connector.py`, matching logic in `scanner.py`, output formatting in `cli.py`/`report.py`.
