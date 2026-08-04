import json
import re

from secgresdb.validators import get_validator


def test_shipped_patterns_file_is_well_formed(patterns_path):
    with open(patterns_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    patterns = data["patterns"]
    assert len(patterns) > 0

    names = [p["name"] for p in patterns]
    assert len(names) == len(set(names)), "duplicate pattern names"

    for p in patterns:
        re.compile(p["regex"])  # must not raise
        assert p["confidence"].lower() in ("high", "medium", "low")
        assert isinstance(p.get("regulations", []), list)
        validator_name = p.get("validator")
        if validator_name:
            assert get_validator(validator_name) is not None, f"unknown validator '{validator_name}' on {p['name']}"
