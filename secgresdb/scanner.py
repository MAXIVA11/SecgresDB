import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, Set

from .postgre_connector import PostgreConnector
from .validators import get_validator

logger = logging.getLogger("secgresdb")

CONFIDENCE_WEIGHT = {"low": 1, "medium": 2, "high": 3}
_CONFIDENCE_ORDER = ["low", "medium", "high"]


def _bump_confidence(confidence: str) -> str:
    """Raise a confidence level by one step (capped at 'high')."""
    try:
        idx = _CONFIDENCE_ORDER.index(confidence)
    except ValueError:
        return confidence
    return _CONFIDENCE_ORDER[min(idx + 1, len(_CONFIDENCE_ORDER) - 1)]


@dataclass
class Pattern:
    name: str
    description: str
    regex: "re.Pattern"
    confidence: str
    regulations: List[str]
    name_hints: List[str] = field(default_factory=list)
    requires_name_hint: bool = False
    validator: Optional[Callable[[str], bool]] = None


class SensitiveDataScanner:
    def __init__(self, connector: PostgreConnector, patterns_file: str):
        """Initialize scanner with a database connector and path to patterns JSON."""
        self.connector = connector
        self.patterns = self._load_patterns(patterns_file)

    @staticmethod
    def _load_patterns(patterns_file: str) -> List[Pattern]:
        """Load and compile regex patterns from JSON file, skipping invalid ones."""
        with open(patterns_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        patterns: List[Pattern] = []
        for p in data.get('patterns', []):
            name = p.get('name', '<unnamed>')
            try:
                compiled = re.compile(p['regex'], re.IGNORECASE)
            except re.error as e:
                logger.warning("Skipping pattern '%s': invalid regex (%s)", name, e)
                continue
            patterns.append(Pattern(
                name=name,
                description=p.get('description', ''),
                regex=compiled,
                confidence=p.get('confidence', 'low').lower(),
                regulations=p.get('regulations', []),
                name_hints=[h.lower() for h in p.get('name_hints', [])],
                requires_name_hint=bool(p.get('requires_name_hint', False)),
                validator=get_validator(p.get('validator')),
            ))
        return patterns

    def scan_database(self, schema: str = 'public', sample_limit: int = 100,
                       exclude_columns: Optional[Set[str]] = None) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """Scan every table in the given schema. Returns table -> column -> findings."""
        results = {}
        for table in self.connector.get_tables(schema):
            table_results = self.scan_table(table, schema, sample_limit, exclude_columns)
            if table_results:
                results[table] = table_results
        return results

    def scan_table(self, table: str, schema: str = 'public', sample_limit: int = 100,
                    exclude_columns: Optional[Set[str]] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan a single table and return {column_name: [finding, ...]} where each
        finding carries its own confidence, regulations, and match coverage.
        """
        exclude_columns = exclude_columns or set()
        columns_meta = self.connector.get_columns(table, schema)
        candidate_columns = [
            c for c in self.connector.scannable_columns(columns_meta)
            if c not in exclude_columns
        ]
        if not candidate_columns:
            return {}

        samples_by_column = self.connector.sample_columns(table, candidate_columns, schema, sample_limit)

        table_results: Dict[str, List[Dict[str, Any]]] = {}
        for col_name, samples in samples_by_column.items():
            if not samples:
                continue
            findings = self._match_column(col_name, samples)
            if findings:
                table_results[col_name] = findings
        return table_results

    def _match_column(self, col_name: str, samples: List[Any]) -> List[Dict[str, Any]]:
        """Evaluate every pattern against a column's sampled values."""
        col_lower = col_name.lower()
        findings = []

        for pattern in self.patterns:
            name_hint_matched = any(hint in col_lower for hint in pattern.name_hints)
            # Noisy, low-signal patterns (ZIP codes, bare 9-digit numbers, etc.)
            # only fire when the column name itself corroborates the guess.
            if pattern.requires_name_hint and not name_hint_matched:
                continue

            matched_count = 0
            for value in samples:
                text = str(value)
                match = pattern.regex.search(text)
                # Validators run against the matched substring, not the whole
                # value - a card number regex can match inside a longer note
                # field, and running Luhn/IBAN checksums over the surrounding
                # text would corrupt the result.
                if match and (pattern.validator is None or pattern.validator(match.group(0))):
                    matched_count += 1

            if matched_count:
                confidence = _bump_confidence(pattern.confidence) if name_hint_matched else pattern.confidence
                findings.append({
                    "name": pattern.name,
                    "description": pattern.description,
                    "confidence": confidence,
                    "regulations": pattern.regulations,
                    "match_count": matched_count,
                    "sample_count": len(samples),
                    "name_hint_matched": name_hint_matched,
                })

        return findings


def summarize(results: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
    """
    Compute aggregate risk stats shared by the console summary, CSV, and HTML
    reports so they never drift from each other.
    """
    confidence_counts = {"high": 0, "medium": 0, "low": 0}
    unique_regulations: Set[str] = set()
    table_risk: Dict[str, str] = {}

    for table, columns in results.items():
        table_max = "low"
        for findings in columns.values():
            for finding in findings:
                conf = finding["confidence"]
                if conf in confidence_counts:
                    confidence_counts[conf] += 1
                unique_regulations.update(finding["regulations"])
                if CONFIDENCE_WEIGHT.get(conf, 0) > CONFIDENCE_WEIGHT.get(table_max, 0):
                    table_max = conf
        table_risk[table] = table_max

    if confidence_counts["high"] > 0:
        overall_risk = "High"
    elif confidence_counts["medium"] > 0:
        overall_risk = "Medium"
    elif confidence_counts["low"] > 0:
        overall_risk = "Low"
    else:
        overall_risk = "None"

    return {
        "confidence_counts": confidence_counts,
        "unique_regulations": sorted(unique_regulations),
        "table_risk": table_risk,
        "overall_risk": overall_risk,
        "tables_with_sensitive_data": len(results),
        "total_sensitive_columns": sum(len(cols) for cols in results.values()),
    }
