import json
import re
from typing import Dict, List, Any
from .postgre_connector import PostgreConnector

class SensitiveDataScanner:
    def __init__(self, connector: PostgreConnector, patterns_file: str):
        """
        Initialize scanner with a database connector and path to patterns JSON.
        """
        self.connector = connector
        self.patterns = self._load_patterns(patterns_file)
        self.results = {}  # {table_name: {column_name: [tags]}}

    @staticmethod
    def _load_patterns(patterns_file: str) -> List[Dict[str, Any]]:
        """Load regex patterns from JSON file."""
        with open(patterns_file, 'r') as f:
            data = json.load(f)
            return data.get('patterns', [])

    def scan_database(self, schema: str = 'public', sample_limit: int = 100) -> Dict[str, Dict[str, List[str]]]:
        """
        Scan all tables in the given schema.
        For each column, sample data and check against patterns.
        Returns a dictionary with table->column->list of matched pattern names.
        """
        tables = self.connector.get_tables(schema)
        for table in tables:
            self._scan_table(table, schema, sample_limit)
        return self.results

    def _scan_table(self, table: str, schema: str, sample_limit: int):
        """Scan a single table."""
        columns = self.connector.get_columns(table, schema)
        table_results = {}

        for col in columns:
            # Skip columns that are likely not text (optional: add data type filtering)
            if col['data_type'] not in ('text', 'varchar', 'character varying', 'char'):
                # Still can scan numeric fields if they contain SSN etc. but we'll be cautious.
                # For now, only scan text-like columns.
                continue

            # Get sample values
            samples = self.connector.sample_data(table, col['name'], schema, limit=sample_limit)
            if not samples:
                continue

            # Check each pattern against samples
            matched_tags = []
            for pattern in self.patterns:
                pattern_name = pattern['name']
                pattern_regex = pattern['regex']
                confidence = pattern['confidence']
                # Compile regex once per column?
                # For simplicity, we'll compile each time. Could cache.
                compiled_re = re.compile(pattern_regex, re.IGNORECASE)
                if any(compiled_re.search(str(value)) for value in samples):
                    matched_tags.append(pattern_name)
                    # Optional: break if we found enough patterns? But continue to collect all matches.

            if matched_tags:
                table_results[col['name']] = matched_tags

        if table_results:
            self.results[table] = table_results

    def scan_table(self, table: str, schema: str = 'public', sample_limit: int = 100) -> Dict[str, List[str]]:
        """Scan a single table and return its sensitive columns."""
        self._scan_table(table, schema, sample_limit)
        return self.results.get(table, {})