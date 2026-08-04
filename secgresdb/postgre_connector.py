import logging
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2 import sql

logger = logging.getLogger("secgresdb")

# Above this estimated row count, use TABLESAMPLE instead of ORDER BY random()
# so sampling stays cheap on large tables (ORDER BY random() forces a full scan + sort).
LARGE_TABLE_ROW_THRESHOLD = 50_000

# Column types we never scan: opaque binary blobs and booleans can't contain
# regex-matchable PII, and scanning them wastes a round trip.
NON_SCANNABLE_TYPES = {"boolean", "bytea", "ARRAY"}


class PostgreConnector:
    def __init__(self, host: str, port: int, database: str, user: str, password: str,
                 sslmode: str = "prefer", connect_timeout: int = 10):
        """Initialize PostgreSQL connection parameters."""
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.sslmode = sslmode
        self.connect_timeout = connect_timeout
        self.connection = None

    def connect(self):
        """Establish connection to PostgreSQL."""
        try:
            self.connection = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                sslmode=self.sslmode,
                connect_timeout=self.connect_timeout,
            )
            self.connection.set_session(readonly=True, autocommit=True)
            logger.info("Connected to PostgreSQL database '%s'", self.database)
        except Exception as e:
            raise ConnectionError(f"Failed to connect to database: {e}") from e

    def disconnect(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            logger.info("Disconnected from database")

    def get_schemas(self) -> List[str]:
        """Return all non-system schemas in the database."""
        with self.connection.cursor() as cursor:
            cursor.execute("""
                SELECT schema_name FROM information_schema.schemata
                WHERE schema_name NOT IN ('pg_catalog', 'information_schema')
                AND schema_name NOT LIKE 'pg\\_toast%'
                AND schema_name NOT LIKE 'pg\\_temp%'
                ORDER BY schema_name
            """)
            return [row[0] for row in cursor.fetchall()]

    def get_tables(self, schema: str = 'public') -> List[str]:
        """Retrieve all base table names in the given schema."""
        with self.connection.cursor() as cursor:
            query = sql.SQL("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = %s
                AND table_type = 'BASE TABLE'
                ORDER BY table_name
            """)
            cursor.execute(query, (schema,))
            return [row[0] for row in cursor.fetchall()]

    def get_columns(self, table: str, schema: str = 'public') -> List[Dict[str, Any]]:
        """Retrieve column details for a given table."""
        with self.connection.cursor() as cursor:
            query = sql.SQL("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = %s AND table_name = %s
                ORDER BY ordinal_position
            """)
            cursor.execute(query, (schema, table))
            columns = []
            for row in cursor.fetchall():
                columns.append({
                    'name': row[0],
                    'data_type': row[1],
                    'nullable': row[2] == 'YES'
                })
            return columns

    def get_row_estimate(self, table: str, schema: str = 'public') -> Optional[int]:
        """
        Fast, approximate row count from planner statistics (no table scan).
        Returns None if the table isn't found in pg_class (e.g. just created,
        stats not yet collected) so callers can fall back to a safe default.
        """
        with self.connection.cursor() as cursor:
            cursor.execute("""
                SELECT c.reltuples::bigint
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %s AND c.relname = %s
            """, (schema, table))
            row = cursor.fetchone()
            if row and row[0] is not None and row[0] >= 0:
                return int(row[0])
            return None

    def sample_columns(self, table: str, columns: List[str], schema: str = 'public',
                        limit: int = 100) -> Dict[str, List[str]]:
        """
        Sample up to `limit` rows from `table` in a single round trip and return
        the non-null values seen per column. Uses TABLESAMPLE on large tables to
        avoid a full-table sort (ORDER BY random()) that would otherwise dominate
        scan time; falls back to ORDER BY random() on small/unknown-size tables
        for a less biased sample.
        """
        if not columns:
            return {}

        result: Dict[str, List[str]] = {c: [] for c in columns}
        select_list = sql.SQL(", ").join(
            sql.SQL("{}::text").format(sql.Identifier(c)) for c in columns
        )
        row_estimate = self.get_row_estimate(table, schema)

        if row_estimate and row_estimate > LARGE_TABLE_ROW_THRESHOLD:
            target_rows = max(limit * 5, 500)
            pct = min(100.0, max(0.01, (target_rows / row_estimate) * 100))
            query = sql.SQL(
                "SELECT {cols} FROM {schema}.{table} TABLESAMPLE SYSTEM ({pct}) LIMIT %s"
            ).format(
                cols=select_list,
                schema=sql.Identifier(schema),
                table=sql.Identifier(table),
                pct=sql.SQL(str(round(pct, 4))),
            )
        else:
            query = sql.SQL(
                "SELECT {cols} FROM {schema}.{table} ORDER BY random() LIMIT %s"
            ).format(
                cols=select_list,
                schema=sql.Identifier(schema),
                table=sql.Identifier(table),
            )

        with self.connection.cursor() as cursor:
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()

        for row in rows:
            for col, val in zip(columns, row):
                if val is not None:
                    result[col].append(val)
        return result

    @staticmethod
    def scannable_columns(columns: List[Dict[str, Any]]) -> List[str]:
        """Filter out column types that can never hold regex-matchable text."""
        return [c['name'] for c in columns if c['data_type'] not in NON_SCANNABLE_TYPES]
