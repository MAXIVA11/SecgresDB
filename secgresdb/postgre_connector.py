import psycopg2
from psycopg2 import sql
from typing import List, Dict, Any

class PostgreConnector:
    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        """Initialize PostgreSQL connection parameters."""
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.connection = None

    def connect(self):
        """Establish connection to PostgreSQL."""
        try:
            self.connection = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password
            )
            print(f"Connected to PostgreSQL database '{self.database}'")
        except Exception as e:
            raise Exception(f"Failed to connect to database: {e}")

    def disconnect(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            print("Disconnected from database")

    def get_tables(self, schema: str = 'public') -> List[str]:
        """
        Retrieve all table names in the given schema.
        Returns a list of table names.
        """
        with self.connection.cursor() as cursor:
            query = sql.SQL("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = %s
                AND table_type = 'BASE TABLE'
            """)
            cursor.execute(query, (schema,))
            tables = [row[0] for row in cursor.fetchall()]
            return tables

    def get_columns(self, table: str, schema: str = 'public') -> List[Dict[str, Any]]:
        """
        Retrieve column details for a given table.
        Returns a list of dicts with column name, data type, etc.
        """
        with self.connection.cursor() as cursor:
            query = sql.SQL("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = %s AND table_name = %s
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

    def sample_data(self, table: str, column: str, schema: str = 'public', limit: int = 100) -> List[Any]:
        """
        Fetch sample values from a specific column for scanning.
        Returns a list of distinct non-null values (up to limit).
        """
        with self.connection.cursor() as cursor:
            # Use DISTINCT to get a variety of values
            query = sql.SQL("""
                SELECT DISTINCT {column}
                FROM {schema}.{table}
                WHERE {column} IS NOT NULL
                LIMIT %s
            """).format(
                column=sql.Identifier(column),
                schema=sql.Identifier(schema),
                table=sql.Identifier(table)
            )
            cursor.execute(query, (limit,))
            rows = cursor.fetchall()
            return [row[0] for row in rows if row[0] is not None]