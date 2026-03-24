#!/usr/bin/env python3
"""
Setup script to create a test PostgreSQL database with fake sensitive data.
Run this before testing SecgresDB.
"""

import argparse
import psycopg2
from psycopg2 import sql
from faker import Faker
import random

fake = Faker()

def parse_args():
    parser = argparse.ArgumentParser(description="Create test database for SecgresDB")
    parser.add_argument("--host", default="localhost", help="PostgreSQL host")
    parser.add_argument("--port", type=int, default=5432, help="PostgreSQL port")
    parser.add_argument("--user", default="postgres", help="Database user")
    parser.add_argument("--password", default="password", help="Database password")
    parser.add_argument("--dbname", default="testdb", help="Database name to create")
    parser.add_argument("--drop", action="store_true", help="Drop existing database if it exists")
    return parser.parse_args()

def create_database(conn_params, dbname):
    """Create a new database if it doesn't exist."""
    # Connect to default 'postgres' database to manage databases
    admin_params = conn_params.copy()
    admin_params['dbname'] = 'postgres'
    conn = psycopg2.connect(**admin_params)
    conn.autocommit = True
    cursor = conn.cursor()
    # Check if database exists
    cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,))
    exists = cursor.fetchone()
    if exists:
        print(f"Database '{dbname}' already exists.")
        return
    cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
    print(f"Database '{dbname}' created.")
    cursor.close()
    conn.close()

def drop_database(conn_params, dbname):
    """Drop the database if it exists."""
    admin_params = conn_params.copy()
    admin_params['dbname'] = 'postgres'
    conn = psycopg2.connect(**admin_params)
    conn.autocommit = True
    cursor = conn.cursor()
    # Terminate existing connections
    cursor.execute(sql.SQL("""
        SELECT pg_terminate_backend(pg_stat_activity.pid)
        FROM pg_stat_activity
        WHERE pg_stat_activity.datname = %s
        AND pid <> pg_backend_pid()
    """), (dbname,))
    cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))
    print(f"Database '{dbname}' dropped.")
    cursor.close()
    conn.close()

def create_tables(conn):
    """Create tables with columns for various sensitive data types."""
    with conn.cursor() as cur:
        # Table 1: customers
        cur.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY,
                name TEXT,
                email TEXT,
                phone TEXT,
                ssn TEXT,
                credit_card TEXT,
                ip_address TEXT,
                dob DATE,
                passport TEXT
            )
        """)
        # Table 2: employees
        cur.execute("""
            CREATE TABLE IF NOT EXISTS employees (
                id SERIAL PRIMARY KEY,
                full_name TEXT,
                work_email TEXT,
                personal_email TEXT,
                phone TEXT,
                ssn TEXT,
                salary NUMERIC,
                hire_date DATE
            )
        """)
        # Table 3: logs (mixed data)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                event TEXT,
                ip_address TEXT,
                user_email TEXT,
                timestamp TIMESTAMP
            )
        """)
        print("Tables created.")
    conn.commit()

def populate_tables(conn, num_rows=100):
    """Populate tables with fake data."""
    with conn.cursor() as cur:
        # Populate customers
        for _ in range(num_rows):
            # Generate credit card number based on type
            cc_type = random.choice(['visa', 'mastercard', 'amex'])
            if cc_type == 'visa':
                cc = fake.credit_card_number(card_type='visa')
            elif cc_type == 'mastercard':
                cc = fake.credit_card_number(card_type='mastercard')
            else:
                cc = fake.credit_card_number(card_type='amex')
            cur.execute("""
                INSERT INTO customers (name, email, phone, ssn, credit_card, ip_address, dob, passport)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                fake.name(),
                fake.email(),
                fake.phone_number(),
                fake.ssn(),
                cc,
                fake.ipv4(),
                fake.date_of_birth(minimum_age=18, maximum_age=90),
                fake.passport_number()
            ))
        # Populate employees
        for _ in range(num_rows):
            cur.execute("""
                INSERT INTO employees (full_name, work_email, personal_email, phone, ssn, salary, hire_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                fake.name(),
                fake.company_email(),
                fake.email(),
                fake.phone_number(),
                fake.ssn(),
                random.randint(30000, 120000),
                fake.date_between(start_date='-10y', end_date='today')
            ))
        # Populate logs
        for _ in range(num_rows):
            cur.execute("""
                INSERT INTO logs (event, ip_address, user_email, timestamp)
                VALUES (%s, %s, %s, %s)
            """, (
                fake.sentence(),
                fake.ipv4(),
                fake.email(),
                fake.date_time_this_decade()
            ))
        print(f"Inserted {num_rows} rows into each table.")
    conn.commit()

def main():
    args = parse_args()
    conn_params = {
        'host': args.host,
        'port': args.port,
        'user': args.user,
        'password': args.password,
    }

    if args.drop:
        drop_database(conn_params, args.dbname)

    # Create database
    create_database(conn_params, args.dbname)

    # Connect to the newly created (or existing) database
    conn_params['dbname'] = args.dbname
    conn = psycopg2.connect(**conn_params)
    conn.autocommit = False

    create_tables(conn)
    populate_tables(conn, num_rows=200)  # Adjust number as needed

    conn.close()
    print(f"Setup complete. You can now run SecgresDB on database '{args.dbname}'.")

if __name__ == "__main__":
    main()