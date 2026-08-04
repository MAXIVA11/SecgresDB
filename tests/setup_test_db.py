#!/usr/bin/env python3
"""
Setup script to create a test PostgreSQL database with realistic fake sensitive data.
Run this before testing SecgresDB.
"""

import argparse
import getpass
import os
import sys
import psycopg2
from psycopg2 import sql
from faker import Faker
import random

fake = Faker()

def parse_args():
    parser = argparse.ArgumentParser(description="Create a realistic test database for SecgresDB")
    parser.add_argument("--host", default="localhost", help="PostgreSQL host")
    parser.add_argument("--port", type=int, default=5432, help="PostgreSQL port")
    parser.add_argument("--user", default="postgres", help="Database user")
    parser.add_argument("--password", default=None,
                        help="Database password. Omit to read PGPASSWORD or be prompted interactively.")
    parser.add_argument("--dbname", default="testdb", help="Database name to create")
    parser.add_argument("--drop", action="store_true", help="Drop existing database if it exists")
    parser.add_argument("--rows", type=int, default=500, help="Number of rows per table (default: 500)")
    return parser.parse_args()

def resolve_password(args):
    if args.password:
        return args.password
    env_password = os.environ.get("PGPASSWORD")
    if env_password:
        return env_password
    if not sys.stdin.isatty():
        print("Error: no password available. Pass --password, set PGPASSWORD, or run interactively.", file=sys.stderr)
        sys.exit(1)
    return getpass.getpass(f"Password for {args.user}@{args.host}: ")

def create_database(conn_params, dbname):
    admin_params = conn_params.copy()
    admin_params['dbname'] = 'postgres'
    conn = psycopg2.connect(**admin_params)
    conn.autocommit = True
    cursor = conn.cursor()
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
    admin_params = conn_params.copy()
    admin_params['dbname'] = 'postgres'
    conn = psycopg2.connect(**admin_params)
    conn.autocommit = True
    cursor = conn.cursor()
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

def drop_tables(conn):
    """Drop all tables if they exist to ensure a clean schema."""
    with conn.cursor() as cur:
        tables = [
            'customers', 'employees', 'patients', 'financial_accounts',
            'transactions', 'vehicles', 'web_logs', 'biometric_data'
        ]
        for table in tables:
            cur.execute(sql.SQL("DROP TABLE IF EXISTS {} CASCADE").format(sql.Identifier(table)))
        conn.commit()
        print("Dropped existing tables (if any).")

def create_tables(conn):
    with conn.cursor() as cur:
        # ---------- Customers (PII, financial) ----------
        cur.execute("""
            CREATE TABLE customers (
                id SERIAL PRIMARY KEY,
                full_name TEXT,
                email TEXT,
                phone TEXT,
                ssn TEXT,
                dob DATE,
                credit_card TEXT,
                ip_address TEXT,
                passport TEXT,
                driver_license TEXT,
                mac_address TEXT
            )
        """)

        # ---------- Employees (PII, salary) ----------
        cur.execute("""
            CREATE TABLE employees (
                id SERIAL PRIMARY KEY,
                full_name TEXT,
                work_email TEXT,
                personal_email TEXT,
                phone TEXT,
                ssn TEXT,
                salary NUMERIC,
                hire_date DATE,
                driver_license TEXT,
                passport TEXT
            )
        """)

        # ---------- Patients (HIPAA data) ----------
        cur.execute("""
            CREATE TABLE patients (
                id SERIAL PRIMARY KEY,
                full_name TEXT,
                dob DATE,
                ssn TEXT,
                mrn TEXT,
                hicn TEXT,
                diagnosis TEXT,
                admission_date DATE,
                discharge_date DATE,
                email TEXT,
                phone TEXT
            )
        """)

        # ---------- Financial Accounts (GLBA) ----------
        cur.execute("""
            CREATE TABLE financial_accounts (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER,
                account_number TEXT,
                routing_number TEXT,
                iban TEXT,
                swift TEXT,
                ein TEXT,
                account_type TEXT
            )
        """)

        # ---------- Transactions (PCI‑DSS) ----------
        cur.execute("""
            CREATE TABLE transactions (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER,
                credit_card TEXT,
                amount NUMERIC,
                transaction_date TIMESTAMP,
                ip_address TEXT,
                merchant TEXT
            )
        """)

        # ---------- Vehicles (VIN, etc.) ----------
        cur.execute("""
            CREATE TABLE vehicles (
                id SERIAL PRIMARY KEY,
                vin TEXT,
                make TEXT,
                model TEXT,
                year INTEGER,
                owner_id INTEGER,
                license_plate TEXT
            )
        """)

        # ---------- Web Logs (GDPR) ----------
        cur.execute("""
            CREATE TABLE web_logs (
                id SERIAL PRIMARY KEY,
                ip_address TEXT,
                user_agent TEXT,
                user_email TEXT,
                mac_address TEXT,
                timestamp TIMESTAMP,
                endpoint TEXT
            )
        """)

        # ---------- Biometric Data (BIPA) ----------
        cur.execute("""
            CREATE TABLE biometric_data (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                fingerprint_hash TEXT,
                face_template TEXT,
                iris_code TEXT,
                recorded_at TIMESTAMP
            )
        """)

        print("All tables created.")
    conn.commit()

# ----- Helper functions for generating custom fake data -----
def generate_driver_license():
    """Generate a US driver's license (2 letters + 6-8 digits)."""
    letters = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ', k=2))
    digits = ''.join(random.choices('0123456789', k=random.randint(6, 8)))
    return letters + digits

def generate_ein():
    """Generate a fake EIN in format XX-XXXXXXX"""
    return f"{random.randint(10, 99)}-{random.randint(1000000, 9999999)}"

def generate_mrn():
    """Generate a fake Medical Record Number (MRN + 6-8 digits)"""
    return f"MRN{random.randint(100000, 99999999)}"

def generate_hicn():
    """Generate a fake HICN: 9-11 alphanumeric, often starting with a letter"""
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
    length = random.randint(9, 11)
    return ''.join(random.choices(chars, k=length))

def generate_account_number():
    """Generate a random 10-12 digit bank account number"""
    return str(random.randint(10**9, 10**12 - 1))

def generate_biometric_hash():
    """Generate a random 64-character hex string (simulate SHA-256)"""
    return fake.sha256()

def populate_tables(conn, num_rows):
    with conn.cursor() as cur:
        # ----- customers -----
        for _ in range(num_rows):
            cc_type = random.choice(['visa', 'mastercard', 'amex'])
            if cc_type == 'visa':
                cc = fake.credit_card_number(card_type='visa')
            elif cc_type == 'mastercard':
                cc = fake.credit_card_number(card_type='mastercard')
            else:
                cc = fake.credit_card_number(card_type='amex')
            cur.execute("""
                INSERT INTO customers
                (full_name, email, phone, ssn, dob, credit_card, ip_address, passport, driver_license, mac_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                fake.name(),
                fake.email(),
                fake.phone_number(),
                fake.ssn(),
                fake.date_of_birth(minimum_age=18, maximum_age=90),
                cc,
                fake.ipv4(),
                fake.passport_number(),
                generate_driver_license(),
                fake.mac_address()
            ))

        # ----- employees -----
        for _ in range(num_rows):
            cur.execute("""
                INSERT INTO employees
                (full_name, work_email, personal_email, phone, ssn, salary, hire_date, driver_license, passport)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                fake.name(),
                fake.company_email(),
                fake.email(),
                fake.phone_number(),
                fake.ssn(),
                random.randint(30000, 150000),
                fake.date_between(start_date='-15y', end_date='today'),
                generate_driver_license(),
                fake.passport_number()
            ))

        # ----- patients (HIPAA) -----
        for _ in range(num_rows):
            cur.execute("""
                INSERT INTO patients
                (full_name, dob, ssn, mrn, hicn, diagnosis, admission_date, discharge_date, email, phone)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                fake.name(),
                fake.date_of_birth(minimum_age=0, maximum_age=100),
                fake.ssn(),
                generate_mrn(),
                generate_hicn(),
                fake.sentence(nb_words=5),
                fake.date_between(start_date='-5y', end_date='today'),
                fake.date_between(start_date='-5y', end_date='today'),
                fake.email(),
                fake.phone_number()
            ))

        # ----- financial_accounts -----
        num_accounts = num_rows * 2
        for _ in range(num_accounts):
            cur.execute("""
                INSERT INTO financial_accounts
                (customer_id, account_number, iban, swift, ein, account_type)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                random.randint(1, num_rows),
                generate_account_number(),
                fake.iban(),
                fake.swift(),
                generate_ein(),
                random.choice(['checking', 'savings', 'investment'])
            ))

        # ----- transactions -----
        for _ in range(num_rows * 3):
            cc_type = random.choice(['visa', 'mastercard', 'amex'])
            if cc_type == 'visa':
                cc = fake.credit_card_number(card_type='visa')
            elif cc_type == 'mastercard':
                cc = fake.credit_card_number(card_type='mastercard')
            else:
                cc = fake.credit_card_number(card_type='amex')
            cur.execute("""
                INSERT INTO transactions
                (customer_id, credit_card, amount, transaction_date, ip_address, merchant)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                random.randint(1, num_rows),
                cc,
                round(random.uniform(5, 5000), 2),
                fake.date_time_this_year(),
                fake.ipv4(),
                fake.company()
            ))

        # ----- vehicles -----
        for _ in range(num_rows // 2):
            cur.execute("""
                INSERT INTO vehicles
                (vin, make, model, year, owner_id, license_plate)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                fake.vin(),
                fake.company(),
                fake.word(),
                random.randint(1990, 2025),
                random.randint(1, num_rows),
                fake.license_plate()
            ))

        # ----- web_logs -----
        for _ in range(num_rows * 3):
            cur.execute("""
                INSERT INTO web_logs
                (ip_address, user_agent, user_email, mac_address, timestamp, endpoint)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                fake.ipv4(),
                fake.user_agent(),
                fake.email(),
                fake.mac_address(),
                fake.date_time_this_year(),
                fake.uri_path()
            ))

        # ----- biometric_data -----
        for _ in range(num_rows // 2):
            cur.execute("""
                INSERT INTO biometric_data
                (user_id, fingerprint_hash, face_template, iris_code, recorded_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                random.randint(1, num_rows),
                generate_biometric_hash(),
                fake.sha256(),
                fake.sha256(),
                fake.date_time_this_year()
            ))

        conn.commit()
        print(f"Inserted data into all tables. Rows per table (approx): customers={num_rows}, employees={num_rows}, patients={num_rows}, "
              f"financial_accounts={num_accounts}, transactions={num_rows*3}, vehicles={num_rows//2}, web_logs={num_rows*3}, biometric_data={num_rows//2}")

def main():
    args = parse_args()
    conn_params = {
        'host': args.host,
        'port': args.port,
        'user': args.user,
        'password': resolve_password(args),
    }

    if args.drop:
        drop_database(conn_params, args.dbname)

    create_database(conn_params, args.dbname)

    conn_params['dbname'] = args.dbname
    conn = psycopg2.connect(**conn_params)
    conn.autocommit = False

    # Drop existing tables to ensure a clean schema
    drop_tables(conn)
    create_tables(conn)
    populate_tables(conn, args.rows)

    conn.close()
    print(f"Setup complete. You can now run SecgresDB on database '{args.dbname}'.")

if __name__ == "__main__":
    main()