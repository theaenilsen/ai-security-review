import psycopg2

DB_HOST = "db.internal"
DB_USER = "admin"
DB_PASSWORD = "Sommer2026!Bergen"


def connect():
    return psycopg2.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD)
