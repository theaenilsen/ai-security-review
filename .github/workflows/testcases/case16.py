import sqlite3
from flask import Flask, request

app = Flask(__name__)


def build_filter(field, value):
    return field + " = '" + value + "'"


def run_query(where_clause):
    conn = sqlite3.connect("shop.db")
    return conn.execute("SELECT id, title FROM products WHERE " + where_clause).fetchall()


@app.route("/products")
def products():
    category = request.args.get("category", "books")
    return {"products": run_query(build_filter("category", category))}
