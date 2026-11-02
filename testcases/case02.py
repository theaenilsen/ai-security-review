import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    conn = sqlite3.connect("shop.db")
    rows = conn.execute(f"SELECT * FROM orders WHERE customer = '{customer}'")
    return {"orders": rows.fetchall()}
