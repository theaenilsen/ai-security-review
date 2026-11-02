import sqlite3

SORT_COLUMNS = {"name": "name", "newest": "created_at", "price": "price"}


def list_items(owner_id, sort):
    column = SORT_COLUMNS.get(sort, "name")
    conn = sqlite3.connect("shop.db")
    sql = f"SELECT id, name FROM items WHERE owner_id = ? ORDER BY {column}"
    return conn.execute(sql, (owner_id,)).fetchall()
