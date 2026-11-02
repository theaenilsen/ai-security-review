from urllib.parse import quote

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/profile")
def profile():
    user_id = request.args.get("id", "")
    url = "https://api.example.com/users/" + quote(user_id, safe="")
    return requests.get(url, timeout=5).json()
