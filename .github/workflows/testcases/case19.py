import requests
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    url = request.args.get("url", "")
    if not url.startswith("https://api.example.com"):
        abort(403)
    return requests.get(url, timeout=5).text
