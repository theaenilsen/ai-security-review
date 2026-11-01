import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/preview")
def preview():
    url = request.args.get("url")
    response = requests.get(url, timeout=5)
    return response.text[:500]
