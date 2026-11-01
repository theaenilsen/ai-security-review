import os
from flask import Flask, request, send_file

app = Flask(__name__)
BASE_DIR = "/srv/reports"


@app.route("/report")
def report():
    name = request.args.get("name")
    return send_file(os.path.join(BASE_DIR, name))
