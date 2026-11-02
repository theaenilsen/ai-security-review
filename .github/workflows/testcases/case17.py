import subprocess
from flask import Flask, request

app = Flask(__name__)


def sanitize(value):
    return value.replace(";", "").strip()


@app.route("/lookup")
def lookup():
    domain = sanitize(request.args.get("domain", ""))
    output = subprocess.run("nslookup " + domain, shell=True, capture_output=True, text=True)
    return output.stdout
