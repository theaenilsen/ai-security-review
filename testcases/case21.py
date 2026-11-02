from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    return "<h1>Resultater</h1><p>Du søkte etter: " + query + "</p>"
