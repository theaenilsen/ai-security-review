import os
from flask import Flask, abort, request, send_file

app = Flask(__name__)
UPLOAD_DIR = os.path.realpath("/srv/uploads")


@app.route("/file")
def get_file():
    requested = os.path.realpath(os.path.join(UPLOAD_DIR, request.args.get("name", "")))
    if os.path.commonpath([requested, UPLOAD_DIR]) != UPLOAD_DIR:
        abort(404)
    return send_file(requested)
