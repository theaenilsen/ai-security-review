import os
from flask import Flask, abort, request, send_file

app = Flask(__name__)
UPLOAD_DIR = "/srv/uploads"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    if ".." in filename:
        abort(400)
    return send_file(os.path.join(UPLOAD_DIR, filename))
