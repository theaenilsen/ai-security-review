import base64
import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/session", methods=["POST"])
def restore_session():
    data = base64.b64decode(request.form["state"])
    session = pickle.loads(data)
    return {"user": session.get("user")}
