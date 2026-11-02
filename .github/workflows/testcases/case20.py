import jwt
from flask import Flask, request

app = Flask(__name__)


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
    return {"user": claims.get("sub"), "role": claims.get("role")}
