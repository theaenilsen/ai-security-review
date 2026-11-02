from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "0")
    result = eval(expression)
    return {"result": result}
