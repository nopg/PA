from flask import Flask


app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello Woaueoeaorld!"

@app.route("/test")
def test():
    return "Testing!!\nClick here: <a href='/'>to go back</a>"

if __name__ == "__main__":
    app.run(debug=True)