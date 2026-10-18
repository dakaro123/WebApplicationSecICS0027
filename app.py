from flask import Flask, render_template
from database import init_db

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register")
def register():
    return render_template("register.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/vault")
def vault():
    return render_template("vault.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)