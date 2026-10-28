from flask import Flask, g, redirect, render_template, request, url_for

from auth import (
    SESSION_LIFETIME,
    authenticate_user,
    create_session,
    create_user,
    delete_session,
    get_user_by_session,
    login_required,
)
from database import init_db


app = Flask(__name__)


@app.before_request
def load_logged_in_user():
    token = request.cookies.get("session_id")
    g.user = get_user_by_session(token)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3:
            error = "Username must be at least 3 characters."

        elif len(password) < 12:
            error = "Master password must be at least 12 characters."

        elif not create_user(username, password):
            error = "Username already exists."

        else:
            return redirect(url_for("login"))

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = authenticate_user(username, password)

        if user is None:
            error = "Invalid username or password."

        else:
            token = create_session(user["id"])

            response = redirect(url_for("vault"))

            response.set_cookie(
                "session_id",
                token,
                max_age=SESSION_LIFETIME,
                httponly=True,
                samesite="Strict",
                secure=False,
            )

            return response

    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get("session_id")

    delete_session(token)

    response = redirect(url_for("login"))
    response.delete_cookie("session_id")

    return response


@app.route("/vault")
@login_required
def vault():
    return render_template("vault.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)