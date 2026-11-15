import logging
import secrets

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    url_for
)

from auth import (
    SESSION_LIFETIME,
    authenticate_user,
    cleanup_expired_sessions,
    create_session,
    create_user,
    delete_session,
    get_session_key,
    get_user_by_session,
    login_required,
    store_session_key,
)
from crypto import (
    decrypt_entry,
    derive_vault_key,
    encrypt_entry,
)
from database import (
    add_vault_entry,
    delete_vault_entry,
    get_vault_entries,
    get_vault_entry,
    init_db,
    update_vault_entry,
)


app = Flask(__name__)
USE_HTTPS = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("password_manager")


@app.before_request
def load_logged_in_user():
    cleanup_expired_sessions()

    token = request.cookies.get("session_id")

    g.session_token = token
    g.user = get_user_by_session(token)

    if (
        g.user is not None
        and get_session_key(token) is None
    ):
        delete_session(token)
        g.user = None


@app.before_request
def protect_from_csrf():
    csrf_token = request.cookies.get("csrf_token")

    if csrf_token is None:
        csrf_token = secrets.token_urlsafe(32)

    g.csrf_token = csrf_token

    if request.method == "POST":
        form_token = request.form.get("csrf_token", "")

        if not secrets.compare_digest(
            csrf_token,
            form_token
        ):
            abort(400)


@app.after_request
def log_request(response):
    logger.info(
        "event=request method=%s path=%s status=%s",
        request.method,
        request.path,
        response.status_code
    )
    return response


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    if USE_HTTPS:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000"
        )

    if hasattr(g, "csrf_token"):
        response.set_cookie(
            "csrf_token",
            g.csrf_token,
            max_age=SESSION_LIFETIME,
            httponly=True,
            samesite="Strict",
            secure=USE_HTTPS,
        )

    return response


@app.errorhandler(400)
def bad_request(error):
    logger.warning(
        "event=http_error method=%s path=%s status=400",
        request.method,
        request.path
    )
    return render_template(
        "error.html",
        message="Invalid request."
    ), 400


@app.errorhandler(404)
def page_not_found(error):
    logger.warning(
        "event=http_error method=%s path=%s status=404",
        request.method,
        request.path
    )
    return render_template(
        "error.html",
        message="Page not found."
    ), 404


@app.errorhandler(500)
def internal_server_error(error):
    logger.error(
        "event=http_error method=%s path=%s status=500",
        request.method,
        request.path
    )
    return render_template(
        "error.html",
        message="Internal server error."
    ), 500


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if len(username) < 3:
            error = (
                "Username must be at least 3 characters."
            )

        elif len(password) < 12:
            error = (
                "Master password must be at least 12 characters."
            )

        elif not create_user(username, password):
            error = "Username already exists."

        else:
            return redirect(url_for("login"))

    return render_template(
        "register.html",
        error=error
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        user = authenticate_user(
            username,
            password
        )

        if user is None:
            error = "Invalid username or password."

        else:
            old_token = request.cookies.get(
                "session_id"
            )

            delete_session(old_token)

            vault_key = derive_vault_key(
                password,
                user["vault_salt"]
            )

            token = create_session(user["id"])

            store_session_key(
                token,
                vault_key
            )

            response = redirect(
                url_for("vault")
            )

            response.set_cookie(
                "session_id",
                token,
                max_age=SESSION_LIFETIME,
                httponly=True,
                samesite="Strict",
                secure=USE_HTTPS,
            )

            return response

    return render_template(
        "login.html",
        error=error
    )


@app.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get("session_id")

    delete_session(token)

    response = redirect(
        url_for("login")
    )

    response.delete_cookie(
        "session_id"
    )

    return response


@app.route("/vault")
@login_required
def vault():
    database_entries = get_vault_entries(
        g.user["id"]
    )

    key = get_session_key(
        g.session_token
    )

    entries = []

    for entry in database_entries:
        decrypted = decrypt_entry(
            key,
            entry["encrypted_data"],
            entry["nonce"]
        )

        entries.append({
            "id": entry["id"],
            "service": decrypted["service"],
            "username": decrypted["username"],
            "notes": decrypted["notes"],
        })

    return render_template(
        "vault.html",
        entries=entries
    )


@app.route(
    "/vault/add",
    methods=["GET", "POST"]
)
@login_required
def add_entry():
    error = None

    if request.method == "POST":
        service = request.form.get(
            "service",
            ""
        ).strip()

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        notes = request.form.get(
            "notes",
            ""
        ).strip()

        if not service:
            error = "Service name is required."

        elif not password:
            error = "Password is required."

        else:
            key = get_session_key(
                g.session_token
            )

            encrypted_data, nonce = encrypt_entry(
                key,
                service,
                username,
                password,
                notes
            )

            add_vault_entry(
                g.user["id"],
                encrypted_data,
                nonce
            )

            return redirect(
                url_for("vault")
            )

    return render_template(
        "entry_form.html",
        form_title="Add entry",
        error=error,
        entry={},
        is_edit=False
    )


@app.route(
    "/vault/<int:entry_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_entry(entry_id):
    database_entry = get_vault_entry(
        entry_id,
        g.user["id"]
    )

    if database_entry is None:
        abort(404)

    key = get_session_key(
        g.session_token
    )

    decrypted = decrypt_entry(
        key,
        database_entry["encrypted_data"],
        database_entry["nonce"]
    )

    entry = {
        "service": decrypted["service"],
        "username": decrypted["username"],
        "notes": decrypted["notes"],
    }

    error = None

    if request.method == "POST":
        service = request.form.get(
            "service",
            ""
        ).strip()

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        notes = request.form.get(
            "notes",
            ""
        ).strip()

        if not service:
            error = "Service name is required."

        else:
            if not password:
                password = decrypted["password"]

            encrypted_data, nonce = encrypt_entry(
                key,
                service,
                username,
                password,
                notes
            )

            update_vault_entry(
                entry_id,
                g.user["id"],
                encrypted_data,
                nonce
            )

            return redirect(
                url_for("vault")
            )

        entry = {
            "service": service,
            "username": username,
            "password": password,
            "notes": notes,
        }

    return render_template(
        "entry_form.html",
        form_title="Edit entry",
        error=error,
        entry=entry,
        is_edit=True
    )


@app.route(
    "/vault/<int:entry_id>/delete",
    methods=["POST"]
)
@login_required
def remove_entry(entry_id):
    delete_vault_entry(
        entry_id,
        g.user["id"]
    )

    return redirect(
        url_for("vault")
    )


if __name__ == "__main__":
    init_db()

    ssl_context = "adhoc" if USE_HTTPS else None
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True,
        ssl_context=ssl_context
    )
