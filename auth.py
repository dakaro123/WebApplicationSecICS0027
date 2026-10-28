import secrets
import sqlite3
import time
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import g, redirect, url_for

from database import get_connection


password_hasher = PasswordHasher()

SESSION_LIFETIME = 30 * 60


def create_user(username, password):
    password_hash = password_hasher.hash(password)
    vault_salt = secrets.token_bytes(16)

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO users (username, password_hash, vault_salt)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, vault_salt)
        )
        connection.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    finally:
        connection.close()


def authenticate_user(username, password):
    connection = get_connection()

    user = connection.execute(
        """
        SELECT id, username, password_hash
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    connection.close()

    if user is None:
        return None

    try:
        password_hasher.verify(user["password_hash"], password)
        return user

    except VerifyMismatchError:
        return None


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + SESSION_LIFETIME

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO sessions (token, user_id, expires_at)
        VALUES (?, ?, ?)
        """,
        (token, user_id, expires_at)
    )

    connection.commit()
    connection.close()

    return token


def get_user_by_session(token):
    if token is None:
        return None

    current_time = int(time.time())

    connection = get_connection()

    user = connection.execute(
        """
        SELECT users.id, users.username
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ?
          AND sessions.expires_at > ?
        """,
        (token, current_time)
    ).fetchone()

    connection.close()

    return user


def delete_session(token):
    if token is None:
        return

    connection = get_connection()

    connection.execute(
        "DELETE FROM sessions WHERE token = ?",
        (token,)
    )

    connection.commit()
    connection.close()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view