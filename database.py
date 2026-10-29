import sqlite3
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parent / "password_manager.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            vault_salt BLOB NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            encrypted_data BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    connection.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    connection.commit()
    connection.close()

def add_vault_entry(user_id, service, encrypted_data, nonce):
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO vault_entries (
            user_id,
            service,
            encrypted_data,
            nonce
        )
        VALUES (?, ?, ?, ?)
        """,
        (user_id, service, encrypted_data, nonce)
    )

    connection.commit()
    connection.close()


def get_vault_entries(user_id):
    connection = get_connection()

    entries = connection.execute(
        """
        SELECT id, service, encrypted_data, nonce
        FROM vault_entries
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,)
    ).fetchall()

    connection.close()

    return entries


def get_vault_entry(entry_id, user_id):
    connection = get_connection()

    entry = connection.execute(
        """
        SELECT id, service, encrypted_data, nonce
        FROM vault_entries
        WHERE id = ?
          AND user_id = ?
        """,
        (entry_id, user_id)
    ).fetchone()

    connection.close()

    return entry


def update_vault_entry(
    entry_id,
    user_id,
    service,
    encrypted_data,
    nonce
):
    connection = get_connection()

    connection.execute(
        """
        UPDATE vault_entries
        SET service = ?,
            encrypted_data = ?,
            nonce = ?
        WHERE id = ?
          AND user_id = ?
        """,
        (
            service,
            encrypted_data,
            nonce,
            entry_id,
            user_id
        )
    )

    connection.commit()
    connection.close()


def delete_vault_entry(entry_id, user_id):
    connection = get_connection()

    connection.execute(
        """
        DELETE FROM vault_entries
        WHERE id = ?
          AND user_id = ?
        """,
        (entry_id, user_id)
    )

    connection.commit()
    connection.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized.")