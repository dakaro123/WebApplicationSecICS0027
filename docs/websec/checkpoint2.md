# Checkpoint 2 Progress

For Checkpoint 2 I continued the password manager and made the first working version of the application.

The main part I worked on was authentication, sessions and the encrypted vault.

## What I added

I added registration and login using a master password.

The master password is not stored directly. I use Argon2id for password hashing.

I also added server-side sessions. The session is stored in SQLite and the browser only gets a random session token.

The session cookie currently uses:

- `HttpOnly`
- `Secure`
- `SameSite=Strict`

The `/vault` page is protected and can only be opened after login.

For the vault I added basic CRUD functionality:

- add entry
- view entries
- edit entry
- delete entry

Vault usernames, passwords and notes are encrypted before they are stored in SQLite.

For encryption I use AES-256-GCM. The encryption key is derived from the master password using Argon2id and a separate salt.

I also check the user ID when loading or changing vault entries, so one user should not be able to access another user's entry just by changing the entry ID in the URL.

SQL queries use parameters instead of directly putting user input into SQL strings.

The application now also runs over HTTPS for development.

## Testing

I tested the main flow manually.

I checked:

- registration and login;
- wrong password;
- duplicate username;
- logout;
- access to `/vault` without login;
- adding, editing and deleting vault entries;
- restarting the application and logging in again;
- encrypted values directly in SQLite;
- access to another user's entry by changing the ID;
- basic SQL injection input;
- stored XSS strings;
- session cookie flags.

The encrypted data in SQLite did not contain the plaintext username, password or notes.

The XSS test strings were displayed as text and did not execute.

When I tried to open another user's vault entry by changing the entry ID, the application returned `404`.

## Run

Create and activate the virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Run:

```powershell
python app.py
```

The application runs at:

`https://127.0.0.1:5000`

The browser gives a certificate warning because I currently use a development self-signed certificate.

## Current state

This is still not the final version of the project.

CSRF protection is not implemented yet and I still want to improve session and key handling later.

For now I mainly wanted to get the main application flow working and add the security parts required for this checkpoint.

There is also a small joke on the home page because the old placeholder text was boring)