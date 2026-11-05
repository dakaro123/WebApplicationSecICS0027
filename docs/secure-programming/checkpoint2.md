# Checkpoint 2 Progress

Implemented a working version of the password manager.

Current progress:
- registration and login with Argon2id password hashing;
- vault key derivation from the master password;
- AES-256-GCM encryption for the full vault entry;
- add, edit and delete vault entries;
- encrypted data stored in SQLite without plaintext credentials;
- session-based access to the vault;
- existing passwords are not sent back to the browser during editing.

The application can be built and run using the instructions in `README.md`.