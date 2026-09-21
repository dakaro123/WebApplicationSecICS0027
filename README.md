# Web-Based Secure Password Manager

Semester project for ICS0027 Web Application Security and ICS0022 Secure Programming.

## Course use

This repository contains the password manager project I use for both
ICS0027 Web Application Security and ICS0022 Secure Programming.

The implementation is shared, but each course focuses on different security aspects.

- Web Application Security: web attacks, sessions, cookies, access control, XSS, CSRF and SQL injection.
- Secure Programming: cryptography, key handling, memory handling, input validation and secure implementation.

Course-specific checkpoint documents are stored separately in the `docs/websec` and `docs/secure-programming` directories.

## Scope

A web-based password manager that allows users to securely store and manage credentials.

## Planned Technology Stack

I kept the stack quite simple on purpose. For this project I want to understand how the security parts actually work instead of adding more technologies just to make the project look more complex.

- Python 3
- Flask
- Jinja2
- SQLite
- Argon2id
- AES-256-GCM
- Server-side sessions
- HTTPS/TLS

## Planned Features

- User registration
- User login and logout
- Encrypted credential storage
- View vault entries
- Add, edit and delete vault entries
- Secure session management
- Server-side input validation
- Protection against XSS, CSRF and SQL injection
- Per-user access control

## Planned Routes

- GET /register
- POST /register
- GET /login
- POST /login
- POST /logout
- GET /vault
- POST /vault
- POST /vault/<id>/edit
- POST /vault/<id>/delete

## Local Setup

There is no runnable application yet. For Checkpoint 1, the repository contains only the planned architecture and security design.

The application is planned to use Python 3 with Flask, Jinja2 and SQLite. Setup and run commands will be added during Checkpoint 2 together with the first working version.