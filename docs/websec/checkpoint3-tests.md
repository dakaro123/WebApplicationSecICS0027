# Checkpoint 3 Security Testing

For Checkpoint 3 I repeated the main security tests and wrote down the payloads and results.

I used a temporary SQLite database during the tests, so the normal `password_manager.db` file was not changed.

## Test results

| Test | Payload or action | Expected result | Result |
|---|---|---|---|
| SQL injection | Login username: `' OR 1=1 --` | Login is not bypassed. | Passed. The application returned `Invalid username or password` and did not create a session. |
| Stored XSS | Service: `<script>alert('service')</script>` | The script is displayed as text and does not execute. | Passed. Jinja escaped the value before it was added to the page. |
| HTML injection | Username: `<img src=x onerror=alert('username')>` | The HTML element is not created. | Passed. The value was displayed as escaped text. |
| Per-user access control | User B requested `/vault/1/edit` for User A's entry. | User B cannot read the entry. | Passed. The application returned `404`. |
| Per-user delete protection | User B sent a delete request for User A's entry. | The entry is not deleted. | Passed. The database still contained User A's entry. |
| Unauthenticated access | Opened `/vault` without a session. | The vault is not displayed. | Passed. The request was redirected to `/login`. |
| CSRF protection | Sent a login POST without a token and with a wrong token. | Both requests are rejected. | Passed. Both requests returned generic `400` responses. |
| Logout | Reused the old session token after logout. | The old session is rejected. | Passed. The request was redirected to `/login` and the in-memory vault key was removed. |
| Session expiry | Changed a session expiry time to the past and reused the session. | The session and its key are removed. | Passed. The database session and `_session_keys` entry were removed. |
| Error handling | Requested a missing page and caused a test exception. | The browser does not receive a traceback or exception detail. | Passed. Generic `404` and `500` pages were returned. |
| Security headers | Requested the home page in HTTP and HTTPS modes. | The configured headers are present and HSTS is only used with HTTPS. | Passed. CSP, `nosniff`, frame protection and referrer policy were present. HSTS was added only in HTTPS mode. |
| Database storage | Saved unique service, username, password and notes values, then inspected `encrypted_data`. | Plaintext vault values are not present in SQLite. | Passed. None of the tested plaintext values were found in the encrypted database field. |
| Browser exposure | Opened the vault and edit pages after saving an entry. | The stored vault password is not returned in HTML. | Passed. The vault page only showed `stored securely`, and the edit password field did not contain the old password. |

All listed tests passed.

## Why the attacks did not work

### SQL injection

Database queries use `?` parameters. User input is passed separately from the SQL query, so the injection payload is treated as a normal username.

### XSS and HTML injection

Jinja automatic escaping is used when vault values are displayed. User-controlled values are not rendered with `|safe`.

The Content Security Policy also limits scripts to the same origin and blocks object content.

### Access control

Vault queries check both the entry ID and the current user ID. Changing only the entry ID is not enough to read, update or delete another user's entry.

### CSRF

Every POST form includes a random CSRF token. The server compares the form token with the token stored in a `SameSite=Strict` cookie before processing the request.

### Sessions

Logout deletes the database session and removes the related vault key from `_session_keys`.

Expired database sessions are cleaned before requests are processed. Their in-memory vault keys are removed at the same time.

### Error handling and logging

The browser receives generic error pages. Application log messages contain the request method, path and status, but do not include form data, passwords, cookies or encryption keys.

## Test limits

These tests cover the current application routes and the attack payloads listed above. They do not prove that the application has no other security problems.

The HTTPS test checks HSTS behaviour when `USE_HTTPS` is enabled. It does not perform a real TLS handshake or test a production TLS deployment.

Python does not guarantee that immutable `str` and `bytes` objects are overwritten in memory. The derived vault key also has to remain in process memory while the session is active. The application reduces the lifetime of this data, but it cannot guarantee secure memory zeroization in CPython.
