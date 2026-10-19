# Secure REST API (Lab 1)

A deliberately-hardened Flask REST API built for the HDU Information Security lab.
It demonstrates protections against the OWASP Top 10 (SQL injection, XSS, broken
authentication), automated security scanning in GitHub Actions (SAST + SCA), and a
full reproduce / root-cause / fix cycle for a real CVE grabbed from **Vulhub**.

**Student:** hongzhixuan · **HDU ID:** 23320328

---

## 1. Project & API

A minimal Flask + SQLite backend with JWT authentication. Only two binary decision
points matter: `POST /auth/login` exchanges valid credentials for a signed JWT, and
the GET endpoints accept only requests carrying that token.

### Endpoints

| Method | Path            | Auth     | Description                                          |
|--------|-----------------|----------|------------------------------------------------------|
| POST   | `/auth/login`   | no       | Body `{username, password}` → issues a JWT on success|
| GET    | `/api/data`     | **JWT**  | Returns data + a list of users                       |
| GET    | `/api/profile`  | **JWT**  | Returns the caller's (3rd, self-designed) endpoint   |

### Running locally

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt       # (or .venv\Scripts\pip.exe on Windows)
.venv/bin/python app.py                          # serves on http://127.0.0.1:5000
```

A default `admin` user (password `pass1234`) is seeded on first run. **In a real
deployment** the password, the JWT secret and `FLASK_DEBUG` must all come from
secrets/environment variables and a proper WSGI server should be used.

### Example API calls

```bash
# 1) no token -> rejected (401)
curl http://127.0.0.1:5000/api/data

# 2) login -> get a token
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass1234"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 3) with token -> 200
curl http://127.0.0.1:5000/api/data -H "Authorization: Bearer $TOKEN"
```

Run the smoke tests with:

```bash
python test_app.py    # 6 unit tests, no live server needed
```

---

## 2. Implemented security measures

### 2.1 SQL injection (SQLi) — parameterized queries / ORM
All database access goes through the **SQLAlchemy ORM** using `filter_by`.
Queries are built by binding values as parameters, never by string concatenation,
so attacker input can never become part of the SQL syntax. See `app.py` →
`User.query.filter_by(username=username)`. The unit test
`test_sql_injection_username_is_ineffective` proves that `admin' OR '1'='1`
is treated as a literal username and fails to log in.

### 2.2 Cross-Site Scripting (XSS) — output escaping
Every value that flows back to a client is passed through `html.escape()`
(e.g. `html.escape(f"Hello user {current_user}")` in `/api/data`). This neutralizes
any script tags or event handlers the user might try to inject.

### 2.3 Broken authentication — JWT + slow password hashing
- Passwords are stored only as **bcrypt** hashes (salt + adaptive work factor,
  deliberately slow to resist offline brute force) — never in plaintext.
- On successful login the server issues a **JWT** signed with HMAC-SHA256
  (`create_access_token`).
- A JWT-protected route decorator (`@jwt_required()`) rejects requests without a
  valid token with `401`, and tampered/altered tokens with `422`.

### 2.4 Configuration hardening
- `JWT_SECRET_KEY` is read from an environment variable, never committed. The
  dev fallback is ≥ 32 bytes to satisfy RFC 7518's minimum HMAC key length
  (avoids `InsecureKeyLengthWarning`).
- `FLASK_DEBUG` is added to the dev-only code path; the server runs with the
  interactive debugger **off** by default (relevant to the CVE below).
- The login endpoint validates `Content-Type`/JSON input and returns `400` for
  missing or malformed fields instead of crashing.

---

## 3. CI/CD with security scanners (SAST + SCA)

`.github/workflows/ci.yml` runs on every `push` and `pull_request`:

1. **SAST — Bandit**: statically analyses `app.py` for known bad patterns.
2. **SCA — Safety**: audits `requirements.txt` dependencies against known CVEs.
3. **Functional — `test_app.py`**: 6 assertions covering auth flow + injection
   defense.

Both scanner JSON reports are attached as Actions artifacts.

> Screenshots of the latest pipeline run (Actions → Security CI) are embedded in the
> submitted PDF report; the job currently reports **0 issues** from Bandit and
> **0 reported vulnerabilities** from Safety.

---

## 4. Selected vulnerability: CVE

**Chosen CVE:** *CVE-2018-1000656* (Flask debug-mode Server-Side Template Injection) —
reproduced from the Vulhub environment `vulhub/flask/CVE-2018-1000656`.

### 4.1 Overview
... *(filled from the Vulhub README during reproduction)*

### 4.2 Reproduction steps
... *(with commands + screenshots)*

### 4.3 Root-cause analysis
... *(explained in my own words)*

### 4.4 The fix
... *(what was changed and why)*

### 4.5 Proof the vulnerability is gone
... *(same attack against the fixed build)*

---

## 5. License / compliance

Educational use only — never point scanners/exploitation at systems you do not own.