# Login Microservice (Flask)

A simple REST microservice that validates username/password logins and enforces a basic lockout policy.

---

## What it does

- Accepts a username and password via `POST /login`
- Allows creation of new users via `POST /create-account`
- Validates request format (types and length rules)
- Stores user credentials securely (passwords hashed with SHA-256)
- Locks an account for a short time after too many failed attempts

---

## Requirements

- Python 3.x
- Flask

---

## API Usage

Base URL (default when running locally): `http://127.0.0.1:5000`

All requests and responses use JSON.

---

# Endpoint: POST /create-account

## Purpose

Creates a new user account.

- User records are stored in `login-records.json`
- Passwords are stored as **SHA-256 hashes**, not plaintext

---

## How to Request Data

Send a POST request to: `http://127.0.0.1:5000/create-account`
**Method:** POST  
**Header:** `Content-Type: application/json`

Validation Rules
- Username must be a string (3–32 characters)
- Password must be a string (1–72 characters)
- The body must be a valid JSON object

### JSON Body

```json
{
  "username": "new_user",
  "password": "new_password"
}
```

## Example Call for Requesting Data

```bash
curl -X POST http://127.0.0.1:5000/create-account \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
