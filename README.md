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

## Request (How to request data)

**Method:** `POST`  
**Path:** `/create-account`  

### JSON Body

```json
{
  "username": "new_user",
  "password": "new_password"
}
