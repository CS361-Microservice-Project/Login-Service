# Login Microservice (Flask)
A simple REST microservice that validates username/password logins and enforces a basic lockout policy.

## What it does
- Accepts a username and password via `POST /login`
- Validates request format (types and length rules)
- Checks credentials against a small in-memory user list
- Locks an account for a short time after too many failed attempts

## Requirements
- Python 3.x
- Flask
