# Login Microservice - A REST microservice for validating username/password logins with a lockout policy.
# Uses Flask + hashlib

from flask import Flask, request, jsonify
import hashlib
import json
import time


class loginRecC:
    def __init__(self, user: str, pword: str):
        self.user = user
        self.pword = pword
    def toDict(self):
        return self.__dict__


jsonfile = "login-records.json"


def save_login(loginLst):
    """
    save_login: Saves the list of login records to the open JSON file.\n
    Prerequisites: The variable "jsonfile" points to the JSON file containing the records.
    Arguments: loginLst (list of loginRecCs).\n
    Returns: Nothing.
    """
    data = [l.toDict() for l in loginLst]
    with open(jsonfile, "w") as f:
        json.dump(data, f, indent=4)


# CONFIG: Basic settings for lockout behavior.
# MAX_ATTEMPTS is how many failed tries are allowed before locking.
# LOCK_SECONDS is how long the account stays locked after too many failed tries.
MAX_ATTEMPTS = 3
LOCK_SECONDS = 60


def hash_password(pword: str):
    """
    hash_password: Converts a plain password into a SHA-256 hex hash string.\n
    Prerequisites: pword is a string.\n
    Arguments: pword (str).\n
    Returns: str, a hex hash of the password. 
    """
    # Encode the string as bytes, hash it, then convert to hex text.
    return hashlib.sha256(pword.encode("utf-8")).hexdigest()


# logs: Database of accounts for this assignment.
# IMPORTANT: Passwords are stored as hashes, not plain text.
with open(jsonfile, "r") as f:
    data = json.load(f)
    logs = [loginRecC(**d) for d in data]


def addPword(user: str, pword: str):
    """
    addPword: Updates a loginRecC with a hashed password.\n
    Prerequisites: None.\n
    Arguments: user (str); pword (str)\n
    Returns: Nothing, updates log if user matches.
    """
    for log in logs:
        if log.user == user:
            log.pword = hash_password(pword)
            print(f"hashed pword is {log.pword}")


# failed_attempts: Tracks how many bad password attempts each username has.
# Key: username (str)
# Value: int number of failed attempts since last successful login or lockout.
failed_attempts = {}


# locked_until: Tracks the lockout end time for each username.
# Key: username (str)
# Value: Unix timestamp (float). If locked_until[user] > current_time, the account is locked.
locked_until = {}


# app: The Flask web server object.
app = Flask(__name__)



def is_valid_format(username, password):
    """
    is_valid_format: Checks whether username and password are valid types and acceptable lengths.\n
    Prerequisites: None.\n
    Arguments: username (any), password (any).\n
    Returns: bool, True if format is valid; False otherwise.
    """
    # Username and password must both be strings.
    if type(username) is not str or type(password) is not str:
        return False

    # Username length rule: 3 to 32 characters.
    if len(username) < 3 or len(username) > 32:
        return False

    # Password length rule: 1 to 72 characters.
    if len(password) < 1 or len(password) > 72:
        return False

    return True


def is_locked(username):
    """
    is_locked: Checks whether a user is currently locked out.\n
    Prerequisites: username is a string.\n
    Arguments: username (str).\n
    Returns: bool, True if locked; False if not locked."""
    # Get the lock time for this user. If it doesn't exist, treat it as 0.
    lock_time = locked_until.get(username, 0)

    # If lock_time is in the future, the account is locked.
    if lock_time > time.time():
        return True

    return False


def record_failed_attempt(username):
    """
    record_failed_attempt: Increases failed attempt count and locks the user if needed.\n
    Prerequisites: username is a string.\n
    Arguments: username (str).\n
    Returns: str, either "locked" if the user just got locked, or "invalid_credentials" otherwise.
    """
    # Increase the failed attempt count by 1.
    failed_attempts[username] = failed_attempts.get(username, 0) + 1

    # If the user has hit the max, lock them and reset the counter.
    if failed_attempts[username] >= MAX_ATTEMPTS:
        locked_until[username] = time.time() + LOCK_SECONDS
        failed_attempts[username] = 0
        return "locked"

    # Otherwise, it is just a normal invalid login.
    return "invalid_credentials"



def reset_user_state(username):
    """
    reset_user_state: Clears failed attempts and lock state for a user after a successful login.\n
    Prerequisites: username is a string.\n
    Arguments: username (str).\n
    Returns: None
    """
    # Reset failed attempts back to 0.
    failed_attempts[username] = 0

    # Set locked_until to 0 so the user is not locked.
    locked_until[username] = 0



@app.post("/login")
def login():
    """
    login: Endpoint for POST /login. Validates request, checks lockout, verifies password, returns JSON status.\n
    Prerequisites: Request must be JSON with keys "username" and "password".\n
    Arguments: None (uses Flask request).\n
    Returns: Flask response (JSON) with one of these status values:\n
    "ok", "locked", "invalid_format", "invalid_credentials"
    """
    # Get the JSON body. silent=True means it returns None instead of throwing an error.
    data = request.get_json(silent=True)

    # If the body isn't a JSON object, return invalid_format.
    if type(data) is not dict:
        return jsonify({"status": "invalid_format"}), 400

    # Pull username and password out of the JSON.
    username = data.get("username")
    password = data.get("password")

    # Validate type/length rules.
    if not is_valid_format(username, password):
        return jsonify({"status": "invalid_format"}), 400

    # If the account is locked, return locked.
    if is_locked(username):
        return jsonify({"status": "locked"}), 200

    # Find the stored hash for this username.
    # If username does not exist, treat it like invalid credentials (do not reveal existence).
    stored_hash = None
    for log in logs:
        if log.user == username:
            stored_hash = log.pword

    # If user is missing, count it as a failed attempt and return invalid credentials or locked.
    if stored_hash is None:
        result = record_failed_attempt(username)
        return jsonify({"status": result}), 200

    # Hash the incoming password and compare it to the stored hash.
    incoming_hash = hash_password(password)

    # If the hashes do not match, count it as a failed attempt.
    if incoming_hash != stored_hash:
        result = record_failed_attempt(username)
        return jsonify({"status": result}), 200

    # If we reached here, the login is correct.
    # Reset failed attempts and lock state.
    reset_user_state(username)

    # Return ok status.
    return jsonify({"status": "ok"}), 200



def main():
    """
    main: Starts the Flask server on localhost port 5001.\n
    Prerequisites: Flask installed.\n
    Arguments: None.\n
    Returns: None (runs until stopped).
    """
    # debug=False so it behaves more like a normal service.
    # host="127.0.0.1" means local machine only (not open to the internet).
    app.run(host="127.0.0.1", port=5001, debug=False)


main()