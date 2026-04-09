"""Deliberately vulnerable Python app for e2e testing."""
import os
import pickle
import sqlite3
import subprocess


def get_user(user_id):
    """SQL injection vulnerability."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()


def run_command(user_input):
    """Command injection vulnerability."""
    result = subprocess.call(f"echo {user_input}", shell=True)
    return result


def load_data(data):
    """Insecure deserialization."""
    return pickle.loads(data)


def read_file(filename):
    """Path traversal vulnerability."""
    path = os.path.join("/app/uploads", filename)
    with open(path, "r") as f:
        return f.read()


SECRET_KEY = "hardcoded_secret_key_12345"


def authenticate(password):
    """Hardcoded credentials."""
    if password == "admin123":
        return True
    return False
