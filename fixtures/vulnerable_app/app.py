"""VEYRON test fixtures.

All credentials below are FAKE and syntactically obvious placeholders used
only to verify secret redaction. No real credential exists in this repo.
"""

import os
import sqlite3


DB_PATH = os.environ.get("VEYRON_FIXTURE_DB", "app.db")


def insecure_query(user_id):
    """VULNERABLE ON PURPOSE: string-built SQL (CWE-89)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
    return cursor.fetchall()


def insecure_eval(user_input):
    """VULNERABLE ON PURPOSE: evaluating untrusted input (CWE-95)."""
    return eval(user_input)


def weak_hash(password):
    """VULNERABLE ON PURPOSE: MD5 for passwords (CWE-328)."""
    import hashlib

    return hashlib.md5(password.encode()).hexdigest()


def insecure_deserialize(data):
    """VULNERABLE ON PURPOSE: pickle loads on untrusted data (CWE-502)."""
    import pickle

    return pickle.loads(data)


# FAKE credential-shaped strings for redaction tests — NOT real secrets.
FAKE_API_KEY = "FAKE_API_KEY_FOR_TESTS_1234567890abcdef"
FAKE_PASSWORD = "fake-password-not-real-000111"
