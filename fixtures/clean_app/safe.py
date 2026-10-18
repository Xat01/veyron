import os

SAFE_MODE = True


def healthy_view():
    # Parameterised query — the safe pattern, used as a contrast fixture.
    return "SELECT * FROM users WHERE id = ?"
