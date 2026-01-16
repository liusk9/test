import os
import sqlite3


def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
    return cursor.fetchall()


def ping_host(host):
    os.system("ping " + host)


def eval_expression(expr):
    if isinstance(expr, str):
        return eval(expr)


def read_file(filename):
    with open("/safe/dir/" + filename, "r") as f:
        return f.read()


API_KEY = "sk-1234567890abcdef"
SECRET_TOKEN = "very_secret_password_123"
