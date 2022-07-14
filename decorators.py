
import jwt
from flask import request, abort

from constants import JWT_SECRET, JWT_ALG


def auth_required(func):
    def wrapper(*args, **kwargs):
        if "Authorisation" not in request.headers:
            abort(401)
        token = request.headers["Authorisation"]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception as e:
            print(f"JWT decode error: {e}")
            abort(401)
        return func(*args, **kwargs)

    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        if "Authorisation" not in request.headers:
            abort(401)
        token = request.headers["Authorisation"]
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception as e:
            print(f"JWT decode error: {e}")
            abort(401)
        if data["role"] == "admin":
            return func(*args, **kwargs)
        abort(403)

    return wrapper
