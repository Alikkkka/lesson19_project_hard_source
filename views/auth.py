from flask_restx import Namespace, Resource
from flask import request
from implemented import auth_service
auth_ns = Namespace('auth')


@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        req_json = request.json
        username = req_json.get("username")
        password = req_json.get("password")
        if not (username or password):
            return "Недостаточно данных: нужны имя и пароль", 400
        try:
            tokens = auth_service.generate_tokens(username, password)
            return tokens

        except Exception:
            return "Ошибка :(", 400

    def put(self):
        req_json = request.json
        refresh_token = req_json.get("refresh_token")
        if not refresh_token:
            return "", 400
        try:
            tokens = auth_service.approve_refresh_token(refresh_token)
            return tokens
        except Exception:
            return "Ошибка :(", 400
