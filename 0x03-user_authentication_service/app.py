#!/usr/bin/env python3
""" App module
"""
from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth

app = Flask(__name__)
app.url_map.strict_slashes = False
AUTH = Auth()


@app.route("/", methods=["GET"])
def home():
    """ Home endpoint
        Return:
            - logout message JSON represented
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users():
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """ login endpoint
        form fields:
            - email
            - password
        Return:
            - user email and login message JSON represwnted
            - 401 if credential are invaild
    """
    email = request.form.get("email")
    password = request.form.get("password")
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_id", session_id)
    return response


@app.route("/sessions", methods=["DELETE"])
def logout():
    """ Logout endpoint """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect(url_for("home"))


@app.route("/profile", methods=["GET"])
def profile() -> str:
    """ access user data using session_id
        Return:
            - user email JSON represented
            - 403 if session_id is not linked to any user
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    return jsonify({"email": user.email})


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """ Reset password token endpoint
        Form fiels:
            - email
        Return:
            - email and reset token JSON represented
            - 403 if email not associate with any user
    """
    email = request.form.get("email")
    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)
    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """ update password endpoint.
        Form fields:
            - email
            - reset_token
            - new_password
        Return:
            - user email and password message JSON represented
            - 403 if reset token is not provided or not linked to any user
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")
    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)
    return jsonify({"email": email, "message": "Password updated"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
