#!/usr/bin/env python3
"""Basic flask app."""

from flask import Flask, jsonify, request
from auth import Auth


AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=["GET"], strict_slashes=False)
def index():
    """
    Handles the index route.

    Returns:
        Response: A JSON response with a welcome message.
    """
    return jsonify({'message': 'Bienvenue'})


@app.route('/users', methods=["POST"], strict_slashes=False)
def users():
    """
    Registers a new user with the provided email and password.

    Extracts email and password from the request form, attempts to register
    the user, and returns an appropriate JSON response.

    Returns:
        Response: A JSON response with a message and HTTP status code.
            - 201: User successfully created.
            - 400: Email already registered.
    """
    email = request.form['email']
    h_pwd = request.form['password']

    try:
        user = AUTH.register_user(email, h_pwd)

        return jsonify({"email": user.email, "message": "user created"}), 201
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
