#!/usr/bin/env python3
"""Basic flask app."""

from flask import Flask, abort, jsonify, make_response, redirect, request
from auth import Auth


AUTH = Auth()

app = Flask(__name__)


@app.get('/', strict_slashes=False)
def index():
    """
    Handles the index route.

    Returns:
        Response: A JSON response with a welcome message.
    """
    return jsonify({'message': 'Bienvenue'})


@app.post('/users', strict_slashes=False)
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

        return jsonify({"email": user.email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.post('/sessions', strict_slashes=False)
def login():
    """
    Logs in a user with the provided email and password.

    Extracts email and hashed password from the request form, validates
    the login credentials, and creates a session if the login is successful.

    Returns:
        Response: A JSON response with a message and HTTP status code.
            - 200: Logged in successfully.
            - 401: Unauthorized access (invalid credentials).
    """
    email = request.form['email']
    h_pwd = request.form['password']

    if not AUTH.valid_login(email, h_pwd):
        abort(401)
    session = AUTH.create_session(email)

    res = make_response(jsonify({"email": email, "message": "logged in"}))
    res.set_cookie('session_id', session)
    return res


@app.post('/reset_password', strict_slashes=False)
def get_reset_password_token():
    """
    Generates a password reset token for the user with the given email.

    Extracts the email from the request form, attempts to
    generate a reset token, and returns it in a JSON response.
    If no user is found with the provided email,
    it aborts the request with a 403 status code.

    Returns:
        Response: A JSON response containing the email and reset token if
        successful, otherwise a 403 error.
    """
    email = request.form['email']

    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token})


@app.put('/reset_password', strict_slashes=False)
def update_password():
    """
    Updates the user's password using the provided email,
    reset token, and new password.

    Extracts the email, reset token, and new password from the request form.
    Attempts to update the user's password using the reset token. If the reset
    token is invalid, it aborts the request with a 403 status code.

    Returns:
        Response: A JSON response containing the email and a success message if
        the password is updated successfully, otherwise a 403 error.
    """
    email = request.form['email']
    reset_token = request.form['reset_token']
    new_p_wrd = request.form['new_password']

    try:
        AUTH.update_password(reset_token, new_p_wrd)
    except ValueError:
        abort(403)

    return jsonify({"email": email, "message": "Password updated"})


@app.delete('/sessions')
def logout():
    """
    Logs out the user by destroying the session.

    Retrieves the session ID from the request cookies and attempts to get the
    user associated with that session. If no user is found, it aborts the
    request with a 403 status code. If the user is found, it redirects to the
    homepage.

    Returns:
        Response: A redirect response to the homepage.
    """
    session_id: str = request.cookies.get("session_id")

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    return redirect('/', code=302)


@app.get('/profile')
def profile():
    """
    Retrieves the profile information of the logged-in user.

    Extracts the session ID from the request cookies and attempts to get the
    user associated with that session. If no user is found, it aborts the
    request with a 403 status code. If the user is found, it returns a JSON
    response with the user's email.

    Returns:
        Response: A JSON response containing the user's email if authenticated,
        otherwise a 403 error.
    """
    session_id: str = request.cookies.get("session_id")

    user = AUTH.get_user_from_session_id(session_id)

    if user is None:
        abort(403)

    return jsonify({"email": user.email})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
