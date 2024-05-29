#!/usr/bin/env python3

import requests

EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"

BASE_URL = "http://0.0.0.0:5000{}"


def register_user(email: str, passwd: str):
    """Tests user registration"""
    resp = requests.post(url=BASE_URL.format('/users'),
                         data={'email': email, 'password': passwd})

    assert resp.status_code == 200
    assert resp.json() == {'email': EMAIL, 'message': 'user created'}


def log_in_wrong_password(email: str, passwd: str):
    """Tests wrong password login"""
    resp = requests.post(url=BASE_URL.format('/sessions'),
                         data={'email': email, 'password': passwd})

    assert resp.status_code == 401


def profile_unlogged():
    """Test profile unloggedin"""
    resp = requests.get(url=BASE_URL.format('/profile'))

    assert resp.status_code == 403


def log_in(email: str, passwd: str) -> str:
    """Tests login correct password"""
    resp = requests.post(url=BASE_URL.format('/sessions'),
                         data={'email': email, 'password': passwd})

    assert resp.status_code == 200
    assert resp.json() == {'email': EMAIL, 'message': 'logged in'}
    s_id = resp.cookies.get('session_id')

    assert s_id is not None
    return s_id


def profile_logged(session_id: str):
    """Tests profile logged in"""
    resp = requests.get(
        url=BASE_URL.format('/profile'),
        cookies={'session_id': session_id})

    assert resp.status_code == 200
    assert resp.json() == {'email': EMAIL}


def log_out(session_id: str):
    """Tests log out"""
    resp = requests.delete(
        url=BASE_URL.format('/sessions'),
        cookies={'session_id': session_id})

    assert resp.status_code == 200
    assert resp.json() == {'message': 'Bienvenue'}


def reset_password_token(email: str) -> str:
    """Tests get request token"""
    resp = requests.post(url=BASE_URL.format('/reset_password'),
                         data={'email': email})

    assert resp.status_code == 200
    r_id = resp.json().get('reset_token')
    assert r_id is not None
    return r_id


def update_password(email: str, reset_token: str, new_passwd: str):
    """Tests update password from request token"""
    resp = requests.put(url=BASE_URL.format('/reset_password'),
                        data={'email': email,
                              'new_password': new_passwd,
                              'reset_token': reset_token})

    assert resp.status_code == 200
    assert resp.json() == {'email': EMAIL, 'message': 'Password updated'}


if __name__ == "__main__":
    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
