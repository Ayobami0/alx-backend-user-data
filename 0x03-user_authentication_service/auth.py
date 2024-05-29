#!/usr/bin/env python3
"""Authentication helper functions."""

import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB, User


def _hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The plain text password to hash.

    Returns:
        bytes: The hashed password.
    """
    return bcrypt.hashpw(password=password.encode(), salt=bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user with the provided email and password.

        Args:
            email (str): The email of the user to register.
            password (str): The plain text password of the user.

        Returns:
            User: The newly created user object.

        Raises:
            ValueError: If a user with the given email already exists.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(
                email=email, hashed_password=_hash_password(password).decode())
        raise ValueError("User {} already exists".format(email))
