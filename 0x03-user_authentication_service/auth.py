#!/usr/bin/env python3
"""Authentication helper functions."""

from typing import Union
from uuid import uuid4
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


def _generate_uuid() -> str:
    """
    Generates a random UUID (Universally Unique Identifier)
    as a hexadecimal string.

    Returns:
        str: A random UUID represented as a hexadecimal string.
    """
    return uuid4().hex


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
                email=email,
                hashed_password=_hash_password(password).decode())
        raise ValueError("User {} already exists".format(email))

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate a user's login credentials.

        Args:
            email (str): The email of the user attempting to log in.
            password (str): The plain text password of the user.

        Returns:
            bool: True if the login credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        return bcrypt.checkpw(password.encode(), user.hashed_password.encode())

    def create_session(self, email: str) -> Union[str, None]:
        """
        Create a session for the user with the provided email.

        If a user with the given email exists, a session identifier (UUID) is
        generated and returned. Otherwise, None is returned.

        Args:
            email (str): The email of the user to create a session for.

        Returns:
            Union[str, None]: A session identifier (UUID) if the user exists,
                otherwise None.
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        return _generate_uuid()
