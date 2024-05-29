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
    return str(uuid4())


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
        generated, stored and returned. Otherwise, None is returned.

        Args:
            email (str): The email of the user to create a session for.

        Returns:
            Union[str, None]: A session identifier (UUID) if the user exists,
                otherwise None.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieves the user associated with the given session ID.

        If a user is found with the provided session ID, it returns the user
        object. Otherwise, it returns None.

        Args:
            session_id (str): The session identifier to look up.

        Returns:
            Union[User, None]: The user object if found, otherwise None.
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id) -> None:
        """
        Destroys the session associated with the given user ID.

        If a session is associated with the user ID, it updates the session ID
        to None, effectively destroying the session. If no session is found or
        an error occurs during the update, it silently ignores it.

        Args:
            user_id: The ID of the user whose session to destroy.
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except (NoResultFound, ValueError):
            pass

    def get_reset_password_token(self, email: str):
        """
        Generates a password reset token for the user with the given email.

        If a user with the provided email is found, a reset token is generated
        and saved in the database. The token is then returned. If no user is
        found, a ValueError is raised.

        Args:
            email (str): The email of the user requesting the password reset.

        Returns:
            str: The generated reset token.

        Raises:
            ValueError: If no user is found with the given email.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates the user's password using the provided
        reset token and new password.

        If a user with the given reset token is found,
        the user's password is updated with the new hashed password
        and the reset token is cleared.
        If no user is found, a ValueError is raised.

        Args:
            reset_token (str): The reset token associated
                with the user's password reset request.
            password (str): The new plain text password to set for the user.

        Raises:
            ValueError: If no user is found with the given reset token.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        self._db.update_user(
            user.id,
            hashed_password=_hash_password(password).decode(),
            reset_token=None
        )
