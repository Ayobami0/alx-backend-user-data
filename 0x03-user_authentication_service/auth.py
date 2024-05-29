#!/usr/bin/env python3
"""Authentication helper functions."""

import bcrypt


def _hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.

    Args:
        password (str): The plain text password to hash.

    Returns:
        bytes: The hashed password.
    """
    return bcrypt.hashpw(password=password.encode(), salt=bcrypt.gensalt())
