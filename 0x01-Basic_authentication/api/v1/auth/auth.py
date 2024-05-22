#!/usr/bin/env python3
"""Auth Module

Contains the implemetation of the Auth class
"""
from typing import List, TypeVar
import requests


class Auth:
    """Auth class

        This class manages the API authentication.

        Attributes:
          require_auth(path: str, excluded_path: List[str]) -> bool
          authorization_header(request=None) -> str
          current_user(request=None) -> TypeVar('User')
        """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if authentication is required for a given path.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): A list of paths that do not require
                authentication.

        Returns:
            bool: False (placeholder implementation).
        """
        if path is None:
            return True
        if excluded_paths is None or len(excluded_paths) == 0:
            return True
        if not path.endswith("/"):
            path += "/"
        if path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the authorization header from the request.

        Args:
            request (Optional[Request]): The request object. Default is None.

        Returns:
            Optional[str]: None (placeholder implementation).
        """
        if request is None:
            return None

        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request.

        Args:
            request (Optional[Request]): The request object. Default is None.

        Returns:
            Optional[User]: None (placeholder implementation).
        """
        return None
