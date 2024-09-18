#!/usr/bin/env python3
""" authentication model """
from flask import request
from typing import List, TypeVar
import fnmatch


class Auth:
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ determines if authentication is required for the given path. """
        if path is None:
            return True
        if excluded_paths is None or not excluded_paths:
            return True
        for excluded_paths in excluded_paths:
            if fnmatch.fnmatch(path.rstrip("/"), excluded_paths.rstrip("/")):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Method to get authorization """
        if request is not None:
            return request.headers.get("Authorization", None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Method to get user from request """
        return None
