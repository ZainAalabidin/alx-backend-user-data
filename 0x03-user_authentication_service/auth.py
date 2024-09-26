#!/usr/bin/env python3
"""
authentication module
"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register new users
            Args:
                - email: user's email
                - password: user's password
            Return:
                user object
        """
        db = self._db
        try:
            user = db.find_user_by(email=email)
        except NoResultFound:
            user = db.add_user(email, _hash_password(password))
            return user
        else:
            raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """ Check the validation of user
            Args:
                - email: user's email
                - password: user's password
            Return:
                - boolean value
        """
        db = self._db
        try:
            user = db.find_user_by(email=email)
        except NoResultFound:
            return False
        if not bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
            return False
        return True

    def create_session(self, email: str) -> str:
        """ Create session for user.
            args:
                - email: user's email.
            Return:
                - session id
        """
        db = self._db
        try:
            user = db.find_user_by(email=email)
        except NoResultFound:
            return None
        session_id = _generate_uuid()
        db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """ Get user based on their session id
            Args:
                - session_id
            Return:
                - user if found rlse None
        """
        if not session_id:
            return None
        db = self._db
        try:
            user = db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """ Destroy user session.
            Args:
                - user_id
            Return:
                - None
        """
        db = self._db
        db.update_user(user_id, session_id=None)


def _hash_password(password: str) -> bytes:
    """
    method that take ink a password string argument and return bytes
    """
    e_pwd = password.encode()
    return bcrypt.hashpw(e_pwd, bcrypt.gensalt())


def _generate_uuid() -> str:
    """ Generate unique ids
        Return:
            - UUID
    """
    return str(uuid4())
