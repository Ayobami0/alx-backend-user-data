#!/usr/bin/env python3
"""DB module."""
from sqlalchemy import create_engine
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session

from user import Base, User


class DB:
    """DB class."""

    def __init__(self) -> None:
        """Initialize a new DB instance."""
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object."""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a user to the database.

            Args:
                email: user's email
                hashed_password: an hash of the user's password
            Returns:
                The newly added user
        """
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)

        res = self._session.query(User).filter_by(email=new_user.email).first()

        return res

    def find_user_by(self, **kwargs):
        """Finds users by provided keywords aguments 

            Args:
                kwargs: arbitrary keyword arguments
            Returns:
                the first row found in the database
        """
        try:
            res = self._session.query(User).filter_by(**kwargs).first()
        except TypeError:
            raise InvalidRequestError
        if res is None:
            raise NoResultFound

        return res
