#!/usr/bin/env python3
"""0. Regex-ing"""
from typing import List
import os
import re
import logging

from mysql.connector.connection import MySQLConnection


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Constructor function
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats a log record

            Args:
                record: the record to format
            Returns:
                a string representing the formatted record
        """
        record.msg = filter_datum(fields=self.fields,
                                  message=record.getMessage(),
                                  redaction=self.REDACTION,
                                  separator=self.SEPARATOR,)
        return super().format(record)


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str,) -> str:
    """Obfuscates messages.

        Args:
            fields: list of strings representing all fields to obfuscate
            redaction:  string representing by what the field will be replaced
            message: string representing the log line
            separator: character separating all fields in the message
        Returns:
            The obfuscated messages seperated by {seperator}
    """
    for v in message.split(separator):
        if v.split('=')[0] in fields:
            message = re.sub("{}".format(v.split("=")[1]), redaction, message)
    return message


def get_logger() -> logging.Logger:
    """
    Creates and configures a logger for user data.

    The logger will have a stream handler with a redacting formatter to
    handle sensitive information.

    Returns:
        logging.Logger: Configured logger for user data.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(fields=list(PII_FIELDS)))

    logger = logging.getLogger(name="user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)

    return logger


def get_db() -> MySQLConnection:
    """
    Creates and returns a connection to the MySQL database.

    The connection details are retrieved from environment variables:
    - PERSONAL_DATA_DB_NAME
    - PERSONAL_DATA_DB_PASSWORD
    - PERSONAL_DATA_DB_USERNAME
    - PERSONAL_DATA_DB_HOST

    Returns:
        MySQLConnection: A connection to the MySQL database.
    """
    env = os.environ

    db_name = env.get("PERSONAL_DATA_DB_NAME")
    db_pass = env.get("PERSONAL_DATA_DB_PASSWORD", "")
    db_user = env.get("PERSONAL_DATA_DB_USERNAME", "root")
    db_host = env.get("PERSONAL_DATA_DB_HOST", "localhost")

    return MySQLConnection(user=db_user, password=db_pass,
                           host=db_host,
                           database=db_name)
