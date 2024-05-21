#!/usr/bin/env python3
"""0. Regex-ing"""

import re
from typing import List


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
    return ';'.join([re.sub(r'(?<={}\=).*'.format(v.split('=')[0]), redaction,
                            v) if v.split('=')[0] in fields else v
                     for v in message.split(separator)])
