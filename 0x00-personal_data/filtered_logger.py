#!/usr/bin/env python3
''' use of regex in replacing occurrences of certain field values'''
import re
from typing import List


def filter_datum(
        fields: List[str], redaction: str,
        message: str, separator: str
        ) -> str:
    '''eturns the log message obfuscated'''
    for field in fields:
        message = re.sub(
                f'{field}=(.*?){separator}',
                f'{field}={redaction}{separator}', message)
        return message
