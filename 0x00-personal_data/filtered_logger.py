#!/usr/bin/env python3
''' use of regex in replacing occurrences of certain field values'''
import re
from typing import List


def filter_datum(
        fields: List[str], redaction: str, message: str,
        separator: str
        ) -> str:
    return re.sub(f"({'|'.join(fields)})=.*?{separator}",
                  lambda m: f"{m.group(1)}={redaction}{separator}", message)
