import re

from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator


def is_blank(my_string):
    """
    Check if my_string is blank.
    """
    return not (my_string and my_string.strip())


def is_string_valid_un(my_string):
    if my_string is None:
        return True
    ret = re.search(r'[^a-zA-Z0-9_@-]+', my_string)
    if ret is None:
        return True
    return False


def is_string_valid(my_string):
    if my_string is None:
        return True
    ret = re.search(r'[^a-zA-Z\s]+', my_string)
    if ret is None:
        return True
    return False


def is_string_valid_email(my_string):
    validator = EmailValidator()
    try:
        validator(my_string)
    except ValidationError as ve:
        return False, ve
    return True, None
