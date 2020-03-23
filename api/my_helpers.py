import re

from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from rest_framework.pagination import PageNumberPagination


def serialize_and_paginate(queryset, request, model_serializer, pagination=PageNumberPagination, page_size=10):
    """

    :param request: request
    :param queryset: The queryset of the response
    :param model_serializer: Serializer class of the queryset
    :param pagination: pagination class
    :param page_size: elements per page
    :return: paginated response
    """

    paginator = pagination()
    paginator.page_size = page_size

    result_page = paginator.paginate_queryset(queryset, request)
    serializer = model_serializer(result_page, many=True)

    return paginator.get_paginated_response(serializer.data)


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
