from rest_framework import permissions


class IsAuthenticatedAndEmailConfirmed(permissions.IsAuthenticated):
    """
    Permission to check if user is logged and has confirmed his email.
    """

    def has_permission(self, request, view):
        return permissions.IsAuthenticated.has_permission(self, request, view) and \
               request.user.userprofile.email_confirmed is True


class HasNotTempPassword(permissions.BasePermission):
    """
    Permission to check if user is not logged with a temporary password.
    """

    def has_permission(self, request, view):
        return not request.user.userprofile.password_reset
