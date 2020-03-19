from rest_framework import permissions


class IsAuthenticatedAndEmailConfirmed(permissions.IsAuthenticated):
    """
    Object-level permission to only allow owners of an object to edit it.
    Assumes the model instance has an `owner` attribute.
    """

    def has_permission(self, request, view):

        return permissions.IsAuthenticated.has_permission(self, request, view) and \
               request.user.userprofile.email_confirmed is True
