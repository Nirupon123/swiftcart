# shared/permissions.py
from rest_framework.permissions import BasePermission
from django.core.cache import cache
from django.contrib.auth import get_user_model

User = get_user_model()

class HasRequiredPermission(BasePermission):
    """
    Global Permission Class that checks Redis for user permissions 
    before allowing access to a view.
    """

    def has_permission(self, request, view):
        if not request.user or not isinstance(request.user, dict):
            return False

        user_id = request.user.get('user_id')
        required_perm = getattr(view, 'required_permission', None)
        if not required_perm:
            return True

        cache_key = f"perms:{user_id}"
        permissions = cache.get(cache_key)

        if permissions is None:
            try:
                user_obj = User.objects.get(id=user_id)
                permissions = list(user_obj.get_all_permissions())
                cache.set(cache_key, permissions, timeout=7200)
            except User.DoesNotExist:
                return False

        return required_perm in permissions


class IsInternalUser(BasePermission):
    """
    Allows access only to users whose account_type is 'internal'.
    Works with the StatelessUser returned by JWTStatelessAuthentication.
    """
    def has_permission(self, request, view):
        if not request.user or not hasattr(request.user, 'get'):
            return False
        return request.user.get('account_type') == 'internal'