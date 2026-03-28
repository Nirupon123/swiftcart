import jwt
from django.conf import settings
from django.core.cache import cache
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed


class StatelessUser(dict):
    """
    A dict subclass that acts as a user object for stateless JWT auth.
    - Inherits dict so views can call request.user.get('user_id').
    - Exposes is_authenticated so DRF's IsAuthenticated permission works.
    """
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True


class JWTStatelessAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        try:
            token = auth_header.split(' ')[1]
        except IndexError:
            raise AuthenticationFailed('Invalid token header')

        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')

        jti = payload.get('jti')
        if not jti:
            raise AuthenticationFailed('Missing jti claim')

        if cache.get(f'denylist:{jti}'):
            raise AuthenticationFailed('Token has been revoked')

        # Return StatelessUser (dict subclass) so downstream views can call
        # request.user.get('user_id') AND IsAuthenticated works correctly.
        return (StatelessUser(payload), token)