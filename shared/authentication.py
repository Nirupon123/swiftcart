import jwt 
from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed



class JWTStatelessAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise AuthenticationFailed('No token provided')
        
        try:
            token = auth_header.split(' ')[1]
        except IndexError:
            raise AuthenticationFailed('Invalid token header')
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        
        jti = jwt.get_jti(token)
        if not jti:
            raise AuthenticationFailed("missing jti")
        

        # DRF expects a tuple of (user, auth_token). 
        # By returning the payload as the 'user', downstream views can access 
        # request.user.get('user_id') without ever touching the PostgreSQL database.

        if cache.get(f"denylist:{jti}"):
            raise AuthenticationFailed("Token has been revoked")

        return (payload, token)