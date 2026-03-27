import jwt
import uuid6
from datetime import datetime,timedelta,timezone
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.cache import cache
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

class LoginView(APIView):
    permission_classes = [AllowAny] 

    def post(self, request):
        email = request.data.get('email')   #username
        password = request.data.get('password')

        # Database Authentication
        user = authenticate(username=email, password=password)
        if not user:
            return Response(
                {"error": "Invalid credentials"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )

        #Gather Permissions
        permissions=list(user.get_all_permissions())
        
        #Seed the Redis Authorization Cache
        token_expiry_hours=1
        cache_key=f"perms:{str(user.id)}"
        
       
        cache.set(cache_key, permissions, timeout=timedelta(hours=token_expiry_hours).total_seconds())

        #Generate the JWT
        jti=str(uuid6.uuid7()) 
        
        payload={
            "user_id": str(user.id),
            "account_type": user.account_type,
            "jti": jti,
            "exp": datetime.now(timezone.utc) + timedelta(hours=token_expiry_hours),
            "iat": datetime.now(timezone.utc),
        }

        token=jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

        #Return the Stateless Token
        return Response({
            "token": token,
            "account_type": user.account_type,
            "message": "Login successful"
        }, 
        status=status.HTTP_200_OK)


class LogoutView(APIView):

    permission_classes = [IsAuthenticated] 

    def post(self,request):
    
        payload=request.user 
        
        jti=payload.get('jti')
        exp=payload.get('exp') 

        if not jti or not exp:
            return Response(
                {"error": "Invalid token payload."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        now=datetime.now(timezone.utc).timestamp()
        ttl=int(exp-now)

        if ttl> 0:
            cache.set(f"denylist:{jti}", "true", timeout=ttl)

        user_id= payload.get('user_id')
        if user_id:
            cache.delete(f"perms:{user_id}")

        return Response(
            {"message": "Successfully logged out"}, 
            status=status.HTTP_200_OK
        )