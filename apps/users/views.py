import jwt
import uuid6
from datetime import datetime, timedelta, timezone
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.cache import cache
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import status

from .serializers import CustomerSignupSerializer, RiderSignupSerializer


# ---------------------------------------------------------------------------
# Auth Views
# ---------------------------------------------------------------------------

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(username=email, password=password)
        if not user:
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        permissions = list(user.get_all_permissions())

        token_expiry_hours = 1
        cache_key = f"perms:{str(user.id)}"
        cache.set(cache_key, permissions, timeout=timedelta(hours=token_expiry_hours).total_seconds())

        jti = str(uuid6.uuid7())

        payload = {
            "user_id": str(user.id),
            "account_type": user.account_type,
            "jti": jti,
            "exp": datetime.now(timezone.utc) + timedelta(hours=token_expiry_hours),
            "iat": datetime.now(timezone.utc),
        }

        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

        return Response({
            "token": token,
            "account_type": user.account_type,
            "message": "Login successful"
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        payload = request.user

        jti = payload.get('jti')
        exp = payload.get('exp')

        if not jti or not exp:
            return Response(
                {"error": "Invalid token payload."},
                status=status.HTTP_400_BAD_REQUEST
            )

        now = datetime.now(timezone.utc).timestamp()
        ttl = int(exp - now)

        # Always denylist the jti. If the token is already expired,
        # use a 60-second safety window so audits can still catch it.
        cache.set(f"denylist:{jti}", "true", timeout=max(ttl, 60))

        user_id = payload.get('user_id')
        if user_id:
            cache.delete(f"perms:{user_id}")

        return Response(
            {"message": "Successfully logged out"},
            status=status.HTTP_200_OK
        )



class CustomerSignupView(APIView):
    """
    Open self-registration for customers.
    Required fields: email, password, name, phone_no, dob, address, pin_code
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CustomerSignupSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()
        profile = user.customer_profile

        return Response({
            "message": "Customer account created successfully.",
            "user_id": str(user.id),
            "email": user.email,
            "account_type": user.account_type,
            "name": profile.name,
            "age": profile.age,
            "ewallet_balance": str(profile.ewallet_balance),
        }, status=status.HTTP_201_CREATED)


class RiderSignupView(APIView):
    """
    Rider self-registration protected by an invite code.
    Required fields: email, password, name, aadhar_no, phone_no, dob,
                     address, pin_code, invite_code
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RiderSignupSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()
        profile = user.rider_profile

        return Response({
            "message": "Rider account created successfully.",
            "user_id": str(user.id),
            "email": user.email,
            "account_type": user.account_type,
            "name": profile.name,
            "age": profile.age,
        }, status=status.HTTP_201_CREATED)