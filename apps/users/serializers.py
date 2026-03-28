from django.db import transaction
from rest_framework import serializers
from .models import CustomUser, CustomerProfile, RiderProfile


class CustomerSignupSerializer(serializers.Serializer):
    # Auth credentials
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)

    # Profile fields
    name = serializers.CharField(max_length=150)
    phone_no = serializers.CharField(max_length=15)
    dob = serializers.DateField()
    address = serializers.CharField()
    pin_code = serializers.CharField(min_length=6, max_length=6)

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate_phone_no(self, value):
        if CustomerProfile.objects.filter(phone_no=value).exists():
            raise serializers.ValidationError("This phone number is already registered.")
        return value

    def validate_pin_code(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("PIN code must be 6 digits.")
        return value

    @transaction.atomic
    def save(self):
        user = CustomUser.objects.create_user(
            email=self.validated_data['email'],
            password=self.validated_data['password'],
            account_type='customer',
        )
        CustomerProfile.objects.create(
            user=user,
            name=self.validated_data['name'],
            phone_no=self.validated_data['phone_no'],
            dob=self.validated_data['dob'],
            address=self.validated_data['address'],
            pin_code=self.validated_data['pin_code'],
        )
        return user


class RiderSignupSerializer(serializers.Serializer):
    # Auth credentials
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)

    # Profile fields
    name = serializers.CharField(max_length=150)
    aadhar_no = serializers.CharField(min_length=12, max_length=12)
    phone_no = serializers.CharField(max_length=15)
    dob = serializers.DateField()
    address = serializers.CharField()
    pin_code = serializers.CharField(min_length=6, max_length=6)

    # Invite code — required for rider registration
    invite_code = serializers.CharField(write_only=True)

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate_aadhar_no(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Aadhar number must be 12 digits.")
        if RiderProfile.objects.filter(aadhar_no=value).exists():
            raise serializers.ValidationError("This Aadhar number is already registered.")
        return value

    def validate_phone_no(self, value):
        if RiderProfile.objects.filter(phone_no=value).exists():
            raise serializers.ValidationError("This phone number is already registered.")
        return value

    def validate_pin_code(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("PIN code must be 6 digits.")
        return value

    def validate_invite_code(self, value):
        from django.conf import settings
        if value != settings.RIDER_INVITE_CODE:
            raise serializers.ValidationError("Invalid invite code.")
        return value

    @transaction.atomic
    def save(self):
        user = CustomUser.objects.create_user(
            email=self.validated_data['email'],
            password=self.validated_data['password'],
            account_type='rider',
        )
        RiderProfile.objects.create(
            user=user,
            name=self.validated_data['name'],
            aadhar_no=self.validated_data['aadhar_no'],
            phone_no=self.validated_data['phone_no'],
            dob=self.validated_data['dob'],
            address=self.validated_data['address'],
            pin_code=self.validated_data['pin_code'],
        )
        return user
