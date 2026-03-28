from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
import uuid6


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('account_type', 'internal')
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    ACCOUNT_TYPES = (
        ('customer', 'Customer App User'),
        ('rider', 'Rider App User'),
        ('internal', 'Internal Staff Dashboard'),
    )

    id = models.UUIDField(primary_key=True, default=uuid6.uuid7, editable=False)
    email = models.EmailField(unique=True)
    account_type = models.CharField(max_length=20, choices=ACCOUNT_TYPES, default='customer')

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return f"{self.email} ({self.account_type})"


# ---------------------------------------------------------------------------
# Profile Models — one per account type
# ---------------------------------------------------------------------------

class CustomerProfile(models.Model):
    """
    Extended profile for customer app users.
    Age is computed from DOB so it is always accurate.
    """
    user = models.OneToOneField(
        CustomUser, on_delete=models.CASCADE, related_name='customer_profile'
    )
    name = models.CharField(max_length=150)
    phone_no = models.CharField(max_length=15, unique=True)
    dob = models.DateField()
    address = models.TextField()
    pin_code = models.CharField(max_length=6)
    # E-wallet balance for refunds — starts at 0
    ewallet_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    @property
    def age(self):
        today = timezone.now().date()
        dob = self.dob
        return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

    def __str__(self):
        return f"CustomerProfile({self.name})"


class RiderProfile(models.Model):
    """
    Extended profile for rider app users.
    Aadhar number is stored but never exposed in API responses.
    """
    user = models.OneToOneField(
        CustomUser, on_delete=models.CASCADE, related_name='rider_profile'
    )
    name = models.CharField(max_length=150)
    aadhar_no = models.CharField(max_length=12, unique=True)
    phone_no = models.CharField(max_length=15, unique=True)
    dob = models.DateField()
    address = models.TextField()
    pin_code = models.CharField(max_length=6)

    @property
    def age(self):
        today = timezone.now().date()
        dob = self.dob
        return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

    def __str__(self):
        return f"RiderProfile({self.name})"


class StaffProfile(models.Model):
    """
    Minimal profile for internal staff.
    All other details are fetched from the company's internal HR/staff DB.
    """
    user = models.OneToOneField(
        CustomUser, on_delete=models.CASCADE, related_name='staff_profile'
    )
    job_card_id = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return f"StaffProfile({self.job_card_id})"