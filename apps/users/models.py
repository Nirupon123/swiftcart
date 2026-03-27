from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
import uuid6

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email=self.normalize_email(email)
        user=self.model(email=email,**extra_fields)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('account_type', 'internal') 
        return self.create_user(email, password,**extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    ACCOUNT_TYPES = (
        ('customer','Customer App User'),
        ('rider','Rider App User'),
        ('internal','Internal Staff Dashboard'),
    )
    
    id=models.UUIDField(primary_key=True,default=uuid6.uuid7,editable=False)
    email=models.EmailField(unique=True)
    account_type=models.CharField(max_length=20,choices=ACCOUNT_TYPES,default='customer')


    is_active=models.BooleanField(default=True)
    is_staff=models.BooleanField(default=False)
    
    objects=CustomUserManager()

    USERNAME_FIELD='email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return f"{self.email} ({self.account_type})"