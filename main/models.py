from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken

from .manager import UserManager

AUTH_PROVIDERS = {
    'email': 'email',
    'facebook': 'facebook',
    'google': 'google',
    'github': 'github',
}

# Create your models here.
class User(AbstractBaseUser, PermissionsMixin):
    email=models.EmailField(max_length=255, unique=True, verbose_name=("Email Address"))
    first_name=models.CharField(max_length=100, verbose_name=("First Name"))
    last_name=models.CharField(max_length=100, verbose_name=("Last Name"))
    phone_number=models.CharField(max_length=13, verbose_name=("Phone Number"))
    is_active=models.BooleanField(default=True, verbose_name=("Active"))
    is_verified=models.BooleanField(default=False, verbose_name=("Verified"))
    is_staff=models.BooleanField(default=False, verbose_name=("Staff"))
    is_superuser=models.BooleanField(default=False, verbose_name=("Super User"))
    date_joined=models.DateTimeField(auto_now_add=True, verbose_name=("Date Joined"))
    last_login=models.DateTimeField(auto_now=True, verbose_name=("Last Login"))
    auth_provider=models.CharField(max_length=50, default=AUTH_PROVIDERS.get('email'))
    
    USERNAME_FIELD="email"
    
    REQUIRED_FIELDS= ["first_name", "last_name", "phone_number"]
    
    objects= UserManager()
    
    def __str__(self) -> str:
        return self.email
    
    @property
    def get_full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"
    
    def tokens(self):
        refresh=RefreshToken.for_user(self)
        return {
            'refresh_token': str(refresh),
            'access_token': str(refresh.access_token)
        }
    
class OneTimePassword(models.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE)
    code=models.CharField(max_length=6, unique=True)
    
    def __str__(self) -> str:
        return f"{self.user.first_name}-passcode"
    