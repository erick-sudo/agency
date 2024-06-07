from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str, smart_bytes
from .utils import send_normal_email
from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
from .exception_handlers import SparkleSyncException

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['email', 'first_name', 'last_name', 'phone_number']

class UserRegisterResializer(serializers.ModelSerializer):
    password=serializers.CharField(max_length=68, min_length=6, write_only=True)
    password_confirmation=serializers.CharField(max_length=68, min_length=6, write_only=True)
    
    class Meta:
        model=User
        fields=['email', 'first_name', 'last_name', 'phone_number', 'password', 'password_confirmation']
        
    def validate(self, attrs):
        password = attrs.get('password', '')
        password_confirmation = attrs.get('password_confirmation', '')
        if password != password_confirmation:
            raise serializers.ValidationError("passwords do not match")
        return attrs
    
    def create(self, validated_data):
        user=User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone_number=validated_data['phone_number'],
            password=validated_data['password']
        )
        return user
    
class LoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255, min_length=6, write_only=True)
    password=serializers.CharField(max_length=68, write_only=True)
    access_token=serializers.CharField(max_length=255, read_only=True)
    refresh_token=serializers.CharField(max_length=255, read_only=True)
    remember_me=serializers.BooleanField(default=False)
    
    class Meta:
        model=User
        fields=['email', 'password', 'access_token', 'refresh_token', 'remember_me']
        
    def validate(self, attrs):
        email=attrs.get('email')
        password=attrs.get('password')
        
        request=self.context.get('request')
        user=authenticate(request, email=email, password=password)
        
        if not user:
            raise SparkleSyncException(detail={'message': f"invalid credentials"}, failure_code="AUTHENTICATION", status_code=400)
        
        if not user.is_verified:
            raise SparkleSyncException(detail={'message': "account not verified, please verify your account"}, failure_code="NOT_VERIFIED", status_code=403)
        
        user_tokens = user.tokens()
        
        return {
            'remember_me': attrs.get('remember_me'),
            'refresh_token': str(user_tokens.get('refresh_token')), 
            'access_token': str(user_tokens.get('access_token')), 
        }
        
class PasswordResetRequestViewSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255, min_length=6)
    
    class Meta:
        fields=['email']
        
    def validate(self, attrs):
        email=attrs.get('email')
        
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            
            if not user.is_verified:
                raise SparkleSyncException(detail={'message': "account not verified, please verify your account"}, failure_code="NOT_VERIFIED", status_code=403)
            
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            relative_link = f"/reset_password/{uidb64}/{token}"
            absolute_link = f"{settings.FRONT_END_URL}{relative_link}"
            email_body=f"Hello {user.first_name}, use the link below to reset your password \n {absolute_link}"
            
            data = {
                'email_body': email_body,
                'email_subject': "Password reset",
                'to_email': user.email
            }
            
            send_normal_email(data)
        else:
            raise SparkleSyncException(detail={'message': f"User by email {email} does not exist"}, failure_code="NOT_FOUND", status_code=404)
        
        return super().validate(attrs)
    
class SetNewPasswordSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=68, min_length=6, write_only=True)
    password_confirmation=serializers.CharField(max_length=68, min_length=6, write_only=True)
    uidb64=serializers.CharField(write_only=True)
    token=serializers.CharField(write_only=True)
    
    class Meta:
        fields=['password', 'password_confirmation', 'uidb64', 'token']
        
    def validate(self, attrs):
        token = attrs.get('token', '')
        uidb64 = attrs.get('uidb64', '')
        password = attrs.get('password', '')
        password_confirmation = attrs.get('password_confirmation', '')
        
        user = None
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
        except Exception as e:
            raise AuthenticationFailed("link is invalid or has expired", 401)
        
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise AuthenticationFailed("reset link is invalid or has expired", 401)
        
        if password!= password_confirmation:
            raise SparkleSyncException(detail={'message': {'password_confirmation': ["passwords do not match"]}}, failure_code="VALIDATION_ERRORS", status_code=422)
        
        user.set_password(password)
        user.save()
        return user
    
class LogoutUserSerializer(serializers.Serializer):
       
    # default_error_messages = {
    #     'bad_token': ('Token is invalid or has expired'),
    #     'no_token': ('No refresh token provided'),
    # }
    
    def validate(self, attrs):       
        request = self.context['request']
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['REFRESH_COOKIE'])
        access_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])
        user = request.user
        
        if not refresh_token:
            pass
        
        if not access_token:
            pass
        
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            tokens = OutstandingToken.objects.filter(user=user).delete()
            print(tokens)
        except Exception as e:
            pass
        return super().validate(attrs)