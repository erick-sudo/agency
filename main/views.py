from rest_framework.generics import GenericAPIView as G
from rest_framework.exceptions import NotAuthenticated, AuthenticationFailed
from rest_framework import serializers, status
from .serializers import UserRegisterResializer, LoginSerializer, PasswordResetRequestViewSerializer, SetNewPasswordSerializer, UserSerializer
from rest_framework.response import Response
from .utils import send_code_to_user
from .models import OneTimePassword, User
from rest_framework.permissions import IsAuthenticated
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .exception_handlers import ApplicationException, FailureCode
from django.conf import settings


class GenericAPIView(G):
    """
    Customized exception handling
    """
    
    def handle_exception(self, exc):
        
        if isinstance(exc, NotAuthenticated):
            exc = ApplicationException(failure_code=FailureCode.MISSING_AUTHENTICATION, status_code=401)
            
        if isinstance(exc, AuthenticationFailed):
            exc = ApplicationException(failure_code=FailureCode.FAILED_AUTHENTICATION, status_code=401)
            
        return super().handle_exception(exc)
    

class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterResializer    
    
    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user=serializer.data
            
            # Send email to user [Selery]
            send_code_to_user(user['email'])
            
            return Response({
                'data': user,
                'message': f"Hello {user['first_name']}, thank you for signing up."
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class VerifyUserEmailView(GenericAPIView):
    
    def post(self, request):
        otp_code = request.data.get('otp_code')
        try:
            user_code = OneTimePassword.objects.get(code=otp_code)
            user = user_code.user
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response({
                    'message': "account verified succesfully"
                }, status=status.HTTP_200_OK)
            
            raise ApplicationException(
                    failure_code=FailureCode.ACCOUNT_ALREADY_VERIFIED,
                    status_code=status.HTTP_400_BAD_REQUEST
            )
        except OneTimePassword.DoesNotExist:
            return Response({
                'message': "invalid passcode"
            }, status=status.HTTP_404_NOT_FOUND)
            

class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer
    
    def post(self, request):
        serializer=self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        response = Response(data={'message': "Login successful"}, status=status.HTTP_200_OK)
        
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=serializer.data['access_token'],
            max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        return response

        
class UserProfileView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        serializer = UserSerializer(request.user)
        serialized_user = serializer.data
        return Response({
            'user': serialized_user
        }, status=status.HTTP_200_OK)
        
    def handle_exception(self, exc):
        """
        Handle 
        """
        return super().handle_exception(exc)
        
class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestViewSerializer
    
    def post(self, request):
        serializer=self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({'message': "a link has been sent to your email to reset your password"}, status=status.HTTP_200_OK)
    
class PasswordResetConfirmView(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ApplicationException(failure_code=FailureCode.INVALID_LINK_TOKEN, status_code=status.HTTP_401_UNAUTHORIZED)
            
            return Response({'success': True , 'message': 'credentials are valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError:
            raise ApplicationException(failure_code=FailureCode.INVALID_LINK_TOKEN, status_code=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            raise ApplicationException(failure_code=FailureCode.INVALID_LINK_TOKEN, status_code=status.HTTP_401_UNAUTHORIZED)
        
class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    def patch(self, request):
        serializer=self.serializer_class(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as e:
            raise ApplicationException(detail={'errors': e.detail }, failure_code=FailureCode.VALIDATION_ERRORS, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
        return Response({'message': "password reset successfully"}, status=status.HTTP_200_OK)
    
class LogoutUserView(GenericAPIView):
    permission_classes=[IsAuthenticated]
    
    def get(self, request):
        # Clear cookies
        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
        return  response