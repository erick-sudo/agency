from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken, AuthenticationFailed

class ApplicationJWTAuthentication(JWTAuthentication):
    """_summary_
        Custom http only cookie authentication mechanism
    Args:
        JWTAuthentication (_type_): _description_
    """
    def authenticate(self, request):
        # Get the access token from the HTTP-only cookie
        access_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])
        
        if not access_token:
            return None

        try:
            # Validate the token
            validated_token = self.get_validated_token(access_token)
        except InvalidToken:
            return None
        except TokenError:
            return None

        try:
            # Get the user associated with the token
            user = self.get_user(validated_token)
        except AuthenticationFailed:
            return None

        return user, validated_token