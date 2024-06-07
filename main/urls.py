
from django.urls import path
from .views import RegisterUserView, VerifyUserEmailView, LoginUserView, UserProfileView, PasswordResetRequestView, PasswordResetConfirmView, SetNewPasswordView, LogoutUserView

urlpatterns = [
    path('register', RegisterUserView.as_view(), name='register'),
    path('verify-email', VerifyUserEmailView.as_view(), name='verify'),
    path('login', LoginUserView.as_view(), name='login'),
    path('profile', UserProfileView.as_view(), name='profile'),
    path('request-password-reset', PasswordResetRequestView.as_view(), name='request-password-reset'),
    path('confirm-password-reset/<uidb64>/<token>', PasswordResetConfirmView.as_view(), name='confirm-password-reset'),
    path('set-new-password', SetNewPasswordView.as_view(), name='set-new-password'),
    path('logout', LogoutUserView.as_view(), name='logout'),
]