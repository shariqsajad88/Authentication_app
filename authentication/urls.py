from django.urls import path
from .views import RegisterView, LoginView, VerifyOTPView, VerifyEmailView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register-api"),
    path("login/", LoginView.as_view(), name="login-api"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify-otp-api"),
    path("verify-email/", VerifyEmailView.as_view(), name="verify-email-api"),
]
