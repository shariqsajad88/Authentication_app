import pyotp
from datetime import timedelta
from django.utils.timezone import now
from django.conf import settings
from django.core.exceptions import ValidationError

class OTPService:
    """OTP Service with enhanced security and efficiency."""

    OTP_EXPIRY_MINUTES = getattr(settings, 'OTP_EXPIRY_MINUTES', 10)

    @staticmethod
    def generate_secret(user):
        """Generates or retrieves a stable secret key for the user."""
        if not user:
            raise ValidationError("User is required to generate a secret key.")

        if not user.two_factor_secret:
            user.two_factor_secret = pyotp.random_base32()
            user.save()

        return user.two_factor_secret

    @staticmethod
    def generate_otp(user):
        """Generates a time-based OTP (TOTP) for the user."""
        if not user:
            raise ValidationError("User is required to generate OTP.")

        secret = OTPService.generate_secret(user)
        totp = pyotp.TOTP(secret, interval=OTPService.OTP_EXPIRY_MINUTES * 60)
        return totp.now()

    @staticmethod
    def verify_otp(user, otp):
        """Verifies the OTP dynamically without storing it."""
        if not user or not otp:
            raise ValidationError("User and OTP are required for verification.")

        secret = OTPService.generate_secret(user)
        totp = pyotp.TOTP(secret, interval=OTPService.OTP_EXPIRY_MINUTES * 60)

        return totp.verify(otp)  

    @staticmethod
    def resend_otp(user):
        """Resends a new OTP."""
        if not user:
            raise ValidationError("User is required to resend OTP.")

        return OTPService.generate_otp(user)
