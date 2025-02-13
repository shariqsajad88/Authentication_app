import pyotp
from datetime import datetime, timedelta
from ..models import OTPVerification

class OTPService:
    @staticmethod
    def generate_otp(user):
        otp = pyotp.random_base32()[:6]
        expires_at = datetime.now() + timedelta(minutes=10)

        OTPVerification.objects.create(
            user=user,
            otp=otp,
            expires_at=expires_at
        )
        return otp

    @staticmethod
    def verify_otp(user, otp):
        verification = OTPVerification.objects.filter(
            user=user,
            otp=otp,
            expires_at__gt=datetime.now()
        ).first()
        
        if verification:
            verification.delete()
            return True
        return False