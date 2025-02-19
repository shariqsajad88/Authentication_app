import logging
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404
from authentication.models import User

logger = logging.getLogger(__name__)

class EmailService:
    @staticmethod
    def send_otp_email(user_id, otp):
        try:
            user = get_object_or_404(User, id=user_id)
            subject = "Your OTP Code"
            message = f"Hello {user.username},\n\nYour OTP code is: {otp}\n\nThank you!"
            email_from = settings.DEFAULT_FROM_EMAIL
            recipient_list = [user.email]

            send_mail(subject, message, email_from, recipient_list, fail_silently=False)
            logger.info(f"OTP email sent to {user.email}")

        except Exception as e:
            logger.error(f"Error sending OTP email: {e}")

    @staticmethod
    def send_welcome_email(user_id):
        try:
            user = get_object_or_404(User, id=user_id)
            subject = "Welcome to Our Platform"
            message = f"Hello {user.username},\n\nWelcome! We are excited to have you on board.\n\nBest Regards!"
            email_from = settings.DEFAULT_FROM_EMAIL
            recipient_list = [user.email]

            send_mail(subject, message, email_from, recipient_list, fail_silently=False)
            logger.info(f"Welcome email sent to {user.email}")

        except Exception as e:
            logger.error(f"Error sending welcome email: {e}")
