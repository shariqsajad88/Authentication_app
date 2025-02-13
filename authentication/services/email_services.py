from django.core.mail import send_mail
from django.conf import settings
from django.utils.html import strip_tags
from django.template.loader import render_to_string
import logging

logger = logging.getLogger(__name__)

class EmailService:
    @staticmethod
    def send_otp_email(user, otp):
        subject = 'Your OTP Verification Code'
        html_message = render_to_string('authentication/email/otp_email.html', {
            'user': user,
            'otp': otp
        })
        plain_message = strip_tags(html_message)
        
        try:
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.EMAIL_HOST_USER,  # FIXED: Ensure this is set
                recipient_list=[user.email],
                html_message=html_message
            )
            logger.info(f"OTP email sent to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send OTP email to {user.email}: {str(e)}")

    @staticmethod
    def send_welcome_email(user):
        subject = 'Welcome to Our Platform'
        html_message = render_to_string('authentication/email/welcome_email.html', {
            'user': user
        })
        plain_message = strip_tags(html_message)
        
        try:
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.EMAIL_HOST_USER,  # FIXED: Ensure this is set
                recipient_list=[user.email],
                html_message=html_message
            )
            logger.info(f"Welcome email sent to {user.email}")
        except Exception as e:
            logger.error(f"Failed to send welcome email to {user.email}: {str(e)}")
