import logging
from datetime import timezone
from django.db import transaction
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.models import OTPVerification, User
from .serializers import UserRegistrationSerializer, UserLoginSerializer
from .services.otp_services import OTPService
from .services.email_services import EmailService

logger = logging.getLogger(__name__)

# Helper function for generating JWT tokens
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }

class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                with transaction.atomic():  # Ensure atomicity
                    user = serializer.save()
                    otp = OTPService.generate_otp(user)

                    # Send OTP and welcome email
                    EmailService.send_otp_email(user, otp)
                    EmailService.send_welcome_email(user)

                return Response({
                    'success': True,
                    'message': 'Registration successful. Please check your email for verification code.',
                    'user_id': user.id
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error during registration: {str(e)}")
                return Response({
                    'success': False,
                    'message': 'Registration successful but email delivery failed. Please contact support.',
                    'user_id': user.id
                }, status=status.HTTP_201_CREATED)

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                email=serializer.validated_data['email'],
                password=serializer.validated_data['password']
            )
            if user:
                if user.is_2fa_enabled:
                    otp = OTPService.generate_otp(user)
                    try:
                        EmailService.send_otp_email(user, otp)
                    except Exception as e:
                        logger.error(f"Failed to send OTP email: {str(e)}")
                        return Response({
                            'success': False,
                            'message': 'Failed to send OTP email. Please try again.'
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                    return Response({
                        'success': True,
                        'message': '2FA required. Please check your email for the OTP.',
                        'user_id': user.id
                    }, status=status.HTTP_200_OK)

                tokens = get_tokens_for_user(user)
                return Response({
                    'success': True,
                    'message': 'Login successful',
                    **tokens
                }, status=status.HTTP_200_OK)

            return Response({
                'success': False,
                'message': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        otp = request.data.get('otp')

        user = User.objects.filter(id=user_id).first()
        if not user:
            return Response({
                'success': False,
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)

        if OTPService.verify_otp(user, otp):
            user.is_verified = True
            user.save()

            tokens = get_tokens_for_user(user)
            return Response({
                'success': True,
                'message': 'OTP verified successfully',
                **tokens
            }, status=status.HTTP_200_OK)

        return Response({
            'success': False,
            'message': 'Invalid OTP'
        }, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        verification_code = request.data.get('verification_code')

        try:
            user = User.objects.get(id=user_id)
            verification = OTPVerification.objects.filter(
                user=user,
                otp=verification_code,
                expires_at__gt=timezone.now()
            ).first()

            if verification:
                user.is_verified = True
                user.save()
                verification.delete()

                return Response({
                    'success': True,
                    'message': 'Email verified successfully'
                }, status=status.HTTP_200_OK)

            return Response({
                'success': False,
                'message': 'Invalid or expired verification code'
            }, status=status.HTTP_400_BAD_REQUEST)

        except User.DoesNotExist:
            return Response({
                'success': False,
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
