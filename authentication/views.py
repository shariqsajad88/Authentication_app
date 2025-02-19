import logging
from django.utils import timezone 
from django.db import transaction, IntegrityError
from django.contrib.auth import authenticate
from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.models import OTPVerification, User
from .serializers import UserRegistrationSerializer, UserLoginSerializer
from .services.otp_services import OTPService
from .services.email_services import EmailService
import traceback

logger = logging.getLogger(__name__)

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
                with transaction.atomic():
                    user = serializer.save()
                    otp = OTPService.generate_otp(user)
                    
                    try:
                        EmailService.send_otp_email(user.id, otp)
                        EmailService.send_welcome_email(user.id)
                    except Exception as email_error:
                        logger.error(f"Email sending failed: {str(email_error)}")
                        return Response({
                            'success': False,
                            'message': 'Registration successful, but email sending failed. Please contact support.'
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    
                    return Response({
                        'success': True,
                        'message': 'Registration successful. Please check your email for verification code.',
                        'user_id': user.id
                    }, status=status.HTTP_201_CREATED)

            except IntegrityError as db_error:
                logger.error(f"Database error during registration: {str(db_error)}")
                return Response({
                    'success': False,
                    'message': 'Database error occurred. Please try again later.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except Exception as e:
                logger.error(f"Unexpected error during registration: {traceback.format_exc()}")
                return Response({
                    'success': False,
                    'message': 'An error occurred during registration. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(
            email=serializer.validated_data['email'],
            password=serializer.validated_data['password']
        )
        if not user:
            return Response({
                'success': False,
                'message': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)

        if user.is_2fa_enabled:
            try:
                otp = OTPService.generate_otp(user)
                EmailService.send_otp_email.delay(user.id, otp)
                return Response({
                    'success': True,
                    'message': '2FA required. Please check your email for the OTP.',
                    'user_id': user.id
                }, status=status.HTTP_202_ACCEPTED)
            except Exception as e:
                logger.error(f"Failed to send OTP email: {str(e)}")
                return Response({
                    'success': False,
                    'message': 'Failed to send OTP email. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        tokens = get_tokens_for_user(user)
        return Response({
            'success': True,
            'message': 'Login successful',
            **tokens
        }, status=status.HTTP_200_OK)

class VerifyOTPView(APIView):
    def post(self, request):
        otp = request.data.get('otp')

        if not otp:
            return Response({
                'success': False,
                'message': 'OTP is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Look up the OTP in the database
        verification = OTPVerification.objects.filter(otp=otp, expires_at__gt=timezone.now()).select_related('user').first()

        if not verification:
            return Response({
                'success': False,
                'message': 'Invalid or expired OTP'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Mark user as verified
        user = verification.user
        user.is_verified = True
        user.save()
        
        # Delete the used OTP entry
        verification.delete()

        # Generate JWT tokens
        tokens = get_tokens_for_user(user)

        return Response({
            'success': True,
            'message': 'OTP verified successfully',
            **tokens
        }, status=status.HTTP_200_OK)


class VerifyEmailView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        verification_code = request.data.get('verification_code')

        if not user_id or not verification_code:
            return Response({
                'success': False,
                'message': 'user_id and verification_code are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                verification = OTPVerification.objects.select_related('user').get(
                    user_id=user_id, otp=verification_code, expires_at__gt=timezone.now()
                )
                verification.user.is_verified = True
                verification.user.save()
                verification.delete()

                return Response({
                    'success': True,
                    'message': 'Email verified successfully'
                }, status=status.HTTP_200_OK)

        except OTPVerification.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Invalid or expired verification code'
            }, status=status.HTTP_400_BAD_REQUEST)
