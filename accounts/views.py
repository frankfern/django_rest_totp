from accounts.permissions import IsOtpVerified
from rest_framework import views, permissions
from rest_framework.response import Response
from rest_framework import status
# from django_otp import devices_for_user
# from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import TwoFactorTokenObtainPairSerializer
from .utils import get_user_totp_device
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


class TwoFactorTokenObtainPairView(TokenObtainPairView):
    serializer_class = TwoFactorTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        user = request.user
        device = get_user_totp_device(self, user)
        serializer = self.get_serializer(data=request.data, context={
            'device': device,
        })

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class TOTPCreateView(views.APIView):
    """
    Use this endpoint to set up a new TOTP device
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None):
        user = request.user
        device = get_user_totp_device(self, user)
        if not device:
            device = user.totpdevice_set.create(confirmed=False)
        url = device.config_url
        return Response(url, status=status.HTTP_201_CREATED)


class TOTPVerifyView(views.APIView):
    """
    Use this endpoint to verify/enable a TOTP device
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, token, format=None):
        user = request.user
        device = get_user_totp_device(self, user)
        if not device:
            return Response(dict(
                errors=['This user has not setup two factor authentication']),
                status=status.HTTP_400_BAD_REQUEST
            )
        if not device == None and device.verify_token(token):
            if not device.confirmed:
                device.confirmed = True
                # user.is_two_factor_enabled = True
                device.save()
            serializer = TwoFactorTokenObtainPairSerializer(
                data=request.data,
                context={
                    'device': device,
                }
            )
            serializer.is_valid(raise_exception=True)

            return Response(serializer.validated_data, status=status.HTTP_200_OK)

        return Response(dict(errors=dict(token=['Invalid TOTP Token'])),
                        status=status.HTTP_400_BAD_REQUEST)


class Mierda(views.APIView):
    permission_classes = [permissions.IsAuthenticated, IsOtpVerified]

    def get(self, request):
        return "mierda"
