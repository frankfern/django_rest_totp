from rest_framework import views, permissions
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django_otp import devices_for_user

from .serializers import TotpTokenSerializer, TwoFactorTokenObtainPairSerializer
from .permissions import IsOtpVerified
from .utils import get_refresh_with_otp_token, get_user_totp_device


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

    def post(self, request, format=None):
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

    def post(self, request, format=None):
        user = request.user
        device = get_user_totp_device(self, user)
        if not device:
            return Response(dict(
                errors=['This user has not setup two factor authentication']),
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = TotpTokenSerializer(data=request.data, context={
            'device': device,
            'user': user
        })
        serializer.is_valid(raise_exception=True)

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class TOTPDeleteView(views.APIView):
    """
    Use this endpoint to delete a TOTP device
    """
    permission_classes = [permissions.IsAuthenticated,
                          IsOtpVerified]

    def post(self, request, format=None):
        user = request.user
        devices = devices_for_user(user)
        for device in devices:
            device.delete()
        user.is_two_factor_enabled = False
        user.save()
        tokens = get_refresh_with_otp_token(user, None)
        return Response(tokens, status=status.HTTP_200_OK)
