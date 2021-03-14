from rest_framework import views, permissions
from rest_framework.response import Response
from rest_framework import status
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
from .serializers import TwoFactorTokenObtainPairSerializer


def get_user_totp_device(self, user, confirmed=None):
    devices = devices_for_user(user, confirmed=confirmed)
    for device in devices:
        if isinstance(device, TOTPDevice):
            return device


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
                data=request.data, context={
                    'user': request.user,
                })
            serializer.is_valid(raise_exception=True)

            return Response(serializer.validated_data, status=status.HTTP_200_OK)

        return Response(dict(errors=dict(token=['Invalid TOTP Token'])),
                        status=status.HTTP_400_BAD_REQUEST)
