from rest_framework_simplejwt.state import token_backend
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication

from django_otp import devices_for_user
from django_otp.models import Device
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_static.models import StaticDevice


def get_refresh_with_otp_token(user, device):
    refresh = RefreshToken.for_user(user)
    refresh['otp_device_id'] = get_otp_device_id(user, device)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token)
    }


def otp_is_verified(request):
    """
    Helper to determine if user has verified OTP.
    """
    auth = JWTAuthentication()
    header = auth.get_header(request)
    raw_token = auth.get_raw_token(header)
    if raw_token is None:
        return False
    payload = token_backend.decode(raw_token)
    persistent_id = payload.get('otp_device_id')
    if persistent_id:
        device = Device.from_persistent_id(persistent_id)
        if (device is not None) and (device.user_id != request.user.id):
            return False
        else:
            # Valid device in JWT
            return True
    else:
        return False


def get_user_totp_device(self, user, confirmed=None):
    devices = devices_for_user(user, confirmed=confirmed)
    for device in devices:
        if isinstance(device, TOTPDevice):
            return device
    return None


def get_user_static_device(self, user, confirmed=None):
    devices = devices_for_user(user, confirmed=confirmed)
    for device in devices:
        if isinstance(device, StaticDevice):
            return device


def get_otp_device_id(user, device=None):
    if (user is not None) and (device is not None) and (device.user_id == user.id) and (device.confirmed is True):
        return device.persistent_id
    else:
        return None
