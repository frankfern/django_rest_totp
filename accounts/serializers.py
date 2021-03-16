from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .utils import get_otp_device_id, get_refresh_with_otp_token


class TwoFactorTokenObtainPairSerializer(TokenObtainSerializer):
    @classmethod
    def get_token(cls, user, device):
        return get_refresh_with_otp_token(user, device)

    def validate(self, attrs):
        data = super().validate(attrs)
        device = self.context['device']
        tokens_dict = self.get_token(self.user, device)
        data.update(tokens_dict)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data


class TotpTokenSerializer(serializers.Serializer):

    otp_code = serializers.IntegerField()

    def validate(self, attrs):

        user = self.context['user']
        device = self.context['device']
        otp_code = attrs['otp_code']

        if not device == None and device.verify_token(otp_code):
            if not device.confirmed:
                device.confirmed = True
                user.is_two_factor_enabled = True
                device.save()
            return get_refresh_with_otp_token(user, device)

        raise serializers.ValidationError(
            detail=dict(errors=dict(token=['Invalid TOTP Token'])))
