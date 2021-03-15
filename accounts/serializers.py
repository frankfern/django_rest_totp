from django.contrib.auth import get_user
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.views import TokenObtainPairView

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from .utils import get_otp_device_id


class TwoFactorTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        device = self.context['device']
        refresh = self.get_token(self.user)
        refresh['otp_device_id'] = get_otp_device_id(self.user, device)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data


class TotpTokenSerializer(serializers.Serializer):

    def get_token(self, user):

        token = super().get_token(user)
        token['otp_device_id'] = get_otp_device_id(user, device)

        return token

    def obtain_device_jwt(cls, user):

        # def got_user(self):

        #     user = self.context['user']
        #     return user

        # def validate(self, attrs):
        #     refresh = self.get_token(self.got_user())

        #     data = {}
        #     data['refresh'] = str(refresh)
        #     data['access'] = str(refresh.access_token)

        #     return data
