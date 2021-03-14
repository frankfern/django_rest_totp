from django.contrib.auth import get_user
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers


class TwoFactorTokenObtainPairSerializer(serializers.Serializer):

    @classmethod
    def get_token(cls, user):

        token = RefreshToken.for_user(user)
        token['two-factor-allowed'] = True

        return token

    def got_user(self):

        user = self.context['user']
        return user

    def validate(self, attrs):
        refresh = self.get_token(self.got_user())

        data = {}
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        return data
