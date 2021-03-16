
from django.urls import re_path, path
from . import views


urlpatterns = [
    re_path(r'^totp/create/$', views.TOTPCreateView.as_view(), name='totp-create'),
    re_path(r'^totp/login/',
            views.TOTPVerifyView.as_view(), name='totp-login'),
    path('mierda', views.Mierda.as_view()),
]
