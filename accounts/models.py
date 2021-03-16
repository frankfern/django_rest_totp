from django.db import models
from django.contrib.auth.models import AbstractUser


class CustomUser(AbstractUser):

    is_two_factor_enabled = models.BooleanField(default=False)
