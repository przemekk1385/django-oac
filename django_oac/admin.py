from django.contrib.admin import site

from .models import Token


site.register(Token)
