from django.contrib import admin

from .models import Token


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    readonly_fields = ("expires_in", "issued", "user")
