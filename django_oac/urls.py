from django.urls import re_path

from . import views

app_name = "django_oac"
urlpatterns = [
    re_path(r"^authenticate/$", views.authenticate_view, name="authenticate"),
    re_path(r"^callback/$", views.callback_view, name="callback"),
    re_path(r"^error/$", views.error_view, name="error"),
    re_path(r"^logout/$", views.logout_view, name="logout"),
    re_path(r"^test/$", views.test_view, name="test"),
]
