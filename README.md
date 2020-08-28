[![Build Status](https://travis-ci.org/przemekk1385/django_oac.svg?branch=master)](https://travis-ci.org/przemekk1385/django_oac) [![Coverage Status](https://coveralls.io/repos/github/przemekk1385/django_oac/badge.svg)](https://coveralls.io/github/przemekk1385/django_oac) [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# Django OAuth Client

Pretty simple OAuth Client for Django.

## Installation

Coming soon...

## Configuration

Configuration is being kept in `OAC` dict in your project's settings.

`settings.py`

    OAC = {
        "authorize_uri": "https://your.oauth.provider/authorize/",
        "token_uri": "https://your.oauth.provider/token/",
        "revoke_uri": "https://your.oauth.provider/revoke/",
        "redirect_uri": "http://your.site/oac/callback/",
        "jwks_uri": "https://your.oauth.provider/jwks/",
        "client_id": "your_client_id",
        "client_secret": "your_client_secret",
    }

Besides that some additions must be made in the **Application definition** section.

`settings.py`

    # Application definition
    
    INSTALLED_APPS = [
        # other apps
        # ...
        "django_oac",
    ]

    MIDDLEWARE = [
        # other middleware
        # ...
        "django_oac.middleware.OAuthClientMiddleware",
    ]

    AUTHENTICATION_BACKENDS = [
        "django.contrib.auth.backends.ModelBackend",  # default authentcation backend
        "django_oac.backends.OAuthClientBackend",  # Django OAuth Client authentication backend
    ]

And in project's urls.

`urls.py`

    # ...
    from django.urls import include, path
    
    urlpatterns = [
        # other urls
        # ...
        path("some_prefix/", include("django_oac.urls")),
    ]
    
That's it - your are good to go.
