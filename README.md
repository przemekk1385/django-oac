[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# Django OAuth Client

Pretty simple OAuth Client for Django.

## Configuration

Configuration is being kept in `OAC` dict in your project's settings.

`settings.py`

    OAC = {
        "AUTHORIZE_URI": "https://your.oauth.provider/authorize/",
        "TOKEN_URI": "https://your.oauth.provider/token/",
        "REVOKE_URI": "https://your.oauth.provider/revoke/",
        "REDIRECT_URI": "http://your.site/oac/callback/",
        "JWKS_URI": "https://your.oauth.provider/jwks/",
        "CLIENT_ID": "your_client_id",
        "CLIENT_SECRET": "your_client_secret",
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

### Extra settings

Additional keys that can be set in OAC dict.

|key|default value|description|
|:---|:---|:---|
|STATE_EXPIRES_IN|300|state expiration time in seconds, set None to disable check|
|TOKEN_PROVIDER_CLASS|DefaultTokenProvider|class providing and handling token based on OAuth server responses|
|USER_PROVIDER_CLASS|DefaultUserProvider|class providing user based on ID Token|

For more details regarding models providers please review the source code of `models_providers` module.

General idea is to give control over processes of creating token and getting or creating user.

Custom user provider class can let ie. to create user with required priveleges or to make creating user dependent on ID Token payload.
