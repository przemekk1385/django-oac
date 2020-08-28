[![Build Status](https://travis-ci.org/przemekk1385/django_oac.svg?branch=master)](https://travis-ci.org/przemekk1385/django_oac) [![Coverage Status](https://coveralls.io/repos/github/przemekk1385/django_oac/badge.svg)](https://coveralls.io/github/przemekk1385/django_oac) [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# Django OAuth Client

Pretty simple OAuth Client for Django.

## Installation

Cooming soon...

## Configuration

Settings are being kept in `OAC` dict in your project's `settings.py` file. Sample configuration below:

    OAC = {
        "authorize_uri": "https://your.oauth.provider/authorize/",
        "token_uri": "https://your.oauth.provider/token/",
        "revoke_uri": "https://your.oauth.provider/revoke/",
        "redirect_uri": "http://your.site/oac/callback/",
        "jwks_uri": "https://your.oauth.provider/jwks/",
        "client_id": "your_client_id",
        "client_secret": "your_client_secret",
    }

All keys **are required**.