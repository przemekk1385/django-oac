from django.core.cache import cache

from django_oac.services import CacheJWKSService


def test_fetch(oac_jwk):
    oac_jwk.kid = "foo"
    cache.set("bar", oac_jwk.jwks)

    service = CacheJWKSService()
    jwk, jwks = service.fetch("foo", cache_key="bar")

    assert jwk == oac_jwk.jwk
    assert jwks


def test_clear():
    cache.set("foo", "bar")

    service = CacheJWKSService()
    service.clear()

    assert not cache.get("foo")


def test_save():
    service = CacheJWKSService()
    service.save("foo", cache_key="bar")

    assert cache.get("bar") == "foo"
