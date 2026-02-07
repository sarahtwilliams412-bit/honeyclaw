#!/usr/bin/env python3
"""
Tests for GeoIP module.
Tests work both with and without MaxMind databases installed.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.geoip import GeoResult, GeoIPResolver, _LRUCache, lookup_ip, get_geo_fields


class TestGeoResult:
    """Tests for GeoResult dataclass."""

    def test_empty_result(self):
        """Empty GeoResult returns empty dict from to_event_fields."""
        result = GeoResult()
        fields = result.to_event_fields()
        assert fields == {}

    def test_full_result_to_event_fields(self):
        """Populated GeoResult returns correct event fields."""
        result = GeoResult(
            country="United States",
            country_code="US",
            city="San Francisco",
            latitude=37.7749,
            longitude=-122.4194,
            asn=13335,
            asn_org="Cloudflare, Inc.",
        )
        fields = result.to_event_fields()

        assert fields["geo_country"] == "United States"
        assert fields["geo_country_code"] == "US"
        assert fields["geo_city"] == "San Francisco"
        assert fields["geo_lat"] == 37.7749
        assert fields["geo_lon"] == -122.4194
        assert fields["geo_asn"] == "AS13335"
        assert fields["geo_asn_org"] == "Cloudflare, Inc."

    def test_partial_result(self):
        """Partial GeoResult only includes available fields."""
        result = GeoResult(country="Germany", country_code="DE")
        fields = result.to_event_fields()

        assert "geo_country" in fields
        assert "geo_city" not in fields
        assert "geo_asn" not in fields

    def test_to_dict_excludes_none_and_false(self):
        """to_dict excludes None and False values."""
        result = GeoResult(country="Japan")
        d = result.to_dict()
        assert "country" in d
        assert "city" not in d
        assert "is_anonymous_proxy" not in d


class TestLRUCache:
    """Tests for the internal LRU cache."""

    def test_put_and_get(self):
        """Basic put/get works."""
        cache = _LRUCache(maxsize=10)
        result = GeoResult(country="Test")
        cache.put("1.2.3.4", result)
        assert cache.get("1.2.3.4") is result

    def test_miss_returns_none(self):
        """Cache miss returns None."""
        cache = _LRUCache(maxsize=10)
        assert cache.get("1.2.3.4") is None

    def test_eviction(self):
        """Oldest entries are evicted when cache is full."""
        cache = _LRUCache(maxsize=3)
        cache.put("1.1.1.1", GeoResult(country="A"))
        cache.put("2.2.2.2", GeoResult(country="B"))
        cache.put("3.3.3.3", GeoResult(country="C"))

        # Adding a 4th should evict the first
        cache.put("4.4.4.4", GeoResult(country="D"))

        assert cache.get("1.1.1.1") is None
        assert cache.get("2.2.2.2") is not None
        assert cache.get("4.4.4.4") is not None

    def test_lru_order(self):
        """Accessing an entry refreshes its position."""
        cache = _LRUCache(maxsize=3)
        cache.put("1.1.1.1", GeoResult(country="A"))
        cache.put("2.2.2.2", GeoResult(country="B"))
        cache.put("3.3.3.3", GeoResult(country="C"))

        # Access first entry to refresh it
        cache.get("1.1.1.1")

        # Adding 4th should evict "2.2.2.2" (now least recently used)
        cache.put("4.4.4.4", GeoResult(country="D"))

        assert cache.get("1.1.1.1") is not None  # refreshed, not evicted
        assert cache.get("2.2.2.2") is None  # evicted


class TestGeoIPResolver:
    """Tests for GeoIPResolver."""

    def test_disabled_resolver(self):
        """Disabled resolver returns empty results."""
        resolver = GeoIPResolver(enabled=False)
        result = resolver.lookup("8.8.8.8")
        assert isinstance(result, GeoResult)
        assert result.country is None

    def test_localhost_skipped(self):
        """Localhost IPs are skipped."""
        resolver = GeoIPResolver()
        result = resolver.lookup("127.0.0.1")
        assert result.country is None

        result = resolver.lookup("::1")
        assert result.country is None

    def test_unknown_ip_skipped(self):
        """Unknown/empty IPs are skipped."""
        resolver = GeoIPResolver()
        result = resolver.lookup("unknown")
        assert result.country is None

        result = resolver.lookup("")
        assert result.country is None

    def test_caching_works(self):
        """Results are cached for repeated lookups."""
        resolver = GeoIPResolver()
        # Even without databases, the lookup returns an empty result
        # and caches it for non-skipped IPs
        result1 = resolver.lookup("203.0.113.1")
        result2 = resolver.lookup("203.0.113.1")
        # Both should return the same (cached) result
        assert result1.country == result2.country


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_lookup_ip(self):
        """lookup_ip returns a GeoResult."""
        result = lookup_ip("8.8.8.8")
        assert isinstance(result, GeoResult)

    def test_get_geo_fields(self):
        """get_geo_fields returns a dict."""
        fields = get_geo_fields("8.8.8.8")
        assert isinstance(fields, dict)

    def test_get_geo_fields_localhost(self):
        """get_geo_fields returns empty dict for localhost."""
        fields = get_geo_fields("127.0.0.1")
        assert fields == {}
