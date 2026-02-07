#!/usr/bin/env python3
"""
Honeyclaw GeoIP Module

IP geolocation at event creation time using MaxMind GeoLite2 databases.
Falls back gracefully when databases are unavailable.

Environment variables:
    GEOIP_DB_PATH       - Path to GeoLite2-City.mmdb (default: /usr/share/GeoIP/GeoLite2-City.mmdb)
    GEOIP_ASN_DB_PATH   - Path to GeoLite2-ASN.mmdb (default: /usr/share/GeoIP/GeoLite2-ASN.mmdb)
    GEOIP_ENABLED       - Enable/disable geolocation (default: true)
    GEOIP_CACHE_SIZE    - Max cached lookups (default: 10000)

Requires: geoip2 (pip install geoip2)
"""

import os
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

logger = logging.getLogger("honeyclaw.geoip")

# Try to import geoip2
try:
    import geoip2.database
    import geoip2.errors

    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    logger.info("geoip2 not installed — geolocation disabled (pip install geoip2)")


DEFAULT_CITY_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
DEFAULT_ASN_DB = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
DEFAULT_CACHE_SIZE = 10000


@dataclass
class GeoResult:
    """Result of a geolocation lookup."""

    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_anonymous_proxy: bool = False
    is_satellite_provider: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict, excluding None values."""
        return {k: v for k, v in asdict(self).items() if v is not None and v is not False}

    def to_event_fields(self) -> Dict[str, Any]:
        """
        Return fields suitable for embedding directly into a HoneypotEvent or
        log event dict. Uses the field names expected by the SIEM integration.
        """
        fields = {}
        if self.country:
            fields["geo_country"] = self.country
        if self.country_code:
            fields["geo_country_code"] = self.country_code
        if self.city:
            fields["geo_city"] = self.city
        if self.latitude is not None:
            fields["geo_lat"] = self.latitude
        if self.longitude is not None:
            fields["geo_lon"] = self.longitude
        if self.asn is not None:
            fields["geo_asn"] = f"AS{self.asn}"
        if self.asn_org:
            fields["geo_asn_org"] = self.asn_org
        return fields


class _LRUCache:
    """Simple thread-safe LRU cache."""

    def __init__(self, maxsize: int):
        self._maxsize = maxsize
        self._cache: OrderedDict[str, GeoResult] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[GeoResult]:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
        return None

    def put(self, key: str, value: GeoResult):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            else:
                if len(self._cache) >= self._maxsize:
                    self._cache.popitem(last=False)
            self._cache[key] = value


class GeoIPResolver:
    """
    Resolves IP addresses to geolocation data using MaxMind GeoLite2 databases.

    Thread-safe with built-in LRU caching.
    """

    def __init__(
        self,
        city_db_path: Optional[str] = None,
        asn_db_path: Optional[str] = None,
        cache_size: Optional[int] = None,
        enabled: Optional[bool] = None,
    ):
        self.enabled = enabled if enabled is not None else (
            os.environ.get("GEOIP_ENABLED", "true").lower() == "true"
        )

        self._city_reader = None
        self._asn_reader = None
        self._cache = _LRUCache(
            cache_size
            or int(os.environ.get("GEOIP_CACHE_SIZE", DEFAULT_CACHE_SIZE))
        )

        if not self.enabled:
            logger.info("GeoIP disabled by configuration")
            return

        if not GEOIP2_AVAILABLE:
            self.enabled = False
            return

        # Open city database
        city_path = city_db_path or os.environ.get("GEOIP_DB_PATH", DEFAULT_CITY_DB)
        if os.path.exists(city_path):
            try:
                self._city_reader = geoip2.database.Reader(city_path)
                logger.info(f"GeoIP city database loaded: {city_path}")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP city database: {e}")
        else:
            logger.info(f"GeoIP city database not found at {city_path}")

        # Open ASN database
        asn_path = asn_db_path or os.environ.get("GEOIP_ASN_DB_PATH", DEFAULT_ASN_DB)
        if os.path.exists(asn_path):
            try:
                self._asn_reader = geoip2.database.Reader(asn_path)
                logger.info(f"GeoIP ASN database loaded: {asn_path}")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP ASN database: {e}")
        else:
            logger.info(f"GeoIP ASN database not found at {asn_path}")

        if not self._city_reader and not self._asn_reader:
            logger.warning("No GeoIP databases available — geolocation disabled")
            self.enabled = False

    def lookup(self, ip: str) -> GeoResult:
        """
        Look up geolocation data for an IP address.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            GeoResult with available fields populated. Empty GeoResult on
            error or if databases are unavailable.
        """
        if not self.enabled or not ip or ip in ("unknown", "127.0.0.1", "::1"):
            return GeoResult()

        # Check cache
        cached = self._cache.get(ip)
        if cached is not None:
            return cached

        result = GeoResult()

        # City/Country lookup
        if self._city_reader:
            try:
                city_resp = self._city_reader.city(ip)
                result.country = (
                    city_resp.country.name if city_resp.country else None
                )
                result.country_code = (
                    city_resp.country.iso_code if city_resp.country else None
                )
                result.city = city_resp.city.name if city_resp.city else None
                if city_resp.location:
                    result.latitude = city_resp.location.latitude
                    result.longitude = city_resp.location.longitude
                if city_resp.traits:
                    result.is_anonymous_proxy = getattr(
                        city_resp.traits, "is_anonymous_proxy", False
                    )
                    result.is_satellite_provider = getattr(
                        city_resp.traits, "is_satellite_provider", False
                    )
            except Exception:
                pass  # IP not in database or invalid — return empty fields

        # ASN lookup
        if self._asn_reader:
            try:
                asn_resp = self._asn_reader.asn(ip)
                result.asn = asn_resp.autonomous_system_number
                result.asn_org = asn_resp.autonomous_system_organization
            except Exception:
                pass

        self._cache.put(ip, result)
        return result

    def close(self):
        """Close database readers."""
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()


# Module-level singleton
_default_resolver: Optional[GeoIPResolver] = None
_init_lock = threading.Lock()


def get_geoip_resolver() -> GeoIPResolver:
    """Get or create the default GeoIPResolver singleton."""
    global _default_resolver
    if _default_resolver is None:
        with _init_lock:
            if _default_resolver is None:
                _default_resolver = GeoIPResolver()
    return _default_resolver


def lookup_ip(ip: str) -> GeoResult:
    """Convenience function: look up geolocation for an IP address."""
    return get_geoip_resolver().lookup(ip)


def get_geo_fields(ip: str) -> Dict[str, Any]:
    """Convenience function: get event-ready geo fields for an IP address."""
    return lookup_ip(ip).to_event_fields()
