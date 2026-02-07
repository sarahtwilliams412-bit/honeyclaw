#!/usr/bin/env python3
"""
Honeyclaw GeoIP Module

IP geolocation at event creation time using MaxMind GeoLite2 databases.
Falls back to a lightweight IP-to-country lookup when MaxMind database
is not available.

Environment variables:
    GEOIP_DB_PATH       - Path to GeoLite2-City.mmdb (default: /usr/share/GeoIP/GeoLite2-City.mmdb)
    GEOIP_ASN_DB_PATH   - Path to GeoLite2-ASN.mmdb (default: /usr/share/GeoIP/GeoLite2-ASN.mmdb)
    GEOIP_ENABLED       - Enable/disable geolocation (default: true)
    GEOIP_CACHE_SIZE    - Max cached lookups (default: 10000)
    HONEYCLAW_GEOIP_DB_PATH   - Alternative path variable
    HONEYCLAW_GEOIP_ENABLED   - Alternative enable variable

Requires: geoip2 (pip install geoip2) or maxminddb (pip install maxminddb)
"""

import ipaddress
import logging
import os
import threading
from collections import OrderedDict
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional

logger = logging.getLogger("honeyclaw.geoip")

# Try to import geoip2
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

# Try maxminddb as fallback
try:
    import maxminddb
    MAXMINDDB_AVAILABLE = True
except ImportError:
    MAXMINDDB_AVAILABLE = False

if not GEOIP2_AVAILABLE and not MAXMINDDB_AVAILABLE:
    logger.info("No GeoIP library installed — using basic IP range lookup (pip install geoip2 or maxminddb)")


DEFAULT_CITY_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
DEFAULT_ASN_DB = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
DEFAULT_CACHE_SIZE = 10000


@dataclass
class GeoResult:
    """Result of a geolocation lookup."""

    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    organization: Optional[str] = None
    is_anonymous_proxy: bool = False
    is_satellite_provider: bool = False
    is_private: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict, excluding None values and False booleans."""
        result = {}
        if self.is_private:
            result["is_private"] = True
            return result
        if self.country:
            result["country"] = self.country
        if self.country_code:
            result["country_code"] = self.country_code
        if self.city:
            result["city"] = self.city
        if self.region:
            result["region"] = self.region
        if self.latitude is not None:
            result["latitude"] = round(self.latitude, 4)
        if self.longitude is not None:
            result["longitude"] = round(self.longitude, 4)
        if self.asn is not None:
            result["asn"] = self.asn
        if self.asn_org:
            result["asn_org"] = self.asn_org
        if self.organization:
            result["organization"] = self.organization
        if self.is_anonymous_proxy:
            result["is_anonymous_proxy"] = True
        if self.is_satellite_provider:
            result["is_satellite_provider"] = True
        return result

    def to_event_fields(self) -> Dict[str, Any]:
        """
        Return fields suitable for embedding directly into a HoneypotEvent or
        log event dict. Uses the field names expected by the SIEM integration.
        """
        fields = {}
        if self.is_private:
            fields["geo_private"] = True
            return fields
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


# Alias for compatibility
GeoLocation = GeoResult


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


# Known IP ranges for basic geolocation (fallback when no DB available)
_KNOWN_RANGES: Dict[str, Dict[str, Any]] = {
    # Major cloud providers
    "3.0.0.0/8": {"organization": "Amazon AWS", "country": "United States", "country_code": "US"},
    "13.0.0.0/8": {"organization": "Amazon AWS", "country": "United States", "country_code": "US"},
    "34.0.0.0/8": {"organization": "Google Cloud", "country": "United States", "country_code": "US"},
    "35.0.0.0/8": {"organization": "Google Cloud", "country": "United States", "country_code": "US"},
    "20.0.0.0/8": {"organization": "Microsoft Azure", "country": "United States", "country_code": "US"},
    "40.0.0.0/8": {"organization": "Microsoft Azure", "country": "United States", "country_code": "US"},
    "104.0.0.0/8": {"organization": "Various US providers", "country": "United States", "country_code": "US"},
    "172.64.0.0/13": {"organization": "Cloudflare", "country": "United States", "country_code": "US"},
    # Common scanner/research ranges
    "45.33.32.0/24": {"organization": "Nmap/Scanme", "country": "United States", "country_code": "US"},
    "185.220.100.0/22": {"organization": "Tor Exit Nodes", "country": "Germany", "country_code": "DE"},
    # DigitalOcean
    "159.65.0.0/16": {"organization": "DigitalOcean", "country": "United States", "country_code": "US"},
    "167.172.0.0/16": {"organization": "DigitalOcean", "country": "United States", "country_code": "US"},
    # Hetzner
    "95.216.0.0/16": {"organization": "Hetzner", "country": "Germany", "country_code": "DE"},
    "135.181.0.0/16": {"organization": "Hetzner", "country": "Finland", "country_code": "FI"},
    # OVH
    "51.68.0.0/16": {"organization": "OVH", "country": "France", "country_code": "FR"},
    "51.75.0.0/16": {"organization": "OVH", "country": "France", "country_code": "FR"},
}


class GeoIPResolver:
    """
    Resolves IP addresses to geolocation data using MaxMind GeoLite2 databases.

    Falls back to basic IP range lookup when databases are unavailable.
    Thread-safe with built-in LRU caching.
    """

    def __init__(
        self,
        city_db_path: Optional[str] = None,
        asn_db_path: Optional[str] = None,
        cache_size: Optional[int] = None,
        enabled: Optional[bool] = None,
    ):
        # Check multiple env var names for compatibility
        enabled_env = os.environ.get("GEOIP_ENABLED") or os.environ.get("HONEYCLAW_GEOIP_ENABLED", "true")
        self.enabled = enabled if enabled is not None else (enabled_env.lower() == "true")

        self._city_reader = None
        self._asn_reader = None
        self._maxmind_reader = None
        self._use_geoip2 = False
        self._use_maxminddb = False
        self._cache = _LRUCache(
            cache_size or int(os.environ.get("GEOIP_CACHE_SIZE", DEFAULT_CACHE_SIZE))
        )

        if not self.enabled:
            logger.info("GeoIP disabled by configuration")
            return

        # Determine database path
        city_path = (
            city_db_path
            or os.environ.get("GEOIP_DB_PATH")
            or os.environ.get("HONEYCLAW_GEOIP_DB_PATH")
            or DEFAULT_CITY_DB
        )
        asn_path = asn_db_path or os.environ.get("GEOIP_ASN_DB_PATH", DEFAULT_ASN_DB)

        # Try geoip2 first (preferred)
        if GEOIP2_AVAILABLE and os.path.exists(city_path):
            try:
                self._city_reader = geoip2.database.Reader(city_path)
                self._use_geoip2 = True
                logger.info(f"GeoIP city database loaded (geoip2): {city_path}")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP city database with geoip2: {e}")

        # Try ASN database with geoip2
        if GEOIP2_AVAILABLE and os.path.exists(asn_path):
            try:
                self._asn_reader = geoip2.database.Reader(asn_path)
                logger.info(f"GeoIP ASN database loaded: {asn_path}")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP ASN database: {e}")

        # Fallback to maxminddb if geoip2 didn't work
        if not self._use_geoip2 and MAXMINDDB_AVAILABLE and os.path.exists(city_path):
            try:
                self._maxmind_reader = maxminddb.open_database(city_path)
                self._use_maxminddb = True
                logger.info(f"GeoIP database loaded (maxminddb): {city_path}")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP database with maxminddb: {e}")

        if not self._use_geoip2 and not self._use_maxminddb:
            logger.info("No GeoIP databases loaded — using basic IP range fallback")

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

        # Check for private/reserved IPs
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_reserved or addr.is_loopback:
                return GeoResult(is_private=True)
        except ValueError:
            return GeoResult()

        # Check cache
        cached = self._cache.get(ip)
        if cached is not None:
            return cached

        result = GeoResult()

        # Try geoip2
        if self._use_geoip2:
            result = self._lookup_geoip2(ip)
        # Try maxminddb
        elif self._use_maxminddb:
            result = self._lookup_maxminddb(ip)
        # Fallback to basic lookup
        else:
            result = self._lookup_basic(ip)

        self._cache.put(ip, result)
        return result

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an event with geolocation data.

        Looks for source_ip, ip, or client_ip fields and adds
        geo fields to the event.

        Args:
            event: Event dict (modified in-place)

        Returns:
            The enriched event dict
        """
        ip = event.get("source_ip") or event.get("ip") or event.get("client_ip", "")
        if ip:
            geo = self.lookup(ip)
            geo_dict = geo.to_dict()
            if geo_dict:
                event["geo"] = geo_dict
        return event

    def close(self):
        """Close database readers."""
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()
        if self._maxmind_reader:
            try:
                self._maxmind_reader.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Lookup implementations
    # ------------------------------------------------------------------

    def _lookup_geoip2(self, ip: str) -> GeoResult:
        """Look up using geoip2 library."""
        result = GeoResult()

        if self._city_reader:
            try:
                city_resp = self._city_reader.city(ip)
                result.country = city_resp.country.name if city_resp.country else None
                result.country_code = city_resp.country.iso_code if city_resp.country else None
                result.city = city_resp.city.name if city_resp.city else None
                if city_resp.location:
                    result.latitude = city_resp.location.latitude
                    result.longitude = city_resp.location.longitude
                if city_resp.traits:
                    result.is_anonymous_proxy = getattr(city_resp.traits, "is_anonymous_proxy", False)
                    result.is_satellite_provider = getattr(city_resp.traits, "is_satellite_provider", False)
            except Exception:
                pass

        if self._asn_reader:
            try:
                asn_resp = self._asn_reader.asn(ip)
                result.asn = asn_resp.autonomous_system_number
                result.asn_org = asn_resp.autonomous_system_organization
            except Exception:
                pass

        return result

    def _lookup_maxminddb(self, ip: str) -> GeoResult:
        """Look up using maxminddb library."""
        try:
            record = self._maxmind_reader.get(ip)
            if not record:
                return GeoResult()

            country = record.get("country", {})
            city = record.get("city", {})
            location = record.get("location", {})
            traits = record.get("traits", {})

            return GeoResult(
                country=country.get("names", {}).get("en", ""),
                country_code=country.get("iso_code", ""),
                city=city.get("names", {}).get("en", ""),
                latitude=location.get("latitude"),
                longitude=location.get("longitude"),
                asn=traits.get("autonomous_system_number"),
                organization=traits.get("autonomous_system_organization", ""),
            )
        except Exception:
            return GeoResult()

    def _lookup_basic(self, ip: str) -> GeoResult:
        """
        Basic IP geolocation using well-known IP ranges.

        This is a very rough approximation for when MaxMind is unavailable.
        Covers major cloud/hosting providers and some country ranges.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return GeoResult()

        # Check against known ranges
        for cidr, info in _KNOWN_RANGES.items():
            try:
                if addr in ipaddress.ip_network(cidr):
                    return GeoResult(
                        country=info.get("country"),
                        country_code=info.get("country_code"),
                        organization=info.get("organization"),
                    )
            except ValueError:
                continue

        # Default: unknown
        return GeoResult()


# Alias for compatibility
GeoIPLookup = GeoIPResolver


# --- Module-level singleton ---

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


# Alias for compatibility
def get_geoip() -> GeoIPResolver:
    """Alias for get_geoip_resolver()."""
    return get_geoip_resolver()


def lookup_ip(ip: str) -> GeoResult:
    """Convenience function: look up geolocation for an IP address."""
    return get_geoip_resolver().lookup(ip)


def get_geo_fields(ip: str) -> Dict[str, Any]:
    """Convenience function: get event-ready geo fields for an IP address."""
    return lookup_ip(ip).to_event_fields()


def enrich_event_geo(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to enrich an event with geolocation."""
    return get_geoip_resolver().enrich_event(event)
