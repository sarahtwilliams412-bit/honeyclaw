#!/usr/bin/env python3
"""
Honeyclaw GeoIP Module

IP geolocation at event creation time using MaxMind GeoLite2.

Falls back to a lightweight IP-to-country lookup when MaxMind
database is not available.

Environment variables:
  HONEYCLAW_GEOIP_DB_PATH   - Path to GeoLite2-City.mmdb (optional)
  HONEYCLAW_GEOIP_ENABLED   - Enable geolocation (default: true)
"""

import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class GeoLocation:
    """Geographic location information for an IP address."""
    country: str = ""
    country_code: str = ""
    city: str = ""
    region: str = ""
    asn: int = 0
    organization: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    is_private: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.is_private:
            d["is_private"] = True
            return d
        if self.country:
            d["country"] = self.country
        if self.country_code:
            d["country_code"] = self.country_code
        if self.city:
            d["city"] = self.city
        if self.region:
            d["region"] = self.region
        if self.asn:
            d["asn"] = self.asn
        if self.organization:
            d["organization"] = self.organization
        if self.latitude:
            d["latitude"] = round(self.latitude, 4)
        if self.longitude:
            d["longitude"] = round(self.longitude, 4)
        return d


class GeoIPLookup:
    """
    IP geolocation service.

    Attempts to use MaxMind GeoLite2 database if available,
    otherwise uses a basic IP range to country mapping.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.enabled = os.environ.get("HONEYCLAW_GEOIP_ENABLED", "true").lower() == "true"
        self.db_path = db_path or os.environ.get("HONEYCLAW_GEOIP_DB_PATH", "")
        self._reader = None
        self._maxmind_available = False

        if self.enabled and self.db_path:
            self._try_load_maxmind()

    def _try_load_maxmind(self):
        """Try to load MaxMind GeoLite2 database."""
        try:
            import maxminddb
            if Path(self.db_path).exists():
                self._reader = maxminddb.open_database(self.db_path)
                self._maxmind_available = True
        except ImportError:
            pass
        except Exception:
            pass

    def lookup(self, ip: str) -> GeoLocation:
        """
        Look up geolocation for an IP address.

        Args:
            ip: IP address string

        Returns:
            GeoLocation with available information
        """
        if not self.enabled:
            return GeoLocation()

        # Check for private/reserved IPs
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_reserved or addr.is_loopback:
                return GeoLocation(is_private=True)
        except ValueError:
            return GeoLocation()

        # Try MaxMind
        if self._maxmind_available and self._reader:
            return self._lookup_maxmind(ip)

        # Fallback: basic lookup using first octet ranges
        return self._lookup_basic(ip)

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an event with geolocation data.

        Looks for source_ip, ip, or client_ip fields and adds
        a 'geo' field with location information.

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
        """Close the database reader."""
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Lookup implementations
    # ------------------------------------------------------------------

    def _lookup_maxmind(self, ip: str) -> GeoLocation:
        """Look up using MaxMind GeoLite2."""
        try:
            record = self._reader.get(ip)
            if not record:
                return GeoLocation()

            country = record.get("country", {})
            city = record.get("city", {})
            location = record.get("location", {})
            traits = record.get("traits", {})

            return GeoLocation(
                country=country.get("names", {}).get("en", ""),
                country_code=country.get("iso_code", ""),
                city=city.get("names", {}).get("en", ""),
                latitude=location.get("latitude", 0.0),
                longitude=location.get("longitude", 0.0),
                asn=traits.get("autonomous_system_number", 0),
                organization=traits.get("autonomous_system_organization", ""),
            )
        except Exception:
            return GeoLocation()

    def _lookup_basic(self, ip: str) -> GeoLocation:
        """
        Basic IP geolocation using well-known IP ranges.

        This is a very rough approximation for when MaxMind is unavailable.
        Covers major cloud/hosting providers and some country ranges.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return GeoLocation()

        # Check against known ranges
        for cidr, info in _KNOWN_RANGES.items():
            try:
                if addr in ipaddress.ip_network(cidr):
                    return GeoLocation(**info)
            except ValueError:
                continue

        # Default: unknown
        return GeoLocation()


# Known IP ranges for basic geolocation
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


# --- Singleton ---

_default_geoip: Optional[GeoIPLookup] = None


def get_geoip() -> GeoIPLookup:
    """Get or create the default GeoIP lookup."""
    global _default_geoip
    if _default_geoip is None:
        _default_geoip = GeoIPLookup()
    return _default_geoip


def enrich_event_geo(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to enrich an event with geolocation."""
    return get_geoip().enrich_event(event)
