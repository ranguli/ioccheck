#!/usr/bin/env python
"""Provides support for the Shodan.io service"""

from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union

import shodan
from backoff import expo, on_exception
from ratelimit import RateLimitException, limits

from ioccheck.services.service import Service


class Shodan(Service):
    """Represents a response from the Shodan.io API"""

    name = "shodan"
    url = "https://shodan.io/host/"
    ioc: Union[IPv4Address, IPv6Address]

    def __init__(self, ioc: Union[IPv4Address, IPv6Address], api_key: str):
        Service.__init__(self, ioc, api_key)

        self.response = self._get_api_response(ioc, api_key)
        self._response_data = self.response.get("data")[0]

    @on_exception(expo, RateLimitException, max_tries=10)
    @limits(calls=15, period=60)
    def _get_api_response(
        self, ioc: Union[IPv4Address, IPv6Address], api_key: str
    ) -> dict:
        client = shodan.Shodan(api_key)
        result = client.host(str(ioc))
        return result

    @property
    def investigation_url(self) -> Optional[str]:
        """The URL a human can use to follow up for more information"""
        return f"{self.url}/{self.ioc}/"

    @property
    def location(self) -> dict:
        """Geolocation data for the IP address"""
        keys = [
            "region_code",
            "postal_code",
            "country_code",
            "city",
            "area_code",
            "country_name",
            "org",
            "isp",
            "asn",
        ]
        return {k: self.response.get(k) for k in keys}

    @property
    def tags(self) -> list:
        """User-submitted tags for the sample from the MalwareBazaar website"""
        return self._response_data.get("tags")

    @property
    def hostnames(self) -> list:
        """Hostnames found for the given IP address"""
        return self.response.get("hostnames")

    @property
    def vulns(self) -> list:
        """CVEs found by the Shodan scanners for the given IP address"""
        return self.response.get("vulns")
