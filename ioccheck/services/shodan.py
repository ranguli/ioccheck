#!/usr/bin/env python
"""Provides support for the Shodan.io service"""

from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union

import shodan
from backoff import expo, on_exception
from ratelimit import RateLimitException, limits

from ioccheck.exceptions import APIError, InvalidCredentialsError
from ioccheck.services.service import Service


class Shodan(Service):
    """Represents a response from the Shodan.io API"""

    name = "shodan"
    url = "https://shodan.io/host/"
    ioc: Union[IPv4Address, IPv6Address]
    required_credentials = ["api_key"]

    def __init__(self, ioc: Union[IPv4Address, IPv6Address], credentials: dict):
        Service.__init__(self, ioc, credentials)
        self._response_data = self.response.get("data")[0]  # type: ignore

    @on_exception(expo, RateLimitException, max_tries=10)
    @limits(calls=15, period=60)
    def _get_api_response(self, ioc: Union[IPv4Address, IPv6Address]) -> dict:
        if not self.credentials.api_key:
            raise InvalidCredentialsError

        client = shodan.Shodan(self.credentials.api_key)

        try:
            result = client.host(str(ioc))
        except shodan.exception.APIError as e:
            if str(e) == "Invalid API key":
                raise InvalidCredentialsError(
                    "Shodan says your API keys are invalid."
                ) from e
            else:
                raise APIError from e

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
        return self._response_data.get("tags", default=[])

    @property
    def hostnames(self) -> list:
        """Hostnames found for the given IP address"""
        return self.response.get("hostnames", default=[])

    @property
    def vulns(self) -> list:
        """CVEs found by the Shodan scanners for the given IP address"""
        return self.response.get("vulns", default=[])
