import logging
from ipaddress import IPv4Address, IPv6Address
from typing import Union

import shodan
from backoff import expo, on_exception
from ratelimit import RateLimitException, limits

from ioccheck.services.service import Service

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


class Shodan(Service):
    name = "shodan"
    url = "https://shodan.io/host/"

    def __init__(self, ip: Union[IPv4Address, IPv6Address], api_key: str):

        self.ip = ip
        self.response = self._get_api_response(ip, api_key)

        self.investigation_url = f"{self.url}/{ip}"

        self.location = self._get_location_data(self.response)
        self.hostnames = self._get_hostnames(self.response)
        self.tags = self._get_tags(self.response)
        self.vulns = self._get_vulns(self.response)

    @on_exception(expo, RateLimitException, max_tries=10)
    @limits(calls=15, period=60)
    def _get_api_response(
        self, ip: Union[IPv4Address, IPv6Address], api_key: str
    ) -> dict:
        client = shodan.Shodan(api_key)
        result = client.host(str(ip))
        return result

    def _get_tags(self, response) -> list:
        return response.get("data")[0].get("tags")

    def _get_location_data(self, response) -> dict:
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
        return {k: response.get(k) for k in keys}

    def _get_hostnames(self, response) -> list:
        return response.get("hostnames")

    def _get_vulns(self, response) -> list:
        return response.get("vulns")
