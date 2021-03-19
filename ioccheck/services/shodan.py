from typing import Union
from ipaddress import IPv4Address, IPv6Address

import shodan
from backoff import expo, on_exception
from ratelimit import RateLimitException, limits

from ioccheck.services.service import Service


class Shodan(Service):
    name = "shodan"

    def __init__(self, ip: Union[IPv4Address, IPv6Address], api_key: str):

        self.ip = ip
        self.__url = "https://shodan.io/host/"
        self.response = self._get_api_response(ip, api_key)

        self.investigation_url = f"{self.url}/{ip}"
        self.is_malicious = None  # self._get_is_malicious(self.response)

        self.tags = self._get_tags(self.response)

    @on_exception(expo, RateLimitException, max_tries=10)
    @limits(calls=15, period=60)
    def _get_api_response(
        self, ip: Union[IPv4Address, IPv6Address], api_key: str
    ) -> dict:
        client = shodan.Shodan(api_key)
        return client.host(str(ip))

    def _get_tags(self, response):
        return response.get("tags")
