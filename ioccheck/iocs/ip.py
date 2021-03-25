#!/usr/bin/env python
"""Module representing IP addresses"""

import ipaddress
import logging
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import List, Optional, Union

from ioccheck.exceptions import InvalidIPException
from ioccheck.iocs.ioc import IOC, IOCReport
from ioccheck.services import Service, Shodan, ip_services

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

asyncio_logger = logging.getLogger("asyncio")
asyncio_logger.propagate = False
asyncio_logger.setLevel(logging.CRITICAL)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


@dataclass
class IPReport(IOCReport):
    """Report representing threat intelligence results for an IP object"""

    shodan: Shodan


class IP(IOC):
    """Type of IOC representing IP addresses

    Attributes:
        hash_type: Indicates the hashing algorithm used by the hash.
        ioc: Represenation of the IOC as a string
        services: Supported services that can be used to investigate the IOC

    """

    def __init__(self, ioc: str, config_path: Optional[str] = None):

        self.services = ip_services
        self.ioc = self.get_ip(ioc)

        IOC.__init__(self, ioc, config_path)

    def check(self, services: Optional[List[Service]] = None):
        """Get threat intelligence information for an IP

        Args:
            services: The threat intelligence services to be checked
        """
        reports = self._get_reports(services)
        self.reports = IPReport(**reports)

    @staticmethod
    def get_ip(ip_addr: str) -> Union[IPv4Address, IPv6Address]:
        """Convert an IPv4 or IPv6 address string into an IPAddress object

        Args:
            ip_addr: The threat intelligence services to be checked

        Returns:
            IP address as an object

        Raises:
            InvalidIPException: If the IP address string can't be converted.
        """
        if not isinstance(ip_addr, str):
            logger.error("%(ip_addr)s is not of type string.")
            raise InvalidIPException

        try:
            ip = ipaddress.ip_address(ip_addr)  # pylint: disable=C0103
        except ValueError as value_error:
            logger.error("%(ip_addr)s could not be converted to IPAddress object.")
            raise InvalidIPException from value_error

        if not ip.is_global:
            logger.error("%(ip_addr)s is not a public IP.")
            raise InvalidIPException

        return ip
