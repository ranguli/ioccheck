import ipaddress
from ipaddress import IPv4Address, IPv6Address
import logging
from dataclasses import dataclass
from typing import List, Optional, Union

from ioccheck.exceptions import InvalidIPException
from ioccheck.iocs import IOC, IOCReport
from ioccheck.services import Shodan, ip_services

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


@dataclass
class IPReport(IOCReport):
    shodan: Shodan = None  # type: ignore


class IP(IOC):
    def __init__(self, ip_addr: str):
        self.all_services = ip_services
        self.ioc = self._get_ip(ip_addr)

        # self.is_ipv4 = True if self.hash_type == SHA256 else False
        # self.is_ipv6 = True if self.hash_type == MD5 else False

    def check(
        self, services: Optional[List] = None, config_path: Optional[str] = None
    ) -> None:
        reports = self._get_reports(services, config_path)
        self.reports = IPReport(**reports)

    def _get_ip(self, ip_addr: str) -> Union[IPv4Address, IPv6Address]:
        if not isinstance(ip_addr, str):
            raise InvalidIPException

        try:
            ip = ipaddress.ip_address(ip_addr)
        except ValueError:
            raise InvalidIPException

        if not ip.is_global:
            raise InvalidIPException

        return ip
