import ipaddress
import logging
from dataclasses import dataclass
from typing import List, Union

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

        if not isinstance(ip_addr, str):
            raise InvalidIPException

        try:
            self.ioc = ipaddress.ip_address(ip_addr)
        except ValueError:
            raise InvalidIPException

        # self.is_ipv4 = True if self.hash_type == SHA256 else False
        # self.is_ipv6 = True if self.hash_type == MD5 else False

    def check(self, services: Union[List, None], config_path: Union[str, None]):
        reports = self._get_reports(services, config_path)
        self.reports = IPReport(**reports)
