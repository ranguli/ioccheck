import logging

from tabulate import tabulate
from termcolor import colored

from ioccheck.cli.formatters import Formatter
from ioccheck.services import Shodan

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


class ShodanFormatter(Formatter):
    def __init__(self, service: Shodan):
        self.tags = self._format_tags(service)
        self.location = self._format_location_data(service)

    def _format_tags(self, service):
        return ", ".join(service.tags) if service.tags else None

    def _format_location_data(self, service):

        location = service.location
        table = []

        headings = {
            "City": location.get("city"),
            "Country": location.get("country_name"),
            "Organization": location.get("org"),
            "ISP": location.get("isp"),
            "Hostnames": ", ".join(service.hostnames),
            "ASN": location.get("asn"),
        }

        for title, value in headings.items():
            if value:
                table.append([colored(title, "blue"), value])

        return tabulate(table, tablefmt="fancy_grid")
