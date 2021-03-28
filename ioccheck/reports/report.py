#!/usr/bin/evnv python

import datetime
import pkg_resources
from abc import ABC, abstractmethod

from ioccheck.iocs import IOC, Hash, IP


class Report(ABC):
    def __init__(self, ioc: IOC, templates_dir):
        self.ioc = ioc
        self.templates_dir = templates_dir

        if isinstance(self.ioc, Hash):
            self.template_file = "hash_template.html"
        elif isinstance(self.ioc, IP):
            self.template_file = "ip_template.html"
        self.templates_dir = templates_dir

    @property
    def footer(self) -> str:
        today = datetime.datetime.today()
        day = self._make_ordinal(today.day)

        datestamp = f"{today.strftime('%A %B')} {day}, {today.year} at {today.strftime('%I:%M:%S %p')}"
        version = pkg_resources.get_distribution("ioccheck").version

        return f"Generated on {datestamp} by ioccheck v{version}"

    def _make_ordinal(self, n):
        # https://stackoverflow.com/a/50992575
        n = int(n)
        suffix = ["th", "st", "nd", "rd", "th"][min(n % 10, 4)]
        if 11 <= (n % 100) <= 13:
            suffix = "th"
        return str(n) + suffix

    @abstractmethod
    def generate(self):
        pass
