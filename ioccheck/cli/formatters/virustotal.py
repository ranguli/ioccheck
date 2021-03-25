#!/usr/bin/env python
"""Module provides human-friendly output from the VirusTotal Service"""

import logging
from typing import Optional

from tabulate import tabulate
from termcolor import colored

from ioccheck.cli.formatters.formatter import Formatter
from ioccheck.services import VirusTotal

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


class VirusTotalFormatter(Formatter):
    """Provide pre-formatted output from the VirusTotal Service"""

    def __init__(self, service: VirusTotal):
        Formatter.__init__(self, service)

    @property
    def reputation(self) -> Optional[str]:
        """Provide pre-formatted output of the community score"""
        if not isinstance(self.service.reputation, int):
            return None

        if self.service.reputation < 0:
            reputation_string = colored(str(self.service.reputation), "red")
        elif self.service.reputation > 0:
            reputation_string = colored(str(self.service.reputation), "green")
        else:
            reputation_string = colored(str(self.service.reputation), "yellow")

        return reputation_string

    @property
    def detection_count(self):
        """Provide pre-formatted output for the number of detections"""
        detection_percent = self.service.detection_coverage * 100

        detection_count_string = f"{self.service.detection_count} engines ({detection_percent:.2g}%) detected this file.\n"
        if self.service.detection_count == 0:
            detection_count_string = colored(detection_count_string, "green")
        elif self.service.detection_count > 0:
            detection_count_string = colored(detection_count_string, "red")

        return detection_count_string

    @property
    def detections(self):
        """Provide pre-formatted output of the detecting A.V engines"""

        table = [["Antivirus", "Detection"]]

        for detection, result in self.service.detections.items():
            if result.get("category") == "malicious":
                table.append([detection, colored(result.get("result"), "red")])

        return tabulate(table, headers="firstrow", tablefmt="fancy_grid")

    @property
    def sandbox_verdicts(self):
        """Provide pre-formatted output of the results from sandbox analysis"""
        result = None
        try:
            result = self.service.response.sandbox_verdicts
        except AttributeError:
            pass

        return result

    @property
    def tags(self):
        """Provide pre-formatted output of user-submitted tags for the sample"""
        return ", ".join(self.service.tags) if self.service.tags else None

    @property
    def popular_threat_names(self):
        """Provide pre-formatted output of popular humand-friendly names"""
        return (
            ", ".join(self.service.popular_threat_names)
            if self.service.popular_threat_names
            else None
        )
