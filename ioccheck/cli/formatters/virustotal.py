import logging
from typing import Optional

from tabulate import tabulate
from termcolor import colored

from ioccheck.cli.formatters import Formatter
from ioccheck.services import VirusTotal

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


class VirusTotalFormatter(Formatter):
    def __init__(self, service: VirusTotal):
        Formatter.__init__(self, service)

    @property
    def reputation(self) -> Optional[str]:
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
        detection_percent = self.detection_coverage * 100

        detection_count_string = f"{self.service.detection_count} engines ({detection_percent:.2g}%) detected this file.\n"
        if self.service.detection_count == 0:
            detection_count_string = colored(detection_count_string, "green")
        elif self.service.detection_count > 0:
            detection_count_string = colored(detection_count_string, "red")

        return detection_count_string

    @property
    def detections(self):

        table = [["Antivirus", "Detection"]]

        for detection, result in self.service.detections.items():
            if result.get("category") == "malicious":
                table.append([detection, colored(result.get("result"), "red")])

        return tabulate(table, headers="firstrow", tablefmt="fancy_grid")

    @property
    def sandbox_verdicts(self):
        result = None
        try:
            result = self.service.response.sandbox_verdicts
        except AttributeError:
            pass

        return result

    @property
    def tags(self):
        return ", ".join(self.service.tags) if self.service.tags else None

    @property
    def popular_threat_names(self):
        return (
            ", ".join(self.service.popular_threat_names)
            if self.service.popular_threat_names
            else None
        )
