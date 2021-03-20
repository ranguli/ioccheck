import logging

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
        self.reputation = self._format_reputation(service.reputation)
        self.detections = self._format_detections(
            service.detections,
            service.detection_coverage,
            service.detection_count,
        )
        self.detection_count = self._format_detection_count(
            service.detection_coverage, service.detection_count
        )
        self.relationships = service.relationships
        self.popular_threat_names = self._format_popular_threat_names(service)
        self.tags = self._format_tags(service)

    def _format_reputation(self, reputation: int) -> str:

        if reputation < 0:
            reputation_string = colored(str(reputation), "red")
        elif reputation > 0:
            reputation_string = colored(str(reputation), "green")
        else:
            reputation_string = colored(str(reputation), "yellow")

        return reputation_string

    def _format_detection_count(self, detection_coverage, detection_count):
        detection_percent = detection_coverage * 100

        detection_count_string = f"{detection_count} engines ({detection_percent:.2g}%) detected this file.\n"
        if detection_count == 0:
            detection_count_string = colored(detection_count_string, "green")
        elif detection_count > 0:
            detection_count_string = colored(detection_count_string, "red")

        return detection_count_string

    def _format_detections(self, detections, detection_coverage, detection_count):

        table = [["Antivirus", "Detection"]]

        for detection, result in detections.items():
            if result.get("category") == "malicious":
                table.append([detection, colored(result.get("result"), "red")])

        return tabulate(table, headers="firstrow", tablefmt="fancy_grid")

    def _format_sandbox_verdicts(self, service):
        result = None
        try:
            result = service.response.sandbox_verdicts
        except AttributeError:
            pass

        return result

    def _format_tags(self, service):
        return ", ".join(service.tags) if service.tags else None

    def _format_popular_threat_names(self, service):
        return (
            ", ".join(service.popular_threat_names)
            if service.popular_threat_names
            else None
        )
