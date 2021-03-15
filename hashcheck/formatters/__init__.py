from tabulate import tabulate
from termcolor import colored, cprint

from hashcheck.reports import VirusTotalReport


class Formatter:
    def __init__(self):
        pass

class VirusTotalFormatter(Formatter):

    def __init__(self, report: VirusTotalReport):
        self.reputation = self._format_reputation(report.reputation)
        self.detections = self._format_detections(report.get_detections(), report.detection_coverage, report.detection_count)

    def _format_reputation(self, reputation: int) -> str:

        if reputation < 0:
            reputation_string = colored(str(reputation), "red")
        elif reputation > 0:
            reputation_string = colored(str(reputation), "green")
        else:
            reputation_string = colored(str(reputation), "yellow")

        return reputation_string

    def _format_detections(self, detections, detection_coverage, detection_count):

        detection_percent = detection_coverage * 100

        detection_count_string = f"{detection_count} engines ({detection_percent:.2g}%) detected this file.\n"
        if detection_count == 0:
            detection_count_string = colored(detection_count_string, "green")
        elif detection_count > 0:
            detection_count_string = colored(detection_count_string, "red")

        table = [["Antivirus", "Detected", "Result"]]

        for detection, result in detections.items():
            if result.get("category") == "malicious":
                malicious = colored("Yes", "red")
            else:
                malicious = colored("No", "green")

            table.append([detection, malicious, result.get("result")])

        return tabulate(table, headers="firstrow", tablefmt="fancy_grid")

