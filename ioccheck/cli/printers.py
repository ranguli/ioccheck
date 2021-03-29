#!/usr/bin/env python

from abc import ABC, abstractmethod
from typing import Optional

from tabulate import tabulate
from termcolor import colored, cprint

from ioccheck.services import Twitter


class Printer(ABC):
    heading_color = "blue"
    error_color = "red"

    def __init__(self, ioc, heading, attr, delim, error):
        self.ioc = ioc
        self.heading = heading
        self.attr = attr
        self.delim = delim
        self.error = error

        self.text = self.make_text()

    @abstractmethod
    def make_text(self) -> Optional[str]:
        pass

    def print_text(self):
        if (
            self.text is None
            or self.text == ""
            or not hasattr(self.ioc, self.attr)
            or getattr(self.ioc, self.attr) is None
        ):
            cprint(f"[!] {self.error}", self.error_color)
            return

        if self.heading is None:
            print(self.text)
        else:
            self.heading = f"[*] {self.heading}"
            print(
                f"\n{colored(self.heading, self.heading_color)}:{self.delim}{self.text}"
            )


class BehaviourPrinter(Printer):
    heading = "Sandbox behaviour"
    attr = "behaviour"
    delim = "\n"
    error = "No behaviour data to display"

    def __init__(self, ioc):
        Printer.__init__(self, ioc, self.heading, self.attr, self.delim, self.error)

    def make_text(self) -> Optional[str]:
        table = [["Vendor", "Behaviour", "Threat"]]

        for result in self.ioc.behaviour:
            if result.get("threat") is None:
                continue
            elif result.get("threat") == 1:
                threat = colored("Neutral", "green")
            elif result.get("threat") == 2:
                threat = colored("Suspicious", "yellow")
            elif result.get("threat") == 3:
                threat = colored("Malicious", "red")

            table.append([result.get("service"), result.get("behaviour"), threat])

        if len(table) == 1:
            return None

        return tabulate(table, tablefmt="fancy_grid")


class TagsPrinter(Printer):
    heading = "User-submitted tags"
    attr = "tags"
    delim = " "
    error = "No tags to display"

    def __init__(self, ioc):
        Printer.__init__(self, ioc, self.heading, self.attr, self.delim, self.error)

    def make_text(self) -> Optional[str]:
        return ", ".join(self.ioc.tags)


class TwitterPrinter(Printer):
    heading = None
    attr = "tweets"
    delim = " "
    error = "No tweets about this IOC."
    service = Twitter

    def __init__(self, ioc):
        Printer.__init__(self, ioc, self.heading, self.attr, self.delim, self.error)

    def make_text(self) -> Optional[str]:
        text = []
        for tweet in self.ioc.tweets:
            author = colored(f"\n[*] Tweet from: @{tweet.author}:", self.heading_color)
            url = colored(tweet.url, self.heading_color)
            text.append(f"{author} {tweet.text}\n{url}\n")
        return "".join(text)


class DetectionsPrinter(Printer):
    attr = "detections"
    delim = "\n"
    error = "No vendors detected this sample."
    heading = "Vendor detections"

    def __init__(self, ioc):
        Printer.__init__(self, ioc, self.heading, self.attr, self.delim, self.error)

    def make_text(self) -> Optional[str]:
        table = [["Vendor", "Detection"]]

        for detection, result in self.ioc.detections.items():
            if result.get("category") == "malicious":
                table.append([detection, colored(result.get("result"), "red")])

        return tabulate(table, headers="firstrow", tablefmt="fancy_grid")

    def detection_count(self):
        """Provide pre-formatted output for the number of detections"""
        detection_percent = self.ioc.detection_coverage * 100

        detection_count_string = f"{self.service.detection_count} engines ({detection_percent:.2g}%) detected this file.\n"

        if self.service.detection_count == 0:
            detection_count_string = colored(detection_count_string, "green")
        elif self.service.detection_count > 0:
            detection_count_string = colored(detection_count_string, "red")

        return detection_count_string
