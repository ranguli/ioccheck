#!/usr/bin/env python
"""Module containing classes for printing pre-formatted data to the CLI"""

from abc import ABC, abstractmethod
from typing import Optional, Union

from tabulate import tabulate
from termcolor import colored, cprint


from ioccheck.iocs import Hash, IP
from ioccheck.services import Twitter


class Printer(ABC):
    """Base class for creating an object that prints information to the CLI

    Attributes:
        heading_color: Color used by the heading text describing a piece of data.
        error_color: Color to be used for displaying back error messages.
    """

    heading_color = "blue"
    error_color = "red"

    def __init__(
        self, ioc, heading: Optional[str], attr: str, delim: str, error_text: str
    ):
        """
        Args:
            ioc: The


        """
        self.ioc = ioc

        self.heading = heading
        self.attr = attr
        self.delim = delim
        self.error_text = error_text

        self.text = self.make_text()

    @abstractmethod
    def make_text(self) -> Optional[str]:
        pass

    def print_text(self):
        if self.text is None or self.text == "":
            cprint(f"[!] {self.error_text}", self.error_color)
            return

        if self.heading is None:
            print(self.text)
        else:
            self.heading = f"[*] {self.heading}"
            print(
                f"\n{colored(self.heading, self.heading_color)}:{self.delim}{self.text}"
            )


class BehaviorPrinter(Printer):
    heading = "Sandbox behavior"
    attr = "behavior"
    delim = "\n"
    error_text = "No behavior data to display"

    def __init__(self, ioc: Hash):
        Printer.__init__(
            self, ioc, self.heading, self.attr, self.delim, self.error_text
        )

        self.ioc = ioc

    def make_text(self) -> Optional[str]:
        table = [["Vendor", "Behaviour", "Threat"]]

        for result in self.ioc.behavior:  # type: ignore
            if result.threat is None:
                continue

            if result.threat == 1:
                threat = colored("Neutral", "green")
            elif result.threat == 2:
                threat = colored("Suspicious", "yellow")
            elif result.threat == 3:
                threat = colored("Malicious", "red")

            table.append([result.vendor, result.behavior, threat])

        if len(table) == 1:
            return None

        return tabulate(table, tablefmt="fancy_grid")


class TagsPrinter(Printer):
    heading = "User-submitted tags"
    attr = "tags"
    delim = " "
    error_text = "No tags to display"

    def __init__(self, ioc: Union[Hash, IP]):
        Printer.__init__(
            self, ioc, self.heading, self.attr, self.delim, self.error_text
        )

    def make_text(self) -> Optional[str]:
        return ", ".join(self.ioc.tags)


class TwitterPrinter(Printer):
    heading = None
    attr = "tweets"
    delim = " "
    error_text = "No tweets about this IOC."
    service = Twitter

    def __init__(self, ioc: Union[Hash, IP]):
        Printer.__init__(
            self, ioc, self.heading, self.attr, self.delim, self.error_text
        )

    def make_text(self) -> Optional[str]:
        if not self.ioc.tweets:
            return None

        text = []
        for tweet in self.ioc.tweets:
            author = colored(f"\n[*] Tweet from: @{tweet.author}:", self.heading_color)
            url = colored(tweet.url, self.heading_color)
            text.append(f"{author} {tweet.text}\n{url}\n")
        return "".join(text)


class DetectionsPrinter(Printer):
    attr = "detections"
    delim = "\n"
    error_text = "No vendors detected this sample."
    heading = "Vendor detections"

    def __init__(self, ioc: Hash):
        Printer.__init__(
            self, ioc, self.heading, self.attr, self.delim, self.error_text
        )

    def make_text(self) -> Optional[str]:
        table = [["Vendor", "Detection"]]

        for detection, result in self.ioc.detections.items():
            if result.get("category") == "malicious":
                table.append([detection, colored(result.get("result"), "red")])

        return tabulate(table, headers="firstrow", tablefmt="fancy_grid")
