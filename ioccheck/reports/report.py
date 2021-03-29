#!/usr/bin/env python

import datetime
from abc import ABC
from dataclasses import dataclass

import pkg_resources
from emoji import emojize
from jinja2 import Environment, FileSystemLoader

from ioccheck.iocs import IOC


@dataclass
class Icons:
    warning: str
    ok: str
    clipboard: str
    alert: str
    virus: str
    link: str


class Report(ABC):

    icons = Icons(
        warning=emojize(":warning:"),
        ok=emojize(":check_mark_button"),
        clipboard=emojize(":clipboard:"),
        alert=emojize(":police_car_light:"),
        virus=emojize(":microbe:"),
        link=emojize(":link:"),
    )

    template_file = "template.html"

    def __init__(self, ioc: IOC, templates_dir):
        self.ioc = ioc
        self.templates_dir = templates_dir
        print(self.templates_dir)
        self.contents = {"ioc": self.ioc, "icons": self.icons}

    def _make_ordinal(self, number) -> str:
        # https://stackoverflow.com/a/50992575
        number = int(number)
        suffix = ["th", "st", "nd", "rd", "th"][min(number % 10, 4)]
        if 11 <= (number % 100) <= 13:
            suffix = "th"
        return str(number) + suffix

    def generate(self, output_file: str):
        template_loader = FileSystemLoader(searchpath=self.templates_dir)
        template_env = Environment(loader=template_loader, autoescape=True)
        template = template_env.get_template(self.template_file)
        report_contents = template.render(**self.contents)

        with open(output_file, "w+") as outfile:
            outfile.write(report_contents)

    @property
    def footer(self) -> str:
        today = datetime.datetime.today()
        day = self._make_ordinal(today.day)

        datestamp = f"{today.strftime('%A %B')} {day}, {today.year} at {today.strftime('%I:%M:%S %p')}"
        version = pkg_resources.get_distribution("ioccheck").version

        return f"Generated on {datestamp} by ioccheck v{version}"

    @property
    def tag_colors(self):
        return [
            "#264653",
            "#2A9D8F",
            "#E9C46A",
            "#F4A261",
            "#E76F51",
            "#3F88C5",
            "#A2AEBB",
            "#D00000",
            "#79ADDC",
        ]
