#!/usr/bin/env python

from pathlib import Path
from typing import Optional

from dataclasses import dataclass

import emoji
from jinja2 import FileSystemLoader, Environment

from ioccheck.iocs import IOC
from .report import Report

class HTMLReport(Report):
    warning_icon = emoji.emojize(':warning:')
    ok_icon = emoji.emojize(':check_mark_button:')
    clipboard_icon = emoji.emojize(':clipboard:')

    def __init__(self, ioc: IOC, templates_dir: str):
        Report.__init__(self, ioc, templates_dir)
        self.contents = dict(
                detections=self.detections,
                footer=self.footer,
                icons=Icons(
                    warning=self.warning_icon,
                    ok=self.ok_icon,
                    clipboard=self.clipboard_icon
                ),
                hashes=self.ioc.hashes
        )

    def generate(self, output_file: str):
        template_loader = FileSystemLoader(searchpath=self.templates_dir)
        template_env = Environment(loader=template_loader, autoescape=True)
        template = template_env.get_template(self.template_file)
        report_contents = template.render(**self.contents)

        with open(output_file, "w+") as f:
            f.write(report_contents)

    @property
    def detections(self):
        detections = []
        for detection, result in self.ioc.detections.items():
            malicious = False
            if result.get("category") == "malicious":
                malicious = True

            name = result.get("result") if result.get("result") is not None else "Not detected"

            detections.append(Detection(engine=detection, name=name, malicious=malicious))
        return detections


@dataclass
class Icons:
    warning: str
    ok: str
    clipboard: str

@dataclass
class Detection:
    engine: str
    name: str
    malicious: bool



"""

TEMPLATE_FILE = "template.html"



items = []
for i in range(1, 11):
    i = str(i)

    warning = emoji.emojize(':warning:')

    an_item = dict(threat=warning, date="2012-02-" + i, id=i, position="here", status="waiting")
    items.append(an_item)

output_text = template.render(my_list=["foo", "bar", "baz"], items=items)  # this is where to put args to the template renderer
"""
