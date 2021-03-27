#!/usr/bin/env python

from pathlib import Path
from typing import Optional

import emoji
from jinja2 import FileSystemLoader, Environment

from ioccheck.iocs import IOC
from .report import Report

class HTMLReport(Report):
    def __init__(self, ioc: IOC):
        Report.__init__(self, ioc)
        self.contents = dict(detections=self.detections)

    def generate(self, output_file: str):
        template_loader = FileSystemLoader(searchpath=Path.cwd())
        template_env = Environment(loader=template_loader, autoescape=True)
        template = template_env.get_template(self.template_file)
        report_contents = template.render(**self.contents)

        with open(output_file, "w+") as f:
            f.write(report_contents)

    @property
    def detections(self):
        return self.ioc.detections

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
