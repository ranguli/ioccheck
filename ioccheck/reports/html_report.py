#!/usr/bin/env python

from dataclasses import dataclass

import emoji
from jinja2 import FileSystemLoader, Environment

from ioccheck.iocs import IOC
from .report import Report


class HTMLReport(Report):
    warning_icon = emoji.emojize(":warning:")
    ok_icon = emoji.emojize(":check_mark_button:")
    clipboard_icon = emoji.emojize(":clipboard:")
    alert_icon = emoji.emojize(":police_car_light:")
    virus_icon = emoji.emojize(":microbe:")

    def __init__(self, ioc: IOC, templates_dir: str):
        Report.__init__(self, ioc, templates_dir)
        self.contents = dict(
            ioc=self.ioc,
            detections=self.detections,
            footer=self.footer,
            icons=Icons(
                warning=self.warning_icon,
                ok=self.ok_icon,
                clipboard=self.clipboard_icon,
                alert=self.alert_icon,
                virus=self.virus_icon,
            ),
            behaviour=self.behaviour,
            hashes=self.ioc.hashes,
            tags=self.ioc.tags,
            tag_colors=self.tag_colors,
            urls=self.ioc.urls,
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

            name = (
                result.get("result")
                if result.get("result") is not None
                else "Not detected"
            )

            detections.append(
                Detection(engine=detection, name=name, malicious=malicious)
            )
        return sorted(detections, key=lambda x: x.malicious, reverse=True)

    @property
    def behaviour(self):
        behaviours = []
        for behaviour in self.ioc.behaviour:
            behaviours.append(
                Behaviour(
                    sandbox=behaviour.get("service"),
                    description=behaviour.get("behaviour"),
                    threat=behaviour.get("threat"),
                )
            )
        return sorted(behaviours, key=lambda x: x.threat, reverse=True)

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


@dataclass
class Icons:
    warning: str
    ok: str
    clipboard: str
    alert: str
    virus: str


@dataclass
class Detection:
    engine: str
    name: str
    malicious: bool


@dataclass
class Behaviour:
    sandbox: str
    description: str
    threat: int
