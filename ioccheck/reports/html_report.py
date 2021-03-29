#!/usr/bin/env python

from dataclasses import dataclass

from ioccheck.iocs import IOC

from .report import Report


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


class HTMLIPReport(Report):
    def __init__(self, ioc: IOC, templates_dir: str):
        Report.__init__(self, ioc, templates_dir)

        self.contents.update(
            {
                "tweets": self.ioc.tweets,
            }
        )

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


class HTMLHashReport(Report):
    def __init__(self, ioc: IOC, templates_dir: str):
        Report.__init__(self, ioc, templates_dir)

        self.contents.update(
            {
                "detections": self.detections,
                "footer": self.footer,
                "behaviour": self.behaviour,
                "hashes": self.ioc.hashes,  # type: ignore
                "tags": self.ioc.tags,
                "tag_colors": self.tag_colors,
                "urls": self.ioc.urls,
                "tweets": self.ioc.tweets,
            }
        )

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
