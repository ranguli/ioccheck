#!/usr/bin/env python
"""Provides HTML report generation"""

from ioccheck.iocs import IOC
from ioccheck.shared import Behavior, Detection

from .report import Report


class HTMLIPReport(Report):
    """HTML report for an IP IOC"""

    def __init__(self, ioc: IOC, templates_dir: str):
        Report.__init__(self, ioc, templates_dir)

        self.contents.update(
            {
                "tweets": self.ioc.tweets,
            }
        )


class HTMLHashReport(Report):
    """HTML report for a hash IOC"""

    def __init__(self, ioc: IOC, templates_dir: str):
        Report.__init__(self, ioc, templates_dir)

        self.contents.update(
            {
                "detections": self.detections,
                "footer": self.footer,
                "behavior": self.behavior,
                "hashes": self.ioc.hashes,  # type: ignore
                "tags": self.ioc.tags,
                "tag_colors": self.tag_colors,
                "urls": self.ioc.urls,
                "tweets": self.ioc.tweets,
            }
        )

    @property
    def detections(self):
        """Detections with specific formatting applied for HTML reports"""
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
    def behavior(self):
        """Behaviors with specific formatting applied for HTML reports"""
        behaviors = []
        for behavior in self.ioc.behavior:
            behaviors.append(
                Behavior(
                    sandbox=behavior.get("service"),
                    description=behavior.get("behavior"),
                    threat=behavior.get("threat"),
                )
            )
        return sorted(behaviors, key=lambda x: x.threat, reverse=True)
