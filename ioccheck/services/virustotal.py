#!/usr/bin/env python
""" Represents response from the VirusTotal API """

import logging
from typing import Optional, List

from backoff import expo, on_exception
from ratelimit import RateLimitException, limits
import vt

from ioccheck.services.service import Service

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


class VirusTotal(Service):
    """ Represents response from the VirusTotal API """

    name = "virustotal"
    url = "https://virustotal.com"

    def __init__(self, ioc, api_key):
        self.ioc = ioc

        try:
            self.response = self._get_api_response(self.ioc, api_key)
        except (vt.error.APIError, AttributeError):
            return

    @on_exception(expo, RateLimitException, max_tries=10, max_time=60)
    @limits(calls=4, period=60)
    def _get_api_response(self, ioc: str, api_key: str) -> dict:
        client = vt.Client(api_key)
        result = client.get_object(f"/files/{ioc}")
        return result.to_dict().get("attributes")

    @property
    def investigation_url(self) -> Optional[str]:
        return self._investigation_url

    @investigation_url.setter
    def investigation_url(self):
        self._investigation_url = f"{self.url}/gui/file/{self.ioc}/"

    @property
    def detections(self) -> Optional[dict]:
        """The anti-virus providers that detected the hash"""
        return self._detections

    @detections.setter
    def detections(self):
        self._detections = self.response.get("last_analysis_results")

    @property
    def detection_coverage(self) -> float:
        """The number of A.V providers detecting the sample divided by total providers."""

        return self._detection_coverage

    @detection_coverage.setter
    def detection_coverage(self):
        if len(self.detections.keys()) == 0:
            self._detection_coverage = 0
        else:
            self._detection_coverage = self.detection_count(self.detections) / len(
                self.detections.keys()
            )

    @property
    def detection_count(self) -> int:
        """The number of anti-virus providers available from VirusTotal"""
        return self._detection_count

    @detection_count.setter
    def detection_count(self):
        self._detection_count = len(
            [k for k, v in self.detections.items() if v.get("category") == "malicious"]
        )

    @property
    def reputation(self) -> dict:
        """VirusTotal community score for a given entry"""
        return self._reputation

    @reputation.setter
    def reputation(self):
        self._reputation = self.response.get("reputation")

    @property
    def popular_threat_names(self) -> Optional[List[str]]:
        """Human-friendly names that classify a hash as belong to a particular threat"""
        return self._popular_threat_names

    @popular_threat_names.setter
    def popular_threat_names(self):
        try:
            names = self.response.get(
                "popular_threat_classification"
            ).get(  # type: ignore
                "popular_threat_name"
            )
        except AttributeError:
            return

        self._popular_threat_names = [name[0] for name in names] if names else None

    @property
    def relationships(self) -> Optional[dict]:
        """Describes how the hash interacts with IPs, domains, etc"""
        return self._relationships

    @relationships.setter
    def relationships(self):
        self._relationships = self.response.get("relationships")

    @property
    def tags(self):
        """User-provided tags to classify samples"""
        return self._tags

    @tags.setter
    def tags(self):
        try:
            result = self.response.get("tags") if self.response.get("tags") else None
        except AttributeError:
            return
        self._tags = result
