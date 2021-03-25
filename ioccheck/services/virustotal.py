#!/usr/bin/env python
""" Represents response from the VirusTotal API """

from typing import List, Optional

import vt
from backoff import expo, on_exception
from ratelimit import RateLimitException, limits

from ioccheck.services.service import Service


class VirusTotal(Service):
    """ Represents response from the VirusTotal API """

    name = "virustotal"
    url = "https://virustotal.com"

    def __init__(self, ioc, api_key):
        Service.__init__(self, ioc, api_key)

        try:
            self.response = self._get_api_response(self.ioc, api_key)
        except (vt.error.APIError, AttributeError):
            return

    @on_exception(expo, RateLimitException, max_tries=10, max_time=60)
    @limits(calls=4, period=60)
    def _get_api_response(self, ioc: str, api_key: str) -> Optional[dict]:
        client = vt.Client(api_key)
        result = client.get_object(f"/files/{ioc}")

        try:
            return result.to_dict().get("attributes")
        except AttributeError:
            return None

    @property
    def investigation_url(self) -> Optional[str]:
        """ The URL a human can use to follow up for more information """
        return f"{self.url}/gui/file/{self.ioc}/"

    @property
    def detections(self) -> Optional[dict]:
        """The anti-virus providers that detected the hash"""
        try:
            return self.response.get("last_analysis_results")
        except AttributeError:
            return None

    @property
    def detection_coverage(self) -> Optional[float]:
        """The number of A.V providers detecting the sample divided by total providers."""
        if (
            not isinstance(self.detections, dict)
            or self.detections is None
            or not isinstance(self.detection_count, int)
        ):
            return None

        if len(self.detections.keys()) == 0:
            return 0

        return self.detection_count / len(self.detections.keys())

    @property
    def detection_count(self) -> Optional[int]:
        """The number of anti-virus providers available from VirusTotal"""
        if not isinstance(self.detections, dict) or self.detections is None:
            return None

        return len(
            [k for k, v in self.detections.items() if v.get("category") == "malicious"]
        )

    @property
    def reputation(self) -> Optional[int]:
        """VirusTotal community score for a given entry"""
        try:
            return self.response.get("reputation")
        except AttributeError:
            return None

    @property
    def popular_threat_names(self) -> Optional[List[str]]:
        """Human-friendly names that classify a hash as belong to a particular threat"""
        try:
            names = self.response.get(
                "popular_threat_classification"
            ).get(  # type: ignore
                "popular_threat_name"
            )
        except AttributeError:
            return None

        return [name[0] for name in names] if names else None

    @property
    def relationships(self) -> Optional[dict]:
        """Describes how the hash interacts with IPs, domains, etc"""
        try:
            return self.response.get("relationships")
        except AttributeError:
            return None

    @property
    def tags(self) -> Optional[dict]:
        """User-provided tags to classify samples"""
        try:
            return self.response.get("tags") if self.response.get("tags") else None
        except AttributeError:
            return None
