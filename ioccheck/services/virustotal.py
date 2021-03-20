import logging

import vt
from backoff import expo, on_exception
from ratelimit import RateLimitException, limits

from ioccheck.services.service import Service

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


class VirusTotal(Service):
    name = "virustotal"

    def __init__(self, file_hash, api_key):
        self.client = vt.Client(api_key)
        self.url = "https://virustotal.com"

        try:
            self.response = self._get_api_response(file_hash)
        except vt.error.APIError:
            return

        self.investigation_url = self._make_investigation_url(self.url, file_hash)
        self.is_malicious = self._is_malicious(self.response)

        self.detections = self._get_detections(self.response)
        self.detection_coverage = self._get_detection_coverage(self.detections)
        self.detection_count = self._get_detection_count(self.detections)

        self.reputation = self._get_reputation(self.response)
        self.popular_threat_names = self._get_popular_threat_names(self.response)

        self.relationships = self._get_relationships(self.response)
        self.tags = self._get_tags(self.response)

    @on_exception(expo, RateLimitException, max_tries=10, max_time=80)
    @limits(calls=4, period=60)
    def _get_api_response(self, file_hash):
        result = self.client.get_object(f"/files/{file_hash}")
        return result

    def _make_investigation_url(self, url, file_hash):
        return f"{url}/gui/file/{file_hash}/"

    def _is_malicious(self, response):
        return

    def _get_detection_count(self, detections):
        return len(
            [k for k, v in detections.items() if v.get("category") == "malicious"]
        )

    def _get_detection_coverage(self, detections):
        if len(detections.keys()) == 0:
            return 0
        else:
            return self._get_detection_count(detections) / len(detections.keys())

    def _get_detections(self, response):
        return response.last_analysis_results

    def _get_detections_coverage(self, response):
        return response.last_analysis_results

    def _get_reputation(self, response):
        return response.reputation

    def _get_relationships(self, response):
        return response.relationships

    def _get_popular_threat_names(self, response):
        try:
            names = response.get("popular_threat_classification").get(
                "popular_threat_name"
            )
        except AttributeError:
            return None

        return [name[0] for name in names] if names else None

    def _get_tags(self, response):
        try:
            result = self.response.tags if self.response.tags else None
        except AttributeError:
            pass
        return result
