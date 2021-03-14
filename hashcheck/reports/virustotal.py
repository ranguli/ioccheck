class VirusTotalReport:
    def __init__(
        self,
        name,
        investigation_url,
        is_malicious,
        api_response,
        detections,
        reputation,
    ):
        self.name = name
        self.investigation_url = investigation_url
        self.is_malicious_url = is_malicious

        self.api_response = api_response
        self.detections = detections
        self.detection_count = self._get_detection_count(self.detections)
        self.detection_coverage = self._get_detection_coverage(self.detections)
        self.reputation = reputation

        # self.logger.info(f"name: {name} investigation_url: {investigation_url} is_malicious: {is_malicious}")

    def _get_detection_count(self, detections):
        return len(
            [k for k, v in detections.items() if v.get("category") == "malicious"]
        )

    def _get_detection_coverage(self, detections):
        return self._get_detection_count(detections) / len(detections.keys())

    def get_detections(self, engines=None):
        if engines == "all":
            return self.detections
        if isinstance(engines, list):
            return dict(
                (key, value) for key, value in self.detections.items() if key in engines
            )
        elif engines is None:
            engines = [
                "Avast",
                "AVG",
                "BitDefender",
                "ClamAV",
                "FireEye",
                "Fortinet",
                "Kaspersky",
                "Malwarebytes",
                "McAfee",
                "Microsoft",
                "Paloalto",
                "Sophos",
                "Symanetc",
                "TrendMicro",
            ]
            return dict(
                (key, value) for key, value in self.detections.items() if key in engines
            )
        else:
            raise TypeError
