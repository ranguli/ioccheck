from dataclasses import dataclass
import vt


@dataclass
class ServiceReport:
    name: str
    investigation_url: str
    is_malicious: bool


@dataclass
class VirusTotalReport(ServiceReport):
    api_response: vt.Client
    detections: dict
