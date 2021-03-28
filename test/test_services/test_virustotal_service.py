from unittest.mock import Mock, patch

import pytest
import vt

from ioccheck.iocs import Hash
from ioccheck.services import VirusTotal


class TestVirusTotal:
    def test_success(self, virustotal_report_1):
        assert virustotal_report_1

    def test_reports_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports

    def test_virustotal_reports_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports.virustotal

    def test_virustotal_detections_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports.virustotal.detections

    def test_virustotal_detections_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports.virustotal.detections

    def test_virustotal_relationships_exists(self, virustotal_report_1):
        assert not virustotal_report_1.reports.virustotal.relationships

    def test_virustotal_tags_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports.virustotal.tags


class TestVirusTotalAPIError:
    def test_virustotal_error_detections(self, virustotal_bad_response_1):
        assert virustotal_bad_response_1.reports.virustotal.detections is None

    def test_virustotal_error_detection_coverage(self, virustotal_bad_response_1):
        assert virustotal_bad_response_1.reports.virustotal.detections is None

    def test_virustotal_error_reputation(self, virustotal_bad_response_1):
        assert virustotal_bad_response_1.reports.virustotal.reputation is None

    def test_virustotal_error_popular_relationships(self, virustotal_bad_response_1):
        assert virustotal_bad_response_1.reports.virustotal.relationships is None

    def test_virustotal_error_tags(self, virustotal_bad_response_1):
        assert virustotal_bad_response_1.reports.virustotal.tags is None
