import inspect
from unittest.mock import Mock, patch

import pytest
import vt

from ioccheck.exceptions import InvalidCredentialsError
from ioccheck.iocs import Hash
from ioccheck.services import VirusTotal


class TestVirusTotal:
    def test_success(self, virustotal_report_1):
        assert virustotal_report_1

    def test_reports_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports

    def test_reports_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports.virustotal

    def test_detections_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports.virustotal.detections

    def test_detections_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports.virustotal.detections

    def test_relationships_exists(self, virustotal_report_1):
        assert not virustotal_report_1.reports.virustotal.relationships

    def test_tags_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports.virustotal.tags

    def test_no_credential_error(self, hash_1, config_file):
        with patch("ioccheck.services.service.Credentials") as MockCredentials:
            instance = MockCredentials.return_value
            instance.api_key = None

            with pytest.raises(InvalidCredentialsError):
                sample = Hash(hash_1, config_path=config_file)
                sample.check(services=[VirusTotal])

    def test_empty_detections_attribute_error(self, hash_1, config_file):
        def side_effect(*args):
            raise AttributeError

        with patch.object(VirusTotal, "_get_api_response", side_effect=side_effect):
            sample = Hash(hash_1, config_path=config_file)

            with pytest.raises(AttributeError):
                sample.check(services=[VirusTotal])
                assert sample.detections is None
