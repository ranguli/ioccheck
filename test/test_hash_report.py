import pytest


@pytest.mark.usefixtures("virustotal_report_1")
class TestVirusTotalReport1:
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
        """ This response does not contain relationships """
        assert not virustotal_report_1.reports.virustotal.relationships

    def test_virustotal_popular_threat_names_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports.virustotal.popular_threat_names

    def test_virustotal_tags_exists(self, virustotal_report_1):
        assert virustotal_report_1.reports.virustotal.tags
