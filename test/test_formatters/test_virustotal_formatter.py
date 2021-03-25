import pytest

from ioccheck.cli.formatters import VirusTotalFormatter


@pytest.fixture
def virustotal_formatter(virustotal_report_1):
    return VirusTotalFormatter(virustotal_report_1.reports.virustotal)


class TestVirusTotalFormatter:
    def test_exists(self, virustotal_formatter):
        assert virustotal_formatter

    def test_tags(self, virustotal_formatter):
        assert (
            virustotal_formatter.tags
            == "malware, overlay, runtime-modules, peexe, nsis, direct-cpu-clock-access"
        )

    def test_reputation(self, virustotal_formatter):
        assert virustotal_formatter.reputation == "\x1b[33m0\x1b[0m"

    def test_detection_count(self, virustotal_formatter):
        assert (
            virustotal_formatter.detection_count
            == "\x1b[32m0 engines (0%) detected this file.\n\x1b[0m"
        )
