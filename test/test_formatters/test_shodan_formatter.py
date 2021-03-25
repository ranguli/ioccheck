import pytest

from ioccheck.cli.formatters import ShodanFormatter


@pytest.fixture
def shodan_formatter(shodan_report_1):
    return ShodanFormatter(shodan_report_1.reports.shodan)


class TestShodanFormatter:
    def test_exists(self, shodan_formatter):
        assert shodan_formatter

    def test_tags(self, shodan_formatter):
        assert shodan_formatter.tags == "cloud"
