import pytest

from ioccheck.exceptions import APIError
from ioccheck.iocs import IP
from ioccheck.services import Shodan


class TestShodan:
    def test_success(self, shodan_report_1):
        assert shodan_report_1

    def test_tags(self, shodan_report_1):
        assert shodan_report_1.reports.shodan.tags == ["cloud"]

    def test_hostname(self, shodan_report_1):
        assert shodan_report_1.reports.shodan.hostnames == ["ack.nmap.org"]

    def test_location(self, shodan_report_1):
        assert shodan_report_1.reports.shodan.location == {
            "area_code": None,
            "asn": "AS63949",
            "city": "Fremont",
            "country_code": "US",
            "country_name": "United States",
            "isp": "Linode, LLC",
            "org": "Linode",
            "postal_code": None,
            "region_code": "CA",
        }

    def test_vulns(self, shodan_report_1):
        assert shodan_report_1.reports.shodan.vulns == [
            "CVE-2014-0117",
            "CVE-2014-0118",
            "CVE-2016-0736",
            "CVE-2015-3185",
            "CVE-2015-3184",
            "CVE-2018-1312",
            "CVE-2016-4975",
            "CVE-2016-8612",
            "CVE-2014-0226",
            "CVE-2014-3523",
            "CVE-2017-15710",
            "CVE-2017-15715",
            "CVE-2013-6438",
            "CVE-2017-7679",
            "CVE-2018-17199",
            "CVE-2017-9788",
            "CVE-2014-8109",
            "CVE-2017-9798",
            "CVE-2016-2161",
            "CVE-2014-0231",
            "CVE-2013-4352",
            "CVE-2019-0220",
            "CVE-2014-0098",
            "CVE-2018-1283",
            "CVE-2016-8743",
        ]

    def test_api_error(self, shodan_bad_response_1):
        with pytest.raises(APIError):
            shodan_bad_response_1.check()
