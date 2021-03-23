import json
from unittest.mock import patch

import pytest

from ioccheck.iocs import Hash
from ioccheck.services import MalwareBazaar, VirusTotal
from ioccheck.ioc_types import MD5, SHA256


@pytest.fixture
def hash_1():
    """ Test hash 1"""
    return "73bef2ac39be261ae9a06076302c1d0af982e0560e88ac168980fab6ea5dd9c4"


@pytest.fixture
def hash_2():
    """ Test hash 2 """
    return "9afab28587926ce230e2e4430becc599"


@pytest.fixture
def virustotal_mocked_response_1():
    """ Mock VirusTotal API response for hash_1 """
    with open("test/data/virustotal_mock_response.json", "r") as f:
        return json.load(f)


@pytest.fixture
def malwarebazaar_mocked_response_1():
    with open("test/data/malwarebazaar_mock_response.json", "r") as f:
        return json.load(f)


@pytest.fixture
def virustotal_report_1(virustotal_mocked_response_1, hash_1):
    """ VirusTotal report generated from virustotal_mocked_response_1 """
    with patch.object(
        VirusTotal, "_get_api_response", return_value=virustotal_mocked_response_1
    ) as mock_method:
        mock_api_response = virustotal_mocked_response_1
        sample = Hash(hash_1)

        sample.check(services=[VirusTotal])

        return sample
