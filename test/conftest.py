import json
from unittest.mock import patch

import pytest
import shodan
import vt

from ioccheck import exceptions
from ioccheck.ioc_types import MD5, SHA256
from ioccheck.iocs import IP, Hash
from ioccheck.services import MalwareBazaar, Shodan, VirusTotal


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
    with open("test/data/virustotal_mock_response_1.json", "r") as f:
        return json.load(f)


@pytest.fixture
def malwarebazaar_mocked_response_1():
    with open("test/data/malwarebazaar_mock_response_1.json", "r") as f:
        return json.load(f)


@pytest.fixture
def malwarebazaar_mocked_response_2():
    with open("test/data/malwarebazaar_mock_response_2.json", "r") as f:
        return json.load(f)


@pytest.fixture
def shodan_mocked_response_1():
    with open("test/data/shodan_mock_response_1.json", "r") as f:
        return json.load(f)


@pytest.fixture
def virustotal_bad_response_1(virustotal_mocked_response_1, hash_1, config_file):
    with patch.object(
        VirusTotal, "_get_api_response", return_value=None
    ) as mock_method:

        mock_api_response = virustotal_mocked_response_1
        sample = Hash(hash_1, config_path=config_file)

        sample.check(services=[VirusTotal])
        return sample


@pytest.fixture
def virustotal_report_1(virustotal_mocked_response_1, hash_1, config_file):
    """ VirusTotal report generated from virustotal_mocked_response_1 """
    with patch.object(
        VirusTotal, "_get_api_response", return_value=virustotal_mocked_response_1
    ) as mock_method:
        mock_api_response = virustotal_mocked_response_1
        sample = Hash(hash_1, config_path=config_file)

        sample.check(services=[VirusTotal])

        return sample


@pytest.fixture
def malwarebazaar_report_1(malwarebazaar_mocked_response_1, hash_1, config_file):
    """ MalwareBazaar report generated from malware_mocked_response_1 """
    with patch.object(
        MalwareBazaar, "_get_api_response", return_value=malwarebazaar_mocked_response_1
    ) as mock_method:
        mock_api_response = malwarebazaar_mocked_response_1
        sample = Hash(hash_1, config_path=config_file)

        sample.check(services=[MalwareBazaar])

        return sample


@pytest.fixture
def shodan_report_1(shodan_mocked_response_1, config_file):
    """ Shodan report generated from shodan_mocked_response_1 """
    with patch.object(
        Shodan, "_get_api_response", return_value=shodan_mocked_response_1
    ) as mock_method:
        mock_api_response = shodan_mocked_response_1
        sample = IP("45.33.49.119", config_path=config_file)

        sample.check(services=[Shodan])

        return sample


@pytest.fixture
def shodan_report_1(shodan_mocked_response_1, config_file):
    """ Shodan report generated from shodan_mocked_response_1 """
    with patch.object(
        Shodan, "_get_api_response", return_value=shodan_mocked_response_1
    ) as mock_method:
        mock_api_response = shodan_mocked_response_1
        sample = IP("45.33.49.119", config_path=config_file)

        sample.check(services=[Shodan])

        return sample


@pytest.fixture
def shodan_bad_response_1(shodan_mocked_response_1, config_file):
    """ Shodan report simulating a shodan.error.APIError"""

    def side_effect(*args):
        raise shodan.exception.APIError("")

    with patch.object(
        shodan.client.Shodan, "host", return_value=None, side_effect=side_effect
    ) as mock_method:

        mock_api_response = shodan_mocked_response_1
        sample = IP("45.33.49.119", config_path=config_file)

        return sample


@pytest.fixture
def config_file():
    return "test/data/config"
