from configparser import ParsingError

import pytest

from ioccheck.iocs import Hash
from ioccheck.services import VirusTotal


class TestConfigFile:
    def test_config_file_1(self, hash_1):
        ioc = Hash(hash_1, config_path="./test/data/ioccheck_bad_config_1.in")
        ioc.check(services=VirusTotal)

    def test_config_file_2(self, hash_1):
        with pytest.raises(ParsingError):
            ioc = Hash(hash_1, config_path="./test/data/ioccheck_bad_config_2.in")

    def test_config_file_3(self, hash_1):
        with pytest.raises(FileNotFoundError):
            ioc = Hash(hash_1, config_path="./i/dont/exist.in")
