from configparser import ParsingError

import pytest

from ioccheck.iocs import Hash
from ioccheck.services import VirusTotal


class TestConfigFile:
    def test_config_file_3(self, hash_1):
        with pytest.raises(FileNotFoundError):
            ioc = Hash(hash_1, config_path="./i/dont/exist.in")
