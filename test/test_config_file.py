from configparser import ParsingError

import pytest

from ioccheck.iocs import IP, Hash


class TestConfigFile:
    def test_config_file_not_exists(self, hash_1):
        with pytest.raises(FileNotFoundError):
            ioc = Hash(hash_1, config_path="idontexist.in")

    def test_config_file_1(self, hash_1, config_file):
        ioc = Hash(hash_1, config_path=config_file)

    def test_config_file_2(self, hash_1, config_file):
        ioc = Hash(hash_1, config_path=config_file)

    def test_config_file_3(self, hash_1, config_file):
        ioc = Hash(hash_1, config_path=config_file)

    def test_config_file_4(self, config_file):
        ioc = IP("8.8.8.8", config_path=config_file)
