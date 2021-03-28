from configparser import ParsingError

import pytest

from ioccheck.iocs import Hash, IP


class TestConfigFile:
    def test_config_file_not_exists(self, hash_1):
        with pytest.raises(FileNotFoundError):
            ioc = Hash(hash_1, config_path="idontexist.in")

    def test_config_file_1(self, hash_1):
        ioc = Hash(hash_1, config_path="./test/data/ioccheck_bad_config_1.in")

    def test_config_file_2(self, hash_1):
        ioc = Hash(hash_1, config_path="./test/data/ioccheck_bad_config_2.in")

    def test_config_file_3(self, hash_1):
        ioc = Hash(hash_1, config_path="./test/data/ioccheck_bad_config_3.in")

    def test_config_file_4(self):
        ioc = IP("8.8.8.8", config_path="./test/data/ioccheck_bad_config_4.in")
