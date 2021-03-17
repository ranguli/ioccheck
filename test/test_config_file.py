from configparser import ParsingError

import pytest

from hashcheck import Hash
from hashcheck.services import VirusTotal


class TestConfigFile:
    def test_config_file_1(self, sha256_test_hash_eicar):
        _hash = Hash(sha256_test_hash_eicar)
        _hash.check(services=VirusTotal, config_path="./test/hashcheck_bad_config_1.in")

    def test_config_file_2(self, sha256_test_hash_eicar):
        with pytest.raises(ParsingError):
            _hash = Hash(sha256_test_hash_eicar)
            _hash.check(
                services=VirusTotal, config_path="./test/hashcheck_bad_config_2.in"
            )

    def test_config_file_3(self, sha256_test_hash_eicar):
        with pytest.raises(FileNotFoundError):
            _hash = Hash(sha256_test_hash_eicar)
            _hash.check(services=VirusTotal, config_path="./i/dont/exist.in")
