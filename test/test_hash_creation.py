import pytest

from ioccheck.exceptions import InvalidHashException
from ioccheck.ioc_types import MD5, SHA256
from ioccheck.iocs import Hash
from ioccheck.services import MalwareBazaar, VirusTotal


class TestHashCreation:
    """ Instantiating Hash() objects """

    class TestHashGuesses:
        def test_sha256_guess(self, hash_1, config_file):
            assert Hash(hash_1, config_path=config_file).hash_type == SHA256

        def test_sha256_guess_2(self, hash_1, config_file):
            assert (
                Hash(hash_1, hash_type=SHA256, config_path=config_file).hash_type
                == SHA256
            )

        def test_sha256_guess_3(self, hash_2, config_file):
            with pytest.raises(InvalidHashException):
                assert Hash(hash_2, hash_type=SHA256, config_path=config_file)

        def test_md5_guess(self, hash_2, config_file):
            assert Hash(hash_2, config_path=config_file).hash_type == MD5

        def test_md5_guess_2(self, hash_2, config_file):
            assert Hash(hash_2, hash_type=MD5, config_path=config_file).hash_type == MD5

        def test_md5_guess_3(self, hash_1, config_file):
            with pytest.raises(InvalidHashException):
                assert Hash(hash_1, hash_type=MD5, config_path=config_file)

    class TestInvalidHashExceptions:
        @pytest.mark.parametrize(
            "file_hash,hash_type",
            [
                ("12345", MD5),
                ("12345", SHA256),
                ("", MD5),
                ("", SHA256),
                (1, SHA256),
                (1, MD5),
                (1, None),
                (None, SHA256),
                (None, MD5),
                (SHA256, None),
                (SHA256, ""),
                (MD5, None),
                ([], SHA256),
                ([], MD5),
                ([], None),
                ({}, None),
                ("abc", None),
                ("abc", MD5),
                ("abc", SHA256),
            ],
        )
        def test_invalid_hash_exception(self, file_hash, hash_type, config_file):
            with pytest.raises(InvalidHashException):
                Hash(file_hash, hash_type, config_path=config_file)
