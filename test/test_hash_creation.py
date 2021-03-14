import pytest

from hashcheck import Hash, SHA256, MD5
from hashcheck.exceptions import InvalidHashException


class TestHashCreation:
    """ Instantiating Hash() objects """

    class TestHashCreationEICAR:
        def test_hashcheck_eicar_sha256_implicit(self, hashcheck_eicar_sha256_implicit):
            """ Hashcheck correctly guesses a SHA256"""
            assert hashcheck_eicar_sha256_implicit.type == SHA256

        def test_hashcheck_eicar_sha256_explicit(self, hashcheck_eicar_sha256_explicit):
            """ Hashcheck explicitly accepts a SHA256"""
            assert hashcheck_eicar_sha256_explicit.type == SHA256

        def test_hashcheck_eicar_md5_implicit(self, hashcheck_eicar_md5_implicit):
            """ Hashcheck correctly guesses an MD5"""
            assert hashcheck_eicar_md5_implicit.type == MD5

        def test_hashcheck_eicar_md5_explicit(self, hashcheck_eicar_md5_explicit):
            """ Hashcheck correctly guesses an MD5"""
            assert hashcheck_eicar_md5_explicit.type == MD5

    class TestHashCreationClean:
        def test_hashcheck_clean_sha256_implicit(self, hashcheck_clean_sha256_implicit):
            """ Hashcheck correctly guesses a SHA256"""
            assert hashcheck_clean_sha256_implicit.type == SHA256

        def test_hashcheck_clean_sha256_explicit(self, hashcheck_clean_sha256_explicit):
            """ Hashcheck explicitly accepts a SHA256"""
            assert hashcheck_clean_sha256_explicit.type == SHA256

        def test_hashcheck_clean_md5_implicit(self, hashcheck_clean_md5_implicit):
            """ Hashcheck correctly guesses an MD5"""
            assert hashcheck_clean_md5_implicit.type == MD5

        def test_hashcheck_clean_md5_explicit(self, hashcheck_clean_md5_explicit):
            """ Hashcheck correctly guesses an MD5"""
            assert hashcheck_clean_md5_explicit.type == MD5

    class TestHashCreationMismatches:
        def test_hashcheck_mismatch_not_sha256(self, sha256_test_hash_eicar):
            """ Hashcheck supplied with SHA256 but type of MD5 should raise """
            with pytest.raises(InvalidHashException):
                Hash(sha256_test_hash_eicar, MD5)

        def test_hashcheck_mismatch_not_md5(self, md5_test_hash_eicar):
            """ Hashcheck supplied with MD5 but type of SHA256 should raise """
            with pytest.raises(InvalidHashException):
                Hash(md5_test_hash_eicar, SHA256)

    class TestHashCreationTypeErrors:
        def test_hashcheck_int(self):
            """ Hashcheck supplied with a non-string for the hash should raise exception"""
            with pytest.raises(InvalidHashException):
                Hash(1, MD5)

        def test_hashcheck_none(self):
            """ Hashcheck supplied with a non-string for the hash should raise exception """
            with pytest.raises(InvalidHashException):
                Hash(None, MD5)
