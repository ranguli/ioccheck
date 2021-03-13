from hashcheck import Hash, SHA256, MD5
from hashcheck.exceptions import InvalidHashException
from hashcheck.services import VirusTotal

from tests.fixtures import sha256_test_hash_1, md5_test_hash_1
import pytest

@pytest.mark.parametrize("file_hash,hash_type", [
    ("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03", SHA256),
    ("b1946ac92492d2347c6235b4d2611184", MD5),
])

def test_hash_creation_implicit(file_hash, hash_type):
    """ Test that the Hash() object will correctly guess the kind of hash """
    _hash = Hash(file_hash)

    assert _hash.hash_type == hash_type

def test_sha256_hash_is_operator(sha256_test_hash_1):
    """ Test that the "is" operator works against a SHA-256 hash """
    _hash = Hash(sha256_test_hash_1)

    assert _hash.hash_type is SHA256

def test_md5_hash_is_operator(md5_test_hash_1):
    # Test that the "is" operator works against a MD5 hash """
    _hash = Hash(md5_test_hash_1)

    assert _hash.hash_type is MD5

def test_sha256_hash_all_services(sha256_test_hash_1):
    _hash = Hash(sha256_test_hash_1)
    _hash.check()

def test_sha256_hash_vt_service(sha256_test_hash_1):
    _hash = Hash(sha256_test_hash_1)
    _hash.check(services=VirusTotal)

