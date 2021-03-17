import pytest
from hashcheck import Hash
from hashcheck.types import SHA256, MD5
from hashcheck.services import VirusTotal, MalwareBazaar


@pytest.fixture
def sha256_test_hash_clean():
    """ Known good SHA-256 hash (of /bin/bash) to test against """
    return "04a484f27a4b485b28451923605d9b528453d6c098a5a5112bec859fb5f2eea9"


@pytest.fixture
def md5_test_hash_clean():
    """ Known good SHA-256 hash (of /bin/bash) to test against """
    return "7063c3930affe123baecd3b340f1ad2c"


@pytest.fixture(scope="module")
def sha256_test_hash_eicar():
    """ EICAR SHA256 hash """
    return "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture(scope="module")
def sha256_test_hash_emotet():
    """ Emotet sample """
    return "526866190c8081698169b4be19a6b987d494604343fe874475126527841c83a7"


@pytest.fixture
def md5_test_hash_eicar():
    """ EICAR MD5 hash """
    return "44d88612fea8a8f36de82e1278abb02f"


@pytest.fixture
def hashcheck_eicar_sha256_implicit(sha256_test_hash_eicar):
    _hash = Hash(sha256_test_hash_eicar)
    return _hash


@pytest.fixture
def hashcheck_eicar_sha256_explicit(sha256_test_hash_eicar):
    _hash = Hash(sha256_test_hash_eicar, SHA256)
    return _hash


@pytest.fixture
def hashcheck_eicar_md5_implicit(md5_test_hash_eicar):
    _hash = Hash(md5_test_hash_eicar)
    return _hash


@pytest.fixture
def hashcheck_eicar_md5_explicit(md5_test_hash_eicar):
    _hash = Hash(md5_test_hash_eicar, MD5)
    return _hash


@pytest.fixture
def hashcheck_clean_sha256_implicit(sha256_test_hash_clean):
    _hash = Hash(sha256_test_hash_clean)
    return _hash


@pytest.fixture
def hashcheck_clean_sha256_explicit(sha256_test_hash_clean):
    _hash = Hash(sha256_test_hash_clean, SHA256)
    return _hash


@pytest.fixture
def hashcheck_clean_md5_implicit(md5_test_hash_clean):
    _hash = Hash(md5_test_hash_clean)
    return _hash


@pytest.fixture
def hashcheck_clean_md5_explicit(md5_test_hash_clean):
    _hash = Hash(md5_test_hash_clean, MD5)
    return _hash


@pytest.fixture
def hashcheck_eicar_report_all(sha256_test_hash_eicar):
    _hash = Hash(sha256_test_hash_eicar, SHA256)
    _hash.check()

    return _hash


@pytest.fixture
def hashcheck_eicar_report_virus_total(sha256_test_hash_eicar):
    _hash = Hash(sha256_test_hash_eicar, SHA256)
    _hash.check(services=VirusTotal)

    return _hash


@pytest.fixture
def hashcheck_emotet_report_malwarebazaar(sha256_test_hash_emotet):
    _hash = Hash(sha256_test_hash_emotet, SHA256)
    _hash.check(services=MalwareBazaar)

    return _hash
