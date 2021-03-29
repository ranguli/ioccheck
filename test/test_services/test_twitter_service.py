from unittest.mock import Mock, patch

import pytest

from ioccheck.iocs import IP
from ioccheck.services import Twitter


class TestTwitter:
    def test_success(self):
        sample = IP("221.15.239.18")
        sample.check(services=[Twitter])
        assert sample
