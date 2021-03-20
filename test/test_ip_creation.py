import pytest

from ioccheck.exceptions import InvalidIPException
from ioccheck.iocs import IP


class TestIPCreation:
    """ Instantiating IP() objects """

    class TestInvalidIPExceptions:
        @pytest.mark.parametrize(
            "ip_addr",
            [
                ("12345"),
                (""),
                (1),
                (None),
                ([]),
                ({}),
                ("abc"),
                ("127.0.0.1"),
                ("::1"),
                ("0.0.0.0"),
                ("192.168.0.0"),
                ("172.16.0.0"),
                ("10.0.0.0"),
            ],
        )
        def test_invalid_ip_exception(self, ip_addr):
            with pytest.raises(InvalidIPException):
                IP(ip_addr)
