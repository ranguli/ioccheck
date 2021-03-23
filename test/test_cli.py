import logging

import pytest
from click.testing import CliRunner

from ioccheck.cli import run
from ioccheck.iocs.hash import invalid_hash_message

logger = logging.getLogger(__name__)
bad_ioc_inputs = [("12345"), ("asdf"), ("a1b2c3d4")]

bulk_inputs = []
with open("./test/testdata.txt", "r") as f:
    for line in f:
        bulk_inputs.append((line.strip("\n")))


class TestBadIOC:
    @pytest.mark.parametrize("ioc", bad_ioc_inputs)
    def test_bad_ioc_exit_code(self, ioc):
        runner = CliRunner()
        result = runner.invoke(run, [ioc])
        assert result.exit_code == 0

    @pytest.mark.parametrize("ioc", bad_ioc_inputs)
    def test_bad_ioc_stdout(self, ioc):
        runner = CliRunner()
        result = runner.invoke(run, [ioc])
        invalid_hash_message in result.output
