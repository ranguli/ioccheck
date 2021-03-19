import logging

import pytest
from click.testing import CliRunner

from hashcheck.hash import invalid_hash_message
from hashcheck.cli import run


logger = logging.getLogger(__name__)
bad_ioc_inputs = [("12345"), ("asdf")]

bulk_inputs = []
with open("./test/testdata.txt", "r") as f:
    for line in f:
        bulk_inputs.append((line.strip("\n")))


class TestBadIOC:
    @pytest.mark.parametrize("ioc", bad_ioc_inputs)
    def test_bad_ioc_exit_code(self, ioc):
        runner = CliRunner()
        result = runner.invoke(run, [ioc])
        assert result.exit_code == 1

    @pytest.mark.parametrize("ioc", bad_ioc_inputs)
    def test_bad_ioc_stdout(self, ioc):
        runner = CliRunner()
        result = runner.invoke(run, [ioc])
        invalid_hash_message in result.output


class TestBulkInputs:
    @pytest.mark.secret
    @pytest.mark.parametrize("file_hash", bulk_inputs)
    def test_bad_hash_stdout(self, file_hash):
        logger.info(f"Testing input {file_hash}")
        runner = CliRunner()
        result = runner.invoke(run, [file_hash])
        assert result.exit_code == 0
