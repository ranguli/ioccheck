import logging

import pytest
from click.testing import CliRunner

from hashcheck import invalid_hash_message
from hashcheck.cli import run


logger = logging.getLogger(__name__)
bad_hash_inputs = [("12345"), ("asdf")]

bulk_inputs = []
with open("./test/testdata.txt", "r") as f:
    for line in f:
        bulk_inputs.append((line.strip("\n")))


class TestBadHash:
    @pytest.mark.parametrize("file_hash", bad_hash_inputs)
    def test_bad_hash_exit_code(self, file_hash):
        runner = CliRunner()
        result = runner.invoke(run, [file_hash])
        assert result.exit_code == 1

    @pytest.mark.parametrize("file_hash", bad_hash_inputs)
    def test_bad_hash_stdout(self, file_hash):
        runner = CliRunner()
        result = runner.invoke(run, [file_hash])
        invalid_hash_message in result.output


class TestBulkInputs:
    @pytest.mark.secret
    @pytest.mark.parametrize("file_hash", bulk_inputs)
    def test_bad_hash_stdout(self, file_hash):
        logger.info(f"Testing input {file_hash}")
        runner = CliRunner()
        result = runner.invoke(run, [file_hash])
        assert result.exit_code == 0
