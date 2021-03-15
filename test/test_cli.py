import pytest
from click.testing import CliRunner

from hashcheck.cli import run
from hashcheck import invalid_hash_message

bad_hash_inputs = [("12345"), ("asdf")]


class TestBadHash:
    @pytest.mark.parametrize("file_hash", bad_hash_inputs)
    def test_bad_hash_exit_code(self, file_hash):
        runner = CliRunner()
        result = runner.invoke(run, [file_hash])
        assert result.exit_code == 0

    @pytest.mark.parametrize("file_hash", bad_hash_inputs)
    def test_bad_hash_stdout(self, file_hash):
        runner = CliRunner()
        result = runner.invoke(run, [file_hash])
        invalid_hash_message in result.output
