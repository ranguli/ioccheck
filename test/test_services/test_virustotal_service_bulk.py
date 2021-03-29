import glob
import inspect
import json
from unittest.mock import patch

import pytest

from ioccheck.iocs import Hash
from ioccheck.services import VirusTotal

test_inputs = []


for input_file in glob.glob("./test/data/virustotal_bulk_responses/*.json"):
    with open(input_file, "r") as f:
        test_inputs.append((json.load(f)))
    f.close()


def isprop(v):
    return isinstance(v, property)


@pytest.mark.parametrize("response", test_inputs)
def test_bulk_inputs(response, config_file):

    fake_hash = "73bef2ac39be261ae9a06076302c1d0af982e0560e88ac168980fab6ea5dd9c4"

    with patch.object(VirusTotal, "_get_api_response", return_value=response):
        sample = Hash(fake_hash, config_path=config_file)
        sample.check(services=[VirusTotal])

        propnames = [name for (name, value) in inspect.getmembers(sample, isprop)]
        for prop in propnames:
            getattr(sample, prop)

        propnames = [
            name for (name, value) in inspect.getmembers(sample.reports, isprop)
        ]
        for prop in propnames:
            getattr(sample, prop)

        propnames = [
            name
            for (name, value) in inspect.getmembers(
                sample.reports.malwarebazaar, isprop
            )
        ]
        for prop in propnames:
            getattr(sample, prop)
