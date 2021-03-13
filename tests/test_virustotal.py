import os

from hashcheck import Hash, SHA256, MD5
from hashcheck.services import VirusTotal
from hashcheck.exceptions import InvalidHashException

import vt
import pytest

from tests.fixtures import vt_eicar_response

def test_virus_total_client(vt_eicar_response):
    print(vt_eicar_response)
    dir(vt_eicar_response)
    print(vt_eicar_response.reputation)
