#!/usr/bin/env python
""" Services """

from .service import Service  # isort:skip
from .malwarebazaar import MalwareBazaar  # isort:skip
from .shodan import Shodan  # isort:skip
from .virustotal import VirusTotal  # isort:skip

hash_services = [VirusTotal, MalwareBazaar]
ip_services = [Shodan]
