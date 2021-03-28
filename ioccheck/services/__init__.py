#!/usr/bin/env python
""" Services """

from .service import Service  # isort:skip
from .malwarebazaar import MalwareBazaar  # isort:skip
from .shodan import Shodan  # isort:skip
from .virustotal import VirusTotal  # isort:skip
from .twitter import Twitter # isort:skip

hash_services = [VirusTotal, MalwareBazaar, Twitter]
ip_services = [Shodan, Twitter]
