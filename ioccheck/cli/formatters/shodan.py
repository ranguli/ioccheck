#!/usr/bin/env python
"""Module provides human-friendly output from the Shodan.io Service"""

import logging

from ioccheck.cli.formatters.formatter import Formatter
from ioccheck.services import Shodan

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


class ShodanFormatter(Formatter):
    """Provide pre-formatted output from the Shodan.io Service"""

    def __init__(self, service: Shodan, heading_color):
        Formatter.__init__(self, service, heading_color)
