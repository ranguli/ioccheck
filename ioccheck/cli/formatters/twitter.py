#!/usr/bin/env python
"""Module provides human-friendly output from Twitter """

import logging

from ioccheck.cli.formatters.formatter import Formatter
from ioccheck.services import Twitter

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


class TwitterFormatter(Formatter):
    """Provide pre-formatted output from Twitter"""

    def __init__(self, service: Twitter, heading_color: str):
        Formatter.__init__(self, service, heading_color)
