#!/usr/bin/env/python
"""Module for the formatter base class"""

import logging

from ioccheck.services import Service


class Formatter:  # pylint: disable=too-few-public-methods
    """Base class for creating human-friendly threat intelligence API output"""

    def __init__(self, service: Service):
        self.service = service

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        f_handler = logging.FileHandler("ioccheck.log")
        f_handler.setLevel(logging.INFO)

        f_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        f_handler.setFormatter(f_format)

        self.logger.addHandler(f_handler)
