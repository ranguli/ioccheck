#!/usr/bin/env/python
"""Module for the formatter base class"""

from ioccheck.services import Service


class Formatter:
    """Base class for creating human-friendly threat intelligence API output"""

    def __init__(self, service: Service):
        self.service = service
