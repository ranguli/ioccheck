#!/usr/bin/env python
"""Module provides a base Service for implenting other services upon"""

import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class Service(ABC):  # pylint: disable=too-few-public-methods
    """Service base class for adding new threat intelligence services"""

    name: str
    ioc: Any
    reputation: Any

    def __init__(self, ioc, api_key: str):
        self.ioc = ioc
        self.api_key = api_key
        self._default_config_path = os.path.join(Path.home(), ".ioccheck")

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        f_handler = logging.FileHandler("ioccheck.log")
        f_handler.setLevel(logging.INFO)

        f_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        f_handler.setFormatter(f_format)

        self.logger.addHandler(f_handler)

    @abstractmethod
    def _get_api_response(self, ioc, api_key: str) -> dict:
        pass

    def __str__(self):
        return self.name
