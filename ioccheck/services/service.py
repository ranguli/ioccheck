#!/usr/bin/env python
"""Module provides a base Service for implenting other services upon"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, List, Optional

from ioccheck import exceptions


class Service(ABC):  # pylint: disable=too-few-public-methods
    """Service base class for adding new threat intelligence services"""

    name: str
    ioc: Any
    reputation: Any
    required_credentials: List[str]

    def __init__(self, ioc, credentials: dict):

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        f_handler = logging.FileHandler("ioccheck.log")
        f_handler.setLevel(logging.INFO)

        f_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        f_handler.setFormatter(f_format)

        self.logger.addHandler(f_handler)

        self.ioc = ioc

        if list(credentials.keys()) != self.required_credentials:
            raise exceptions.InvalidCredentialsError

        self.credentials = Credentials(**credentials)
        self.response: dict = self._get_api_response(self.ioc)

        if self.response is None:
            raise exceptions.APIError

    @abstractmethod
    def _get_api_response(self, ioc) -> dict:
        pass

    def __str__(self):
        return self.name


@dataclass
class Credentials:
    api_key: Optional[str] = None
    consumer_key: Optional[str] = None
    consumer_secret: Optional[str] = None
    access_token: Optional[str] = None
    access_secret: Optional[str] = None
