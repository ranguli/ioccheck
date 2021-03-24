#!/usr/bin/env python
"""Module provides a base Service for implenting other services upon"""

from abc import ABC, abstractmethod
from typing import Optional


class Service(ABC):
    """Service base class for adding new threat intelligence services"""

    name: str

    def __new__(cls, *args):
        if not hasattr(cls, "name"):
            raise NotImplementedError(
                "'Service' subclasses should have a 'name' attribute"
            )
        if not hasattr(cls, "url"):
            raise NotImplementedError(
                "'Service' subclasses should have a 'url' attribute"
            )
        return object.__new__(cls)

    def __init__(self):
        pass

    @abstractmethod
    def _get_api_response(self, ioc, api_key: str) -> dict:
        pass

    @property
    def reputation(self) -> Optional[int]:
        pass

    def __str__(self):
        return self.name
