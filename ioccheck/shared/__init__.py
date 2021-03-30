#!/usr/bin/env python

"""Common data types and constants"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

default_config_path = os.path.join(Path.home(), ".config/ioccheck/")


@dataclass
class Detection:
    """Detection of a sample by an anti-virus provider"""

    engine: str
    name: str
    malicious: bool


@dataclass
class Behavior:
    """Observed behavior of a sample from a sandbox"""

    vendor: str
    behavior: str
    threat: int


@dataclass
class Credentials:
    """Credentials necessary for services"""

    api_key: Optional[str] = None
    consumer_key: Optional[str] = None
    consumer_secret: Optional[str] = None
    access_token: Optional[str] = None
    access_secret: Optional[str] = None


@dataclass
class Tweet:
    """Tweet referencing an IOC directly by name"""

    author: str
    date: str
    text: str
    url: str
