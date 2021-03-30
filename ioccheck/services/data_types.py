from dataclasses import dataclass
from typing import Optional


@dataclass
class Behavior:
    vendor: str
    behavior: str
    threat: int


@dataclass
class Credentials:
    api_key: Optional[str] = None
    consumer_key: Optional[str] = None
    consumer_secret: Optional[str] = None
    access_token: Optional[str] = None
    access_secret: Optional[str] = None
