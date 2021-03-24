#!/usr/bin/env python
"""Module providing custom types for ioccheck"""

from dataclasses import dataclass


class IOCType:  # pylint: disable=too-few-public-methods
    """Base class for representing a type of IOC"""


@dataclass
class HashType(IOCType):
    """Representation of file hash"""

    name: str
    regex: str

    def __str__(self) -> str:
        return self.name


@dataclass
class IPType(IOCType):
    """Representation of an IP address"""

    name: str

    def __str__(self) -> str:
        return self.name


SHA256 = HashType(name="SHA256", regex=r"^[A-Fa-f0-9]{64}$")
SHA1 = HashType(name="SHA256", regex=r"^[A-Fa-f0-9]{40}$")
MD5 = HashType(name="MD5", regex=r"^[a-f0-9]{32}$")

IPv4 = IPType(name="IPv4")
IPv6 = IPType(name="IPv6")

hash_types = [SHA256, SHA1, MD5]
ip_types = [IPv4, IPv6]
