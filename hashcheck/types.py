#!/usr/bin/env python
from dataclasses import dataclass


@dataclass
class HashType:
    name: str
    regex: str

    def __str__(self) -> str:
        return self.name


SHA256 = HashType(name="SHA256", regex=r"^[A-Fa-f0-9]{64}$")
SHA1 = HashType(name="SHA256", regex=r"^[A-Fa-f0-9]{40}$")
MD5 = HashType(name="MD5", regex=r"^[a-f0-9]{32}$")

hash_types = [SHA256, SHA1, MD5]
