from dataclasses import dataclass
import re

from hashcheck.exceptions import InvalidHashException

@dataclass
class SHA256:
    regex: str = r'^[A-Fa-f0-9]{64}$'

@dataclass
class MD5:
    regex: str = r'^[a-f0-9]{32}$'

hash_types  = [SHA256, MD5]

class Hash:

    def __init__(self, file_hash: str, hash_type = None):
        self.hash = file_hash

        if hash_type:
            if not self.__check_hash_type(hash_type.regex, file_hash):
                raise InvalidHashException("Hash is not a supported hash type.  Supported types are {','.join(hash_types.keys())}")
            else:
                self.hash_type = hash_type
        else:
            self.hash_type = self.__guess_hash_type(self.hash)

        self.is_sha256 = True if self.hash_type == SHA256 else False
        self.is_md5  = True if self.hash_type == MD5 else False

    def __guess_hash_type(self, file_hash: str):
        actual_type = None

        for index, hash_type in enumerate(hash_types):
            print(hash_type)
            if self.__check_hash_type(hash_type.regex, file_hash):
                actual_type = hash_type
                break

        if actual_type is None:
            raise InvalidHashException("Hash is not a supported hash type.  Supported types are {','.join(hash_types.keys())}")

        return actual_type

    def __check_hash_type(self, hash_regex: str, file_hash: str) -> bool:
        return bool(re.match(hash_regex, file_hash))

    def __str__(self):
        return self.hash
