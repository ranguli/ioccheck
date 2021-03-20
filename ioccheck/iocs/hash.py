import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ioccheck.exceptions import InvalidHashException
from ioccheck.iocs import IOC, IOCReport
from ioccheck.services import MalwareBazaar, Service, VirusTotal, hash_services
from ioccheck.types import MD5, SHA256, HashType, hash_types

default_config_path = os.path.join(Path.home(), ".ioccheck")
invalid_hash_message = f"Hash is not a supported hash type. Supported types are {', '.join([str(hash_type) for hash_type in hash_types])}."

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


@dataclass
class HashReport(IOCReport):
    virustotal: VirusTotal = None  # type: ignore
    malwarebazaar: MalwareBazaar = None  # type: ignore


class Hash(IOC):
    def __init__(self, file_hash: str, hash_type: HashType = None):
        self.ioc = file_hash
        self.hash_type = hash_type
        self.all_services = hash_services

        if not isinstance(self.ioc, str):
            raise InvalidHashException

        if hash_type:
            if not self._check_hash_type(hash_type.regex, file_hash):
                raise InvalidHashException(invalid_hash_message)
        else:
            self.hash_type = self._guess_hash_type(self.ioc)

        self.is_sha256 = True if self.hash_type == SHA256 else False
        self.is_md5 = True if self.hash_type == MD5 else False

    def _guess_hash_type(self, file_hash: str) -> HashType:
        """ Try all known hash regexes to determine the type of a hash. """
        actual_type: HashType

        for index, hash_type in enumerate(hash_types):
            if self._check_hash_type(hash_type.regex, file_hash):
                return hash_type

        raise InvalidHashException(invalid_hash_message)

    def _check_hash_type(self, hash_regex: str, file_hash: str) -> bool:
        """ Validate that a given hash matches its regex."""
        return bool(re.match(hash_regex, file_hash))

    def check(
        self,
        services: Optional[List[Service]] = None,
        config_path: Optional[str] = None,
    ):
        reports = self._get_reports(services, config_path)
        self.reports = HashReport(**reports)
