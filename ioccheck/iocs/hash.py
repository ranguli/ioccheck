#!/usr/bin/env python
"""Module representing file hashes"""


import logging
import re
from dataclasses import dataclass
from typing import List, Optional

from ioccheck.exceptions import InvalidHashException
from ioccheck.ioc_types import MD5, SHA256, HashType, hash_types
from ioccheck.iocs import IOC, IOCReport
from ioccheck.services import MalwareBazaar, Service, VirusTotal, hash_services

invalid_hash_message = f"Hash is not a supported hash type. Supported types are {', '.join([str(hash_type) for hash_type in hash_types])}."

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)

asyncio_logger = logging.getLogger("asyncio")
asyncio_logger.propagate = False
asyncio_logger.setLevel(logging.CRITICAL)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)


@dataclass
class HashReport(IOCReport):
    """Report representing threat intelligence results for a Hash object

    Attributes:
        virustotal: Results from the VirusTotal API
        malwarebazaar: Results from the MalwareBazaar API
    """

    virustotal: VirusTotal = None  # type: ignore
    malwarebazaar: MalwareBazaar = None  # type: ignore


class Hash(IOC):
    """Type of IOC representing file hashes

    Attributes:
        hash_type: Indicates the hashing algorithm used by the hash.
        ioc: Represenation of the IOC as a string
        services: Supported services that can be used to investigate the IOC
        is_sha256: Whether or not the hash is a SHA256 hash.
        is_md5: Whether or not the hash is an MD5 hash.

    """

    def __init__(
        self,
        ioc: str,
        hash_type: Optional[HashType] = None,
        config_path: Optional[str] = None,
    ):

        self.ioc = ioc
        self.hash_type = hash_type
        self.services = hash_services

        IOC.__init__(self, ioc, config_path)

        if not isinstance(self.ioc, str):
            logger.error("%(self.ioc)s is not of type str")
            raise InvalidHashException

        if hash_type:
            if not self._check_hash_type(hash_type.regex, ioc):
                logger.error(
                    "%(ioc)s is not a valid hash because it doesn't match regex %(hash_type.regex)s "
                )
                raise InvalidHashException(invalid_hash_message)
        else:
            self.hash_type = self._guess_hash_type(self.ioc)

        self.is_sha256 = bool(self.hash_type == SHA256)
        self.is_md5 = bool(self.hash_type == MD5)

    def _guess_hash_type(self, file_hash: str) -> HashType:
        """Guesses the type of a file hash.

        Args:
            file_hash: The file hash to guess the type of

        Returns:
            The type of the file hash

        Raises:
            InvalidHashException: If the input hash matches no known type
        """

        for hash_type in hash_types:
            logger.info("Trying hash %(hash_type)s")
            if self._check_hash_type(hash_type.regex, file_hash):
                logger.info("Hash %(file_hash)s is of type %(hash_type)s")
                return hash_type

        logger.error("The type of hash %(file_hash)s could not be guessed!")
        raise InvalidHashException(invalid_hash_message)

    @staticmethod
    def _check_hash_type(hash_regex: str, file_hash: str) -> bool:
        """Validate that a given hash matches a regex.

        Args:
            hash_regex: The regex to identify a hashes type
            file_hash: The hash to be checked

        Returns:
            Whether or not the hash matches the regex.
        """

        return bool(re.match(hash_regex, file_hash))

    def check(self, services: Optional[List[Service]] = None):
        """Get threat intelligence information for a hash

        Args:
            services: The threat intelligence services to be checked
        """

        reports = self._get_reports(self.config_path, services)
        self.reports = HashReport(**reports)
