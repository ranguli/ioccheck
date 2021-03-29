#!/usr/bin/env python
"""Module representing file hashes"""

import re
from typing import List, Optional

from ioccheck.exceptions import InvalidHashException
from ioccheck.ioc_types import MD5, SHA256, HashType, hash_types
from ioccheck.iocs.ioc import IOC, IOCReport
from ioccheck.services import Service, hash_services
from ioccheck.services.data_types import Behavior


class HashReport(IOCReport):
    """Report representing threat intelligence results for a Hash object

    Attributes:
        virustotal: Results from the VirusTotal API
        malwarebazaar: Results from the MalwareBazaar API
    """


class Hash(IOC):  # pylint: disable=too-few-public-methods,too-many-instance-attributes
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

        IOC.__init__(self, ioc, config_path)

        self.hash_type = hash_type
        self._supported_types = ", ".join([str(hash_type) for hash_type in hash_types])
        self.invalid_hash_msg = f"Hash is not a supported hash type. Supported types are {self._supported_types}"
        self.services = hash_services

        if not isinstance(self.ioc, str):
            self.logger.error(f"{self.ioc} is not of type str")
            raise InvalidHashException

        if hash_type:
            if not self._check_hash_type(hash_type.regex, ioc):
                self.logger.error(
                    f"{ioc} is not a valid hash because it doesn't match regex {hash_type.regex}"
                )
                raise InvalidHashException(self.invalid_hash_msg)
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
            self.logger.info(f"Trying hash {hash_type}")
            if self._check_hash_type(hash_type.regex, file_hash):
                self.logger.info(f"Hash {file_hash} is of type {hash_type}")
                return hash_type

        self.logger.error(f"The type of hash {file_hash} could not be guessed!")
        raise InvalidHashException(self.invalid_hash_msg)

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

        reports = self._get_reports(services)
        self.reports = HashReport(**reports)

    @property
    def hashes(self) -> dict:
        """Results from other hashing algorithms found by other services

        Returns:
           Other
        """
        hashes = {}

        for report in [self.reports.malwarebazaar, self.reports.virustotal]:
            if report is not None and hasattr(report, "hashes"):
                hashes.update(report.hashes)  # type: ignore
        return hashes

    @property
    def detections(self) -> dict:
        detections = {}

        for report in [self.reports.virustotal]:
            if report is not None and report.detections:
                detections.update(report.detections)
        return detections

    @property
    def file_type(self) -> Optional[str]:
        malwarebazaar = self.reports.malwarebazaar

        if malwarebazaar is not None and malwarebazaar.file_type:
            return self.reports.malwarebazaar.file_type
        return None

    @property
    def mime_type(self) -> Optional[str]:
        malwarebazaar = self.reports.malwarebazaar

        if malwarebazaar is not None and malwarebazaar.mime_type:
            return self.reports.malwarebazaar.mime_type
        return None

    @property
    def file_size(self) -> Optional[int]:
        malwarebazaar = self.reports.malwarebazaar

        if malwarebazaar is not None and malwarebazaar.file_size:
            return self.reports.malwarebazaar.file_size
        return None

    @property
    def behavior(self) -> Optional[List[Behavior]]:
        return self._get_cross_report_value([self.reports.malwarebazaar], "behavior")
