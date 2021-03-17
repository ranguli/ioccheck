import configparser
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from hashcheck.exceptions import InvalidHashException
from hashcheck.services import MalwareBazaar, VirusTotal, all_services
from hashcheck.services.service import Service
from hashcheck.types import MD5, SHA1, SHA256, HashType, hash_types

default_config_path = os.path.join(Path.home(), ".hashcheck")
invalid_hash_message = f"Hash is not a supported hash type. Supported types are {', '.join([str(hash_type) for hash_type in hash_types])}."

logger = logging.getLogger("hashcheck")

aiohttp_logger = logging.getLogger("aiohttp")
aiohttp_logger.propagate = False
aiohttp_logger.enabled = False

f_handler = logging.FileHandler("hashcheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


@dataclass
class HashReport:
    virustotal: VirusTotal = None
    malwarebazaar: MalwareBazaar = None


class Hash:
    def __init__(self, file_hash: str, hash_type: HashType = None):
        self.hash = file_hash
        self.name = None
        self.reports = {}
        self.hash_type = hash_type

        if not isinstance(self.hash, str):
            raise InvalidHashException

        if hash_type:
            if not self._check_hash_type(hash_type.regex, file_hash):
                raise InvalidHashException(invalid_hash_message)
        else:
            self.hash_type = self._guess_hash_type(self.hash)

        self.is_sha256 = True if self.hash_type == SHA256 else False
        self.is_md5 = True if self.hash_type == MD5 else False

    def _guess_hash_type(self, file_hash: str):
        """ Try all known hash regexes to determine the type of a hash. """
        actual_type = None

        for index, hash_type in enumerate(hash_types):
            if self._check_hash_type(hash_type.regex, file_hash):
                actual_type = hash_type
                break

        if actual_type is None:
            raise InvalidHashException(invalid_hash_message)

        return actual_type

    def _check_hash_type(self, hash_regex: str, file_hash: str) -> bool:
        """ Validate that a given hash matches its regex."""
        return bool(re.match(hash_regex, file_hash))

    def _get_credentials(self, config_header, config_path: str) -> str:

        self._get_configured_services(config_path)

        if not Path(config_path).is_file():
            message = f"File {config_path} does not exist."
            logger.error(message)
            raise FileNotFoundError(message)

        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            api_key = config[config_header]["API_KEY"]
        except KeyError:
            message = f"Could not find necessary API keys in {config_path}"
            logger.error(message)
            raise KeyError(message)

        return api_key

    def _get_configured_services(self, config_path: str) -> list:
        """ Return a list of Service objects with credentials in the config"""

        logger.info(
            f"Default config path is {default_config_path}, supplied path is {config_path}"
        )

        if not Path(config_path).is_file():
            message = f"File {config_path} does not exist"
            logger.error(message)
            raise FileNotFoundError(message)

        config = configparser.ConfigParser()
        config.read(config_path)

        return [
            service for service in all_services if service.name in config.sections()
        ]

    def check(self, services=None, config_path=None):
        reports = {}
        config_path = default_config_path if config_path is None else config_path

        if services is None:
            configured_services = self._get_configured_services(config_path)
            [
                self._add_report(self.hash, service, config_path, reports)
                for service in configured_services
            ]
        else:
            if isinstance(services, list):
                [
                    self._add_report(self.hash, service, config_path, reports)
                    for service in services
                ]
            elif issubclass(services, Service):
                self._add_report(self.hash, services, config_path, reports)
            else:
                raise ValueError("Error while checking services")

        self.reports = HashReport(**reports)
        logging.info(f"Generated report {self.reports}")

    def _add_report(
        self, file_hash: str, service: Service, config_path: str, reports: dict
    ):
        service = self._single_check(self.hash, service, config_path)
        reports.update({service.name: service})

    def _single_check(self, file_hash, service, config_path):
        api_key = self._get_credentials(service.name, config_path)
        return service(file_hash, api_key)

    def __str__(self):
        return self.hash
