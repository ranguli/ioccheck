from dataclasses import dataclass
import configparser
import re
import os
from pathlib import Path
import logging

from hashcheck.services.service import Service
from hashcheck.services import all_services
from hashcheck.types import SHA256, MD5, hash_types, HashType
from hashcheck.exceptions import InvalidHashException
from hashcheck.reports import VirusTotalReport

hashcheck_logger = logging.getLogger(__name__)
hashcheck_logger.setLevel(logging.INFO)

fh = logging.FileHandler("hashcheck.log")
fh.setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

fh.setFormatter(formatter)
hashcheck_logger.addHandler(fh)

default_config_path = os.path.join(Path.home(), ".hashcheck")


class Hash:
    def __init__(self, file_hash: str, hash_type: HashType = None):
        self.hash = file_hash
        self.name = None
        self.reports = None
        self.hash_type = hash_type

        if not isinstance(self.hash, str):
            raise InvalidHashException

        if hash_type:
            if not self.__check_hash_type(hash_type.regex, file_hash):
                raise InvalidHashException(
                    "Hash is not a supported hash type.  Supported types are {','.join(hash_types.keys())}"
                )
        else:
            self.hash_type = self.__guess_hash_type(self.hash)

        self.is_sha256 = True if self.hash_type == SHA256 else False
        self.is_md5 = True if self.hash_type == MD5 else False

    def __guess_hash_type(self, file_hash: str):
        """ Try all known hash regexes to determine the type of a hash. """
        actual_type = None

        for index, hash_type in enumerate(hash_types):
            if self.__check_hash_type(hash_type.regex, file_hash):
                actual_type = hash_type
                break

        if actual_type is None:
            raise InvalidHashException(
                "Hash is not a supported hash type.  Supported types are {','.join(hash_types.keys())}"
            )

        return actual_type

    def __check_hash_type(self, hash_regex: str, file_hash: str) -> bool:
        """ Validate that a given hash matches its regex."""
        return bool(re.match(hash_regex, file_hash))

    def __str__(self):
        return self.hash

    def _get_credentials(self, config_header, config_path: str) -> str:
        hashcheck_logger.info(
            f"Default config path is {default_config_path}, supplied path is {config_path}"
        )

        if not Path(config_path).is_file():
            raise FileNotFoundError(f"File {config_path} does not exist.")

        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            api_key = config[config_header]["API_KEY"]
        except KeyError:
            raise KeyError(f"Could not find necessary API keys in {config_path}")

        return api_key

    def check(self, services=None, config_path=None):
        reports = HashReport()

        if config_path is None:
            config_path = default_config_path

        if services is None:
            for service in all_services:
                api_key = self._get_credentials(service.name, config_path)
                service = service(self.hash, api_key)
                if service.name == "virustotal":
                    reports.virustotal = service.report
        else:
            if isinstance(services, list):
                for service in services:
                    api_key = self._get_credentials(service.name, config_path)
                    service = service(self.hash, api_key)
                    if service.name == "virustotal":
                        reports.virustotal = service.report
            elif issubclass(services, Service):
                api_key = self._get_credentials(services.name, config_path)
                service = services(self.hash, api_key)
                if service.name == "virustotal":
                    reports.virustotal = service.report
            else:
                raise ValueError("Error while checking services")
        self.reports = reports


@dataclass
class HashReport:
    virustotal: VirusTotalReport = None
