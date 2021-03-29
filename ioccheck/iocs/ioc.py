#!/usr/bin/env python
""" The IOC module provides base classes for other indicators of compromise """

import configparser
import logging
import os
from pathlib import Path
from typing import List, Optional, Union
from dataclasses import dataclass

from ioccheck.exceptions import InvalidCredentialsError, NoConfiguredServicesException
from ioccheck.services import Service, Twitter, VirusTotal, MalwareBazaar, Shodan
from ioccheck.shared import default_config_path


@dataclass
class IOCReport:
    twitter: Twitter = None  # type: ignore
    shodan: Shodan = None  # type: ignore
    virustotal: VirusTotal = None  # type: ignore
    malwarebazaar: MalwareBazaar = None  # type: ignore


class IOC:  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """Base class for creating indicators of compromise classes

    Attributes:
        ioc: The Indicator of Compromise
        config_path: The filepath of the configuration file
        reports: The Indicator of Compromise
        services: All potential services avilable for the IOC type
    """

    def __init__(self, ioc, config_path: Optional[str] = None):

        self.ioc = ioc

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.services: list

        f_handler = logging.FileHandler("ioccheck.log")
        f_handler.setLevel(logging.INFO)

        f_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        f_handler.setFormatter(f_format)

        self.logger.addHandler(f_handler)

        if config_path is None:
            self.config_path = default_config_path
        else:
            self.config_path = config_path

        self.credentials_file = os.path.join(self.config_path, "credentials")

        self.logger.info(
            f"Default config path is {default_config_path}, supplied path is {self.config_path}"
        )

        if not Path(self.credentials_file).is_file():
            message = f"File {self.credentials_file} does not exist"
            self.logger.error(message)
            raise FileNotFoundError(message)

        self.reports: IOCReport

    @property
    def credentials(self) -> dict:
        """Credentials for use with API services"""

        if not Path(self.credentials_file).is_file():
            message = f"File {self.credentials_file} does not exist"
            self.logger.error(message)
            raise FileNotFoundError(message)

        config = configparser.ConfigParser()
        config.read(self.credentials_file)

        credentials: dict = {}

        for section in config.sections():
            values = ",".join(config[section].keys())
            self.logger.info(
                f"Got {values} for {section} from {self.credentials_file}."
            )

            credentials.update({section: dict(config[section])})

        return credentials

    @property
    def tweets(self) -> Optional[List]:
        """Tweets that mention the IOC directly"""
        try:
            return self.reports.twitter.tweets
        except AttributeError:
            return None

    @property
    def configured_services(self) -> list:
        """IOC services in the config file with keys"""

        # TODO: refactor out this duplicate snippet also in credentials()

        if not Path(self.credentials_file).is_file():
            message = f"File {self.credentials_file} does not exist"
            self.logger.error(message)
            raise FileNotFoundError(message)

        config = configparser.ConfigParser()
        config.read(self.credentials_file)

        result = [
            service for service in self.services if service.name in config.sections()
        ]

        if not result:
            self.logger.error("No configured services were found.")
            raise NoConfiguredServicesException

        return result

    def _get_reports(self, services: Optional[Union[List, List[Service]]] = None):

        reports = {}
        report_services = []

        if services is None:
            report_services = self.configured_services
        elif not isinstance(services, list):
            report_services.append(services)
        else:
            report_services = services

        for service in report_services:
            reports.update(self._get_report(self.ioc, service))

        return reports

    def _get_report(self, ioc: str, service: Service) -> dict:
        service = self._single_check(ioc, service)
        return {service.name: service}

    def _single_check(self, ioc, service) -> Service:

        api_key = self.credentials.get(service.name)  # type: ignore

        if not api_key:
            self.logger.error(f"No API keys for {service}")
            raise InvalidCredentialsError

        return service(ioc, api_key)

    def __str__(self):
        return self.ioc

    def _get_cross_report_value(self, reports: list, attribute: str):
        result = []

        for report in reports:
            if report is not None and hasattr(report, attribute):
                try:
                    result.extend(getattr(report, attribute))
                except TypeError:
                    pass

        return result

    @property
    def tags(self) -> Optional[List[dict]]:
        """User-submitted tags describing the IOC across multiple services."""
        return self._get_cross_report_value(
            [self.reports.malwarebazaar, self.reports.virustotal], "tags"
        )

    @property
    def urls(self) -> Optional[List[dict]]:
        """URLs to use for following up on information from a service."""
        return self._get_cross_report_value(
            [self.reports.malwarebazaar, self.reports.virustotal], "urls"
        )
