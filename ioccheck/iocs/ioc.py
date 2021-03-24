#!/usr/bin/env python
""" The IOC module provides base classes for other indicators of compromise """

import configparser
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union

from ioccheck.exceptions import (InvalidCredentialsException,
                                 NoConfiguredServicesException)
from ioccheck.services import Service

asyncio_logger = logging.getLogger("asyncio")
asyncio_logger.propagate = False
asyncio_logger.setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


@dataclass
class IOCReport:
    """Base dataclass for creating indicators of compromise reports """


class IOC:
    """Base class for creating indicators of compromise classes

    Attributes:
        ioc: The Indicator of Compromise
        config_path: The filepath of the configuration file
        reports: The Indicator of Compromise
        services: All potential services avilable for the IOC type
        configured_services: All configured services available for the IOC type
    """

    def __init__(self, ioc, config_path: Optional[str] = None):

        self.ioc = ioc
        self._default_config_path = os.path.join(Path.home(), ".ioccheck")

        if config_path is None:
            self.config_path = self._default_config_path
        else:
            self.config_path = config_path

        logger.info(
            f"Default config path is {self._default_config_path}, supplied path is {self.config_path}"
        )

        self.reports: IOCReport
        self.services: list

        self.configured_services: list = self._get_configured_services(self.config_path)
        self._credentials: dict = self._get_credentials(self.config_path)

    def _get_credentials(self, config_path: str) -> dict:
        self._configured_services = self._get_configured_services(config_path)

        if not Path(config_path).is_file():
            message = f"File {config_path} does not exist."
            logger.error(message)
            raise FileNotFoundError(message)

        config = configparser.ConfigParser()
        config.read(config_path)

        credentials: dict = {}

        for section in config.sections():

            logger.info(
                f"Got values {','.join(config[section].keys())} for {section} from {config_path}"
            )

            credentials.update({section: config[section]["api_key"]})

        return credentials

    def _get_configured_services(self, config_path: str) -> list:

        if config_path is None:
            config_path = self._default_config_path

        if not Path(config_path).is_file():
            message = f"File {config_path} does not exist"
            logger.error(message)
            raise FileNotFoundError(message)

        config = configparser.ConfigParser()
        config.read(config_path)

        result = [
            service for service in self.services if service.name in config.sections()
        ]

        if not result:
            logger.error("No configured services were found.")
            raise NoConfiguredServicesException

        return result

    def _get_reports(
        self, config_path: str, services: Optional[Union[List, List[Service]]] = None
    ):

        reports = {}
        config_path = self._default_config_path if config_path is None else config_path
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

        api_key = self._credentials.get(service.name)  # type: ignore

        if not api_key:
            logger.error(f"No API keys for {service}")
            raise InvalidCredentialsException

        return service(ioc, api_key)

    def __str__(self):
        return self.ioc
