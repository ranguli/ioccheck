import configparser
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from ioccheck.exceptions import NoConfiguredServicesException
from ioccheck.services import Service

default_config_path = os.path.join(Path.home(), ".ioccheck")

logger = logging.getLogger(__name__)

aiohttp_logger = logging.getLogger("aiohttp")
aiohttp_logger.propagate = False

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


@dataclass
class IOCReport:
    pass


class IOC:
    def __init__(self, ioc: str):
        self.ioc = ioc
        self.name: str
        self.reports: IOCReport
        self.all_services: list

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

        result = [
            service
            for service in self.all_services
            if service.name in config.sections()
        ]

        if not result:
            raise NoConfiguredServicesException

        return result

    def _get_reports(self, services=None, config_path=None):
        reports = {}
        config_path = default_config_path if config_path is None else config_path

        if services is None:
            configured_services = self._get_configured_services(config_path)
            [
                reports.update(
                    self._get_report(self.ioc, service, config_path, reports)
                )
                for service in configured_services
            ]
        else:
            if isinstance(services, list):
                [
                    reports.update(
                        self._get_report(self.ioc, service, config_path, reports)
                    )
                    for service in services
                ]
            elif issubclass(services, Service):
                reports.update(
                    self._get_report(self.ioc, services, config_path, reports)
                )
            else:
                raise ValueError("Error while checking services")
        return reports

    def _get_report(
        self, file_hash: str, service: Service, config_path: str, reports: dict
    ) -> dict:
        service = self._single_check(self.ioc, service, config_path)
        return {service.name: service}

    def _single_check(self, ioc, service, config_path):
        api_key = self._get_credentials(service.name, config_path)
        return service(ioc, api_key)

    def __str__(self):
        return self.ioc
