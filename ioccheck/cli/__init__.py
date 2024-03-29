#!/usr/bin/env python
"""Command-line interface for the ioccheck library"""

import logging
import os
import random
import sys
from pathlib import Path

import click
import pkg_resources
import shodan
from pyfiglet import Figlet
from tabulate import tabulate
from termcolor import colored, cprint

from ioccheck import exceptions
from ioccheck.iocs import IP, Hash
from ioccheck.reports import HTMLHashReport, HTMLIPReport
from ioccheck.services import Shodan, Twitter
from ioccheck.shared import default_config_path

from .printers import (BehaviorPrinter, DetectionsPrinter, TagsPrinter,
                       TwitterPrinter)

asyncio_logger = logging.getLogger("asyncio")
asyncio_logger.setLevel(logging.CRITICAL)


fonts = [
    "slant",
    "block",
    "colossal",
    "cosmic",
    "larry3d",
    "poison",
    "smkeyboard",
    "standard",
    "trek",
]

HEADING_COLOR = "blue"
CHECK_MESSAGE = "[*] Checking if IOC is a valid"
FAIL_MESSAGE = "[!] IOC is not a valid"

figlet = Figlet(font=random.choice(fonts))  # nosec
templates_dir = os.path.join(Path.home(), ".config/ioccheck/reports/templates/")
version = pkg_resources.get_distribution("ioccheck").version


ioc_types = [
    {
        "name": "file hash",
        "ioc": Hash,
        "exception": exceptions.InvalidHashException,
        "printers": [
            TagsPrinter,
            DetectionsPrinter,
            BehaviorPrinter,
            TwitterPrinter,
        ],
    },
    {
        "name": "public IPv4 or IPv6 address",
        "ioc": IP,
        "exception": exceptions.InvalidIPException,
        "printers": [TagsPrinter, TwitterPrinter],
    },
]

cprint(figlet.renderText("ioccheck"))

cprint(f"v{version} (https://github.com/ranguli/ioccheck)\n", HEADING_COLOR)


@click.command()
@click.argument("ioc")
@click.option("--config", required=False, type=str)
@click.option("--report", required=False, type=str)
def run(ioc, config, report):
    """Entrypoint for the ioccheck CLI"""

    printed_ioc = colored(ioc, HEADING_COLOR)
    print(f"Checking IOC {printed_ioc}.\n")

    if not config:
        config = default_config_path

    for ioc_type in ioc_types:
        try:
            check_ioc(ioc_type, ioc, HEADING_COLOR, config)
            break
        except ioc_type.get("exception"):
            cprint(f"{FAIL_MESSAGE} {ioc_type.get('name')}.", "yellow")
        except exceptions.InvalidCredentialsError as error:
            cprint(f"[!] {error}", "red")
        except exceptions.NoConfiguredServicesException:
            sys.exit(
                colored(
                    "[!] No configured services available to search that IOC.", "red"
                )
            )
        except FileNotFoundError as error:
            sys.exit(colored(f"[!] {error}", "red"))

    if report:
        handle_report(ioc, report)


def check_ioc(ioc_type, ioc, heading_color, config):
    """Checks a given IOC"""
    cprint(f"{CHECK_MESSAGE} {ioc_type.get('name')}.", heading_color)
    ioc = ioc_type.get("ioc")(ioc, config_path=config)
    cprint("[?] Checking services", "red")
    ioc.check()

    for printer in ioc_type.get("printers"):
        text_printer = printer(ioc)
        text_printer.print_text()


def handle_report(ioc, report):
    """Report generation"""
    cprint(f"[*] Generating report {report}")
    if isinstance(ioc, Hash):
        html_report = HTMLHashReport(ioc, templates_dir)
    elif isinstance(ioc, IP):
        html_report = HTMLIPReport(ioc, templates_dir)

    html_report.generate(report)
