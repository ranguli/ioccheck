#!/usr/bin/env python
"""Command-line interface for the ioccheck library"""

import cProfile
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

from .printers import BehaviorPrinter, DetectionsPrinter, TagsPrinter, TwitterPrinter

asyncio_logger = logging.getLogger("asyncio")
asyncio_logger.setLevel(logging.CRITICAL)


fonts = [
    "slant",
    "banner",
    "basic",
    "bell",
    "block",
    "calgphy2",
    "colossal",
    "cosmic",
    "doom",
    "larry3d",
    "poison",
    "smkeyboard",
    "standard",
    "straight",
    "trek",
]


def hash_details(_hash, heading_color):
    results = [[k, v] for k, v in _hash.hashes.items() if v]

    table = []

    for result in results:
        table.append(result)

    return tabulate(table, tablefmt="fancy_grid")


@click.command()
@click.argument("ioc")
@click.option("--config", required=False, type=str)
@click.option("--report", required=False, type=str)
def run(ioc, config, report):
    """Entrypoint for the ioccheck CLI"""

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

    figlet = Figlet(font=random.choice(fonts))  # nosec
    heading_color = "blue"

    version = pkg_resources.get_distribution("ioccheck").version

    cprint(
        figlet.renderText("ioccheck"),
    )
    cprint(f"v{version} (https://github.com/ranguli/ioccheck)\n", heading_color)

    printed_ioc = colored(ioc, heading_color)
    print(f"Checking IOC {printed_ioc}.\n")

    check_message = "[*] Checking if IOC is a valid"
    fail_message = "[!] IOC is not a valid"

    if not config:
        config = default_config_path

    templates_dir = os.path.join(Path.home(), ".config/ioccheck/reports/templates/")

    for ioc_type in ioc_types:
        try:
            cprint(f"{check_message} {ioc_type.get('name')}.", heading_color)
            ioc = ioc_type.get("ioc")(ioc, config_path=config)
            cprint("[?] Checking services", "red")
            ioc.check()

            for printer in ioc_type.get("printers"):
                printer(ioc).print_text()
            break
        except ioc_type.get("exception"):
            cprint(f"{fail_message} {ioc_type.get('name')}.", "yellow")
        except exceptions.InvalidCredentialsError as e:
            cprint(f"[!] {e}", "red")
        except exceptions.NoConfiguredServicesException:
            sys.exit(
                colored(
                    "[!] No configured services available to search that IOC.", "red"
                )
            )
        except FileNotFoundError as error:
            sys.exit(colored(f"[!] {error}", "red"))

    if report:
        cprint(f"[*] Generating report {report}")
        if isinstance(ioc, Hash):
            html_report = HTMLHashReport(ioc, templates_dir)
        elif isinstance(ioc, IP):
            html_report = HTMLIPReport(ioc, templates_dir)

        html_report.generate(report)
