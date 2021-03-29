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
from ioccheck.cli.formatters import (
    MalwareBazaarFormatter,
    ShodanFormatter,
    TwitterFormatter,
)
from ioccheck.iocs import IP, Hash
from ioccheck.reports import HTMLHashReport, HTMLIPReport
from ioccheck.services import Shodan, Twitter
from ioccheck.shared import default_config_path

from .printers import BehaviourPrinter, DetectionsPrinter, TagsPrinter, TwitterPrinter

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

"""
def location_data():
    Pre-formatted output for geolocation data

    location = self.service.location
    table = []

    headings = {
        "City": location.get("city"),
        "Country": location.get("country_name"),
        "Organization": location.get("org"),
        "ISP": location.get("isp"),
        "Hostnames": ", ".join(self.service.hostnames),
        "ASN": location.get("asn"),
    }

    for title, value in headings.items():
        if value:
            table.append([colored(title, "blue"), value])

    return tabulate(table, tablefmt="fancy_grid")
    """


def shodan_results(ip_addr, heading_color):
    """ Use the ShodanFormatter to print pre-formatted output """
    shodan_report = ip_addr.reports.shodan

    formatter = ShodanFormatter(shodan_report, heading_color)

    cprint("[*] Shodan location data:", heading_color)
    print(formatter.location)

    tags_header = colored("[*] Shodan tags:", heading_color)
    print(f"{tags_header} {formatter.tags}")


def ip_results(ip_addr, heading_color):
    pass


def detections(_hash, heading_color):
    table = [["Antivirus", "Detection"]]

    for detection, result in _hash.detections.items():
        if result.get("category") == "malicious":
            table.append([detection, colored(result.get("result"), "red")])

    return tabulate(table, headers="firstrow", tablefmt="fancy_grid")


def hash_details(_hash, heading_color):
    results = [[k, v] for k, v in _hash.hashes.items() if v]

    table = []

    for result in results:
        table.append(result)

    return tabulate(table, tablefmt="fancy_grid")


def hash_results(_hash, heading_color):
    """Print results a file hash"""
    """
    hash_algorithm_heading = colored("[*] Hashing algorithm:", heading_color)
    print(f"{hash_algorithm_heading} {_hash.hash_type}")

    try:
        virustotal_results(_hash, heading_color)
    except AttributeError:
        cprint("[!] There was an error displaying the VirusTotal report.", "red")

    hashes_heading = colored("[*] Hash details:", heading_color)
    print(f"{hashes_heading}\n{hash_details(_hash, heading_color)}")

    detections_heading = colored("[*] Detections:", heading_color)
    print(f"{detections_heading}\n{detections(_hash, heading_color)}")


    """


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
                BehaviourPrinter,
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
