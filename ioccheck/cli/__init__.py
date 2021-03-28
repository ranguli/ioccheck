#!/usr/bin/env python
"""Command-line interface for the ioccheck library"""

import logging
import random
import sys
import os
from pathlib import Path

import click
import pkg_resources
from pyfiglet import Figlet
from termcolor import colored, cprint

from tabulate import tabulate

import shodan

from ioccheck.cli.formatters import (
    MalwareBazaarFormatter,
    ShodanFormatter,
    VirusTotalFormatter,
    TwitterFormatter,
)
from ioccheck.exceptions import (
    InvalidHashException,
    InvalidIPException,
    NoConfiguredServicesException,
)
from ioccheck.iocs import IP, Hash

from ioccheck.reports import HTMLHashReport, HTMLIPReport

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


def twitter_results(ioc, heading_color):
    twitter_report = ioc.reports.twitter

    formatter = TwitterFormatter(twitter_report, heading_color)
    print(formatter.tweets)


def ip_results(ip_addr, heading_color):
    """Print results for an IP address"""
    try:
        shodan_results(ip_addr, heading_color)
    except AttributeError:
        cprint("[!] There was an error displaying the Shodan report.", "red")

    twitter_results(ip_addr, heading_color)


def virustotal_results(_hash, heading_color):
    """ Use the VirusTotalFormatter to print pre-formatted output """

    virustotal = _hash.reports.virustotal

    formatter = VirusTotalFormatter(virustotal, heading_color)

    investigation_url_heading = colored("[*] VirusTotal URL:", heading_color)
    print(f"{investigation_url_heading} {virustotal.investigation_url}")

    # Make a pretty table of the results
    detections_heading = colored("[*] Detections:", "blue")

    print(f"{detections_heading} {formatter.detection_count}")
    print(formatter.detections)

    reputation_heading = colored("[*] VirusTotal reputation:", heading_color)
    print(f"{reputation_heading} {formatter.reputation}")


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


def behaviour(_hash, heading_color):
    table = [["Vendor", "Behaviour", "Threat"]]

    for result in _hash.behaviour:
        if result.get("threat") == 1:
            threat = colored("Neutral", "green")
        elif result.get("threat") == 2:
            threat = colored("Suspicious", "yellow")
        elif result.get("threat") == 3:
            threat = colored("Malicious", "red")

        table.append([result.get("service"), result.get("behaviour"), threat])

    return tabulate(table, tablefmt="fancy_grid")


def hash_results(_hash, heading_color):
    """Print results a file hash"""
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

    if not _hash.tags:
        cprint("[!] No tags to display.", "yellow")

    heading = colored("[*] User-submitted tags:", heading_color)
    print(f"{heading} {', '.join(_hash.tags)}")

    if not _hash.behaviour:
        cprint("[!] No behaviour data to display.", "yellow")

    heading = colored("[*] Behaviour:", heading_color)
    print(heading)
    print(behaviour(_hash, heading_color))

    twitter_results(_hash, heading_color)


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
            "exception": InvalidHashException,
            "results": hash_results,
        },
        {
            "name": "public IPv4 or IPv6 address",
            "ioc": IP,
            "exception": InvalidIPException,
            "results": ip_results,
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
        config = os.path.join(Path.home(), ".config/ioccheck/credentials")

    templates_dir = os.path.join(Path.home(), ".config/ioccheck/reports/templates/")

    for ioc_type in ioc_types:
        try:
            cprint(f"{check_message} {ioc_type.get('name')}.", heading_color)
            ioc = ioc_type.get("ioc")(ioc, config_path=config)
            ioc.check()
            ioc_type.get("results")(ioc, heading_color)
            break
        except ioc_type.get("exception"):
            cprint(f"{fail_message} {ioc_type.get('name')}.", "yellow")
        except NoConfiguredServicesException:
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
