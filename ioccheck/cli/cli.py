#!/usr/bin/env python
"""Command-line interface for the ioccheck library"""

import logging
import random
import sys

import click
import pkg_resources
from pyfiglet import Figlet
from termcolor import colored, cprint

from ioccheck.cli.formatters import (MalwareBazaarFormatter, ShodanFormatter,
                                     VirusTotalFormatter)
from ioccheck.exceptions import (InvalidHashException, InvalidIPException,
                                 NoConfiguredServicesException)
from ioccheck.iocs import IP, Hash

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


def shodan_results(ip_addr, heading_color):
    """ Use the ShodanFormatter to print pre-formatted output """
    shodan = ip_addr.reports.shodan

    formatter = ShodanFormatter(shodan)

    cprint("[*] Shodan location data:", heading_color)
    print(formatter.location)

    tags_header = colored("[*] Shodan tags:", heading_color)
    print(f"{tags_header} {formatter.tags}")


def ip_results(ip_addr, heading_color):
    """Print results for an IP address"""
    try:
        shodan_results(ip_addr, heading_color)
    except AttributeError:
        cprint("[!] There was an error displaying the Shodan report.", "red")


def virustotal_results(_hash, heading_color):
    """ Use the VirusTotalFormatter to print pre-formatted output """

    virustotal = _hash.reports.virustotal

    formatter = VirusTotalFormatter(virustotal)

    if formatter.tags:
        tags_heading = colored("[*] VirusTotal tags:", heading_color)
        print(f"{tags_heading} {formatter.tags}")

    investigation_url_heading = colored("[*] VirusTotal URL:", heading_color)
    print(f"{investigation_url_heading} {virustotal.investigation_url}")

    # Make a pretty table of the results
    detections_heading = colored("[*] VirusTotal detections:", "blue")

    print(f"{detections_heading} {formatter.detection_count}")
    print(formatter.detections)

    reputation_heading = colored("[*] VirusTotal reputation:", heading_color)
    print(f"{reputation_heading} {formatter.reputation}")

    if formatter.popular_threat_names:
        threat_names_heading = colored("[*] VirusTotal threat labels:", heading_color)
        print(f"{threat_names_heading} {formatter.popular_threat_names}")


def malwarebazaar_results(_hash, heading_color):
    """ Use the MalwareBazaarFormatter to print pre-formatted output """

    malwarebazaar = _hash.reports.malwarebazaar

    formatter = MalwareBazaarFormatter(malwarebazaar)

    if formatter.tags:
        tags_heading = colored("[*] MalwareBazaar tags:", heading_color)
        print(f"{tags_heading} {formatter.tags}")

    file_size_heading = colored("[*] File details:", heading_color)
    print(
        f"{file_size_heading} {formatter.file_type} | {malwarebazaar.mime_type} ({formatter.file_size})"
    )

    cprint("[*] File hashes:\n", heading_color)
    print(formatter.hashes)


def hash_results(_hash, heading_color):
    """Print results a file hash"""
    hash_algorithm_heading = colored("[*] Hashing algorithm:", heading_color)
    print(f"{hash_algorithm_heading} {_hash.hash_type}")

    try:
        virustotal_results(_hash, heading_color)
    except AttributeError:
        cprint("[!] There was an error displaying the VirusTotal report.", "red")

    try:
        malwarebazaar_results(_hash, heading_color)
    except AttributeError:
        cprint("[!] There was an error diplaying the MalwareBazaar report.", "red")


@click.command()
@click.argument("ioc")
@click.option("--config", required=False, type=str)
def run(ioc, config):
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

if __name__ == "__main__":
    run()
