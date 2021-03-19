#!/usr/bin/env python

import sys
import random
import logging

import click
from termcolor import colored, cprint

from pyfiglet import Figlet

from ioccheck import Hash, IP
from ioccheck.exceptions import InvalidHashException, InvalidIPException
from ioccheck.cli.formatters import MalwareBazaarFormatter, VirusTotalFormatter

aiohttp_logger = logging.getLogger("aiohttp")
aiohttp_logger.propagate = False
aiohttp_logger.enabled = False
aiohttp_logger.setLevel(logging.WARNING)

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

figlet = Figlet(font=random.choice(fonts))  # nosec
heading_color = "blue"

cprint(figlet.renderText("ioccheck"), heading_color)
cprint("v0.1.0 (https://github.com/ranguli/ioccheck)\n", heading_color)

def hash_results(_hash, heading_color):
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

ioc_types = [
    {"name": "file hash", "ioc": Hash, "exception": InvalidHashException, "results": hash_results},
    {"name": "IP address", "ioc": IP, "exception": InvalidIPException}
]


@click.command()
@click.argument("ioc")
def run(ioc):
    printed_ioc = colored(ioc, heading_color)
    # print(f"Checking IOC {printed_ioc}.\n")

    check_message = "[*] Checking if IOC is a"
    fail_message = "[!] IOC is not a"

    for ioc_type in ioc_types:
        try:
            cprint(f"{check_message} {ioc_type.get('name')}.", heading_color)
            ioc = ioc_type.get("ioc")(ioc)
            ioc.check()
            ioc_type.get("results")(ioc, heading_color)
            break
        except ioc_type.get("exception"):
            cprint(f"{fail_message} {ioc_type.get('name')}.", "yellow")
