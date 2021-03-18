#!/usr/bin/env python

import sys

import click
from termcolor import colored, cprint

from hashcheck import Hash
from hashcheck.exceptions import InvalidHashException
from hashcheck.formatters import MalwareBazaarFormatter, VirusTotalFormatter

banner = """
888                        888               888                        888
888                        888               888                        888
888                        888               888                        888
88888b.   8888b.  .d8888b  88888b.   .d8888b 88888b.   .d88b.   .d8888b 888  888
888 "88b     "88b 88K      888 "88b d88P"    888 "88b d8P  Y8b d88P"    888 .88P
888  888 .d888888 "Y8888b. 888  888 888      888  888 88888888 888      888888K
888  888 888  888      X88 888  888 Y88b.    888  888 Y8b.     Y88b.    888 "88b
888  888 "Y888888  88888P' 888  888  "Y8888P 888  888  "Y8888   "Y8888P 888  888

                                                                           0.1.0
https://github.com/ranguli/hashcheck
"""

heading_color = "blue"

cprint(banner, heading_color)


@click.command()
@click.argument("file_hash")
def run(file_hash):
    printed_hash = colored(file_hash, heading_color)
    print(f"Checking hash {printed_hash}.\n")

    try:
        _hash = Hash(file_hash)
        _hash.check()
    except InvalidHashException as e:
        sys.exit(e)

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
