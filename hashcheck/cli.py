#!/usr/bin/env python

import click
from termcolor import colored, cprint

from hashcheck import Hash
from hashcheck.exceptions import InvalidHashException
from hashcheck.formatters import VirusTotalFormatter


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
    print(f"Checking hash {file_hash}.\n")

    try:
        _hash = Hash(file_hash)
        _hash.check()

    except InvalidHashException as e:
        print(e)

    hash_algorithm_heading = colored("[*] Hashing algorithm:", heading_color)
    print(f"{hash_algorithm_heading} {_hash.hash_type}")

    virustotal = _hash.reports.virustotal
    virustotal_formatter = VirusTotalFormatter(virustotal)

    # Return most popular AV providers
    investigation_url_heading = colored("[*] VirusTotal URL:", heading_color)
    print(f"{investigation_url_heading} {virustotal.investigation_url}")

    # Make a pretty table of the results
    cprint("[*] VirusTotal detections:", "blue")
    print(virustotal_formatter.detections)

    reputation_heading = colored("[*] VirusTotal reputation:", "blue")
    print(f"{reputation_heading} {virustotal_formatter.reputation}")
