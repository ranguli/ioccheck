#!/usr/bin/env python

import click
from hashcheck import Hash
from hashcheck.exceptions import InvalidHashException

from termcolor import colored, cprint

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

cprint(banner, "blue")


@click.command()
@click.argument("file_hash")
def run(file_hash):
    try:
        _hash = Hash(file_hash)
        print(_hash)
    except InvalidHashException as e:
        print(e)
