#!/usr/bin/env python

import click
from hashcheck import Hash
from hashcheck.exceptions import InvalidHashException


@click.command()
@click.argument("file_hash")
def run(file_hash):
    try:
        _hash = Hash(file_hash)
    except InvalidHashException as e:
        print(e)
