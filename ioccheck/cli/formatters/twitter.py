#!/usr/bin/env python
"""Module provides human-friendly output from Twitter """

import logging
from typing import Optional

from tabulate import tabulate
from termcolor import cprint, colored

from ioccheck.cli.formatters.formatter import Formatter
from ioccheck.services import Twitter

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("ioccheck.log")
f_handler.setLevel(logging.INFO)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)


class TwitterFormatter(Formatter):
    """Provide pre-formatted output from Twitter"""

    def __init__(self, service: Twitter, heading_color: str):
        Formatter.__init__(self, service, heading_color)

    @property
    def tweets(self) -> Optional[str]:
        """Provide pre-formatted output of tweets"""

        for tweet in self.service.tweets:
            author = colored(f"\n@{tweet.author}:", self.heading_color)
            url = colored(tweet.url, self.heading_color)
            print(f"{author} {tweet.text}\n{url}\n")
