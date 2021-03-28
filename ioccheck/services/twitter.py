#!/usr/bin/env python
""" Represents response from the VirusTotal API """

from dataclasses import dataclass
from typing import Optional

import tweepy

from ioccheck.services.service import Service


class Twitter(Service):
    """ Represents response from the VirusTotal API """

    name = "twitter"
    url = "https://twitter.com"

    def __init__(self, ioc, credentials):
        Service.__init__(self, ioc, credentials)

        try:
            self.response = self._get_api_response(self.ioc, credentials)
        except tweepy.error.TweepError:
            return

    def _get_api_response(self, ioc: str, credentials: dict) -> Optional[dict]:
        consumer_key = credentials.get("consumer_key")
        consumer_key_secret = credentials.get("consumer_key_secret")
        access_token = credentials.get("access_token")
        access_token_secret = credentials.get("access_token_secret")

        auth = tweepy.OAuthHandler(consumer_key, consumer_key_secret)
        auth.set_access_token(access_token, access_token_secret)
        api = tweepy.API(auth, wait_on_rate_limit=True)

        try:
            tweets = tweepy.Cursor(
                api.search,
                q=f"{self.ioc} -filter:retweets",
                lang="en",
                tweet_mode="extended",
            ).items()
            return {"tweets": [tweet for tweet in tweets if not tweet.retweeted]}
        except tweepy.error.TweepError:
            return {}

    @property
    def tweets(self):
        return [
            Tweet(
                author=tweet.author.screen_name,
                date=tweet.created_at,
                text=tweet.full_text,
                url=f"https://twitter.com/twitter/status/{tweet.id}",
            )
            for tweet in self.response.get("tweets")
        ]


@dataclass
class Tweet:
    author: str
    date: str
    text: str
    url: str
