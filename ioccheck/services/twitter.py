#!/usr/bin/env python
""" Represents response from the VirusTotal API """

from dataclasses import dataclass

import tweepy

from ioccheck.exceptions import APIError
from ioccheck.services.service import Service


class Twitter(Service):
    """Represents response from the VirusTotal API

    Attributes:
    name: The name of the service as it should appear in the credentials file
    url: Root URL from which other URLs can be created
    required_credentials: Names of credentials that must be found in the credentials file
    """

    name = "twitter"
    url = "https://twitter.com"
    required_credentials = [
        "consumer_key",
        "consumer_secret",
        "access_token",
        "access_secret",
    ]
    auth_errors = [tweepy.error.TweepError]

    def __init__(self, ioc, credentials):
        Service.__init__(self, ioc, credentials)

    def _get_api_response(self, ioc: str) -> dict:
        auth = tweepy.OAuthHandler(
            self.credentials.consumer_key, self.credentials.consumer_secret
        )
        auth.set_access_token(
            self.credentials.access_token, self.credentials.access_secret
        )
        api = tweepy.API(auth, wait_on_rate_limit=True)

        try:
            tweets = tweepy.Cursor(
                api.search,
                q=f'"{self.ioc}" -filter:retweets',
                lang="en",
                tweet_mode="extended",
            ).items(20)
            return {
                "tweets": [tweet for tweet in tweets if self.ioc in tweet.full_text]
            }
        except tweepy.error.TweepError as error:
            raise APIError from error

    @property
    def tweets(self):
        return [
            Tweet(
                author=tweet.author.screen_name,
                date=tweet.created_at,
                text=tweet.full_text,
                url=f"{self.url}/twitter/status/{tweet.id}",
            )
            for tweet in self.response.get("tweets")
        ]


@dataclass
class Tweet:
    author: str
    date: str
    text: str
    url: str
