#!/usr/bin/env python
""" Represents response from the VirusTotal API """

import tweepy

from ioccheck.exceptions import APIError
from ioccheck.services.service import Service
from ioccheck.shared import Tweet


class Twitter(Service):  # pylint: disable=too-few-public-methods
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

            results = []
            for tweet in tweets:
                if self.ioc in tweet.full_text:
                    results.append(self._create_result(tweet))
            return {"tweets": results}

        except tweepy.error.TweepError as error:
            raise APIError from error

    def _create_result(self, tweet: tweepy.models.Status):
        return {
            "author": tweet.author.screen_name,
            "date": str(tweet.created_at),
            "text": tweet.full_text,
            "url": f"{self.url}/twitter/status/{tweet.id}",
        }

    @property
    def tweets(self):
        """Tweets that reference the IOC directly by name"""
        return [
            Tweet(
                author=tweet.get("author"),
                date=tweet.get("date"),
                text=tweet.get("text"),
                url=tweet.get("url"),
            )
            for tweet in self.response.get("tweets")
        ]
