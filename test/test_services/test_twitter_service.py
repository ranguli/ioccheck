import inspect
from unittest.mock import Mock, patch

import pytest
import vt
from tweepy import Cursor
from tweepy.error import TweepError

from ioccheck.exceptions import APIError
from ioccheck.iocs import IP
from ioccheck.services import Twitter


class TestTwitter:
    def test_success(self, twitter_report_1):
        assert twitter_report_1

    def test_tweets_exist(self, twitter_report_1):
        assert twitter_report_1.tweets

    def test_tweets_count(self, twitter_report_1):
        assert len(twitter_report_1.tweets) == 13

    def test_tweet_author(self, twitter_report_1):
        assert twitter_report_1.tweets[0].author == "malthe"

    def test_tweet_url(self, twitter_report_1):
        assert (
            twitter_report_1.tweets[0].url
            == "https://twitter.com/twitter/status/1376699296150523904"
        )

    def test_error_chaining(self, ip_1, config_file):
        """Tweepy errors should be caught and chained as our own APIError"""
        with patch("tweepy.Cursor") as MockClass:
            MockClass.side_effect = TweepError("")

            sample = IP(ip_1, config_path=config_file)

            with pytest.raises(APIError):
                sample.check(services=[Twitter])
