#!/usr/bin/env python
""" Exceptions for ioccheck """


class Error(Exception):
    """Generic exception for non-recoverable exceptions."""


class IOCException(Exception):
    """Generic exception raised for issues pertaining to IOCs."""


class IOCNotFoundError(Exception):
    """Raised when can not find an IOC."""


class InvalidHashException(Exception):
    """Raised if a given hash is invalid.

    If an hash string doesn't match any of the regexes provided by
    the support hash types, this exception is thrown.
    """


class InvalidIPException(Exception):
    """Raised if a given IP is invalid.

    If a string isn't a valid IP address, or is not a public
    IP address, this exception is thrown.
    """


class NoConfiguredServicesException(Exception):
    """Raised if there are no services setup with credentials.

    If a config file has no entries for services, this
    exception is thrown
    """


class APIError(Error):
    """Generic API exception that is chained with a library-specific (i.e Shodan or VirusTotal) API exception.

    This is a catch-all for any API error returned by someone else's API.
    """


class InvalidCredentialsError(APIError):
    """Raised if there is some kind of error with credentials.

    If an API returns an authentication error, or no valid credential
    is retrieved for a service from the configuration file, this
    exception is thrown.
    """
