#!/usr/bin/env python
""" Exceptions for ioccheck """


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


class InvalidCredentialsException(Exception):
    """Raised if there is some kind of error with credentials.

    If an API returns an authentication error, or no valid credential
    is retrieved for a service from the configuration file, this
    exception is thrown.
    """
