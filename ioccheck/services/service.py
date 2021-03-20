#!/usr/bin/env python


class Service(object):
    def __init__(self):
        self.name: str

    def check_hash(self, file_hash):
        return self._get_api_response(file_hash)

    def __str__(self):
        return self.name
