#!/usr/bin/env python


class Service(object):
    def check_hash(self, file_hash):
        return self.__get_api_response(file_hash)

    def __str__(self):
        return self.name
