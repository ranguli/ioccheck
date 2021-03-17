class InvalidHashException(Exception):
    pass


class InvalidCredentialsException(Exception):
    def __init__(self, service: str):
        self.service = service


class HashNotFoundException(Exception):
    def __init__(self, service: str):
        self.service = service
