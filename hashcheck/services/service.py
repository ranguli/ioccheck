from dataclasses import dataclass

class Service(object):

    def __init__(self):
        pass

    def check_hash(self):
        pass


@dataclass
class Report:
    url: str
    malicious: bool
    api_response: dict
