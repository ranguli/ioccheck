from .malwarebazaar import MalwareBazaar
from .shodan import Shodan
from .virustotal import VirusTotal

hash_services = [VirusTotal, MalwareBazaar]
ip_services = [Shodan]
