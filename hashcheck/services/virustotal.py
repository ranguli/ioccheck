from contextlib import redirect_stdout, redirect_stderr
import io
import logging

from ratelimit import limits, RateLimitException
from backoff import on_exception, expo
import vt

from hashcheck.services.service import Service
from hashcheck.reports import VirusTotalReport

logger = logging.getLogger()
logging.basicConfig(
    filename="hashcheck.log", format="%(levelname)s:%(message)s", level=logging.DEBUG
)
logger.setLevel(logging.INFO)


class VirusTotal(Service):
    name = "virustotal"

    def __init__(self, file_hash, api_key):
        self.client = vt.Client(api_key)
        self.url = "https://virustotal.com"
        self.response = self._get_api_response(file_hash)
        self.report = self._get_report(file_hash, self.response)

    @on_exception(expo, RateLimitException, max_tries=10, max_time=80)
    @limits(calls=4, period=60)
    def _get_api_response(self, file_hash):
        result = None
        f = io.StringIO()
        with redirect_stdout(f), redirect_stderr(f):
            result = self.client.get_object(f"/files/{file_hash}")
        logging.info(f"Received {result} from VirusTotal API")

        return result

    def _get_report(self, file_hash, response):
        return VirusTotalReport(
            response.meaningful_name,
            self.__make_investigation_url(self.url, file_hash),
            self.__is_malicious(response),
            response,
            self._get_detections(response),
            self._get_reputation(response),
        )

    def __make_investigation_url(self, url, file_hash):
        return f"{url}/gui/file/{file_hash}/"

    def __is_malicious(self, response):
        return

    def _get_detections(self, response):
        return response.last_analysis_results

    def _get_reputation(self, response):
        return response.reputation
