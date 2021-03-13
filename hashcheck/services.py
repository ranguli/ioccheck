#!/usr/bin/env python

import os
import sys
from pathlib import Path

import configparser
import vt

from hashcheck.reports import VirusTotalReport

config_filename = ".hashcheck"


class Service(object):
    def check_hash(self, file_hash):
        return self._get_api_response(file_hash)

    def _get_credentials(self, config_filename: str) -> str:
        config_path = os.path.join(Path.home(), config_filename)

        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            api_key = config[self.name]["API_KEY"]
        except KeyError:
            sys.exit("Could not find necessary API keys in ~/.hashcheck with ")

        return api_key

    def __str__(self):
        return self.name


class VirusTotal(Service):
    def __init__(self, file_hash):
        self.name = "virustotal"
        self.client = vt.Client(self._get_credentials(config_filename))
        self.url = "https://virustotal.com"
        self.response = self._get_api_response(file_hash)
        self.report = self._get_report(file_hash, self.response)

    def _get_api_response(self, file_hash):
        """ Returns the API response in a somewhat common format """
        return self.client.get_object(f"/files/{file_hash}")

    def _get_report(self, file_hash, response):
        return VirusTotalReport(
            name=response.meaningful_name,
            investigation_url=self.__make_investigation_url(self.url, file_hash),
            is_malicious=self.__is_malicious(response),
            detections=self._get_detections(response),
            api_response=response
        )

    def __make_investigation_url(self, url, file_hash):
        return f"{url}/gui/file/{file_hash}/"

    def __is_malicious(self, response):
        return

    def _get_detections(self, response):
        #return {k:v for k,v in response.last_analysis_results.items() if v.get("category") == "malicious"}
        return response.last_analysis_results

        #processed_detections = {}
        #for detection in detections:
        #    print(detection)
        #    if detection.get("category") == "malicious":
        #        processed_detections.update(detection)
        #return processed_detections

    def __str__(self):
        return self.name


all_services = [VirusTotal]
