from dataclasses import dataclass


class Service(object):

    def __init__(self, name, description, credentials):
        #self.client
        pass

    def check_hash(self, file_hash):
        return self.__get_api_response(file_hash)

    def __get_api_response(self, file_hash):
        pass

    def __str__(self):
        return self.name


class VirusTotal(Service):

    def __init__(self, credentials):
        self.client = vt.Client(credentials.get("API_KEY"))
        self.url = "https://virustotal.com"

    def __get_api_response(self, file_hash):
        response = client.getobject(f"/files/{file_hash}")

        return VirusTotalReport(
                name=response.meaningful_name,
                investigation_url=self.__make_investigation_url(self.url, file_hash),
                is_malicious=self.__is_malicious(response)
        )

    def __make_investigation_url(self, url, file_hash):
        return f"{url}/gui/file/{file_hash}/{detection}"

    def __is_malicious(self, response):

        detections = self.__process_detections(response.last_analysis_results)
        return

    def __process_detections(self, detections):
        processed_detections = {}
        for detection in detections:
            print(detection)
            if detection.get("category") == "malicious":
                processed_detections.update(detection)
        print(processed_detections)

#['DATE_ATTRIBUTES', 'context_attributes', 'crowdsourced_yara_results', 'first_seen_itw_date', 'first_submission_date', 'from_dict', 'get', 'id', 'last_analysis_date', 'last_analysis_results', 'last_analysis_stats', 'last_modification_date', 'last_submission_date', 'magic', 'md5', 'meaningful_name', 'names', 'popular_threat_classification', 'relationships', 'reputation', 'sandbox_verdicts', 'sha1', 'sha256', 'size', 'ssdeep', 'tags', 'times_submitted', 'tlsh', 'to_dict', 'total_votes', 'trid', 'type', 'type_description', 'type_extension', 'type_tag', 'unique_sources']


@dataclass
class ServiceReport:
    name: str
    investigation_url: str
    is_malicious: bool

#@dataclass
#class VirusTotalReport(ServiceReport):

all_services = [VirusTotal]
