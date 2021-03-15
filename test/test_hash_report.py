import pytest


class TestHashReport:
    class TestVirusTotalReport:
        @pytest.mark.secret
        def test_detections_exist(self, hashcheck_eicar_report_virus_total):
            assert hashcheck_eicar_report_virus_total.reports.virustotal.detections

        @pytest.mark.secret
        def test_detections_malwarebytes(self, hashcheck_eicar_report_virus_total):
            """ Malwarebytes is known not to detect EICAR """
            assert (
                hashcheck_eicar_report_virus_total.reports.virustotal.detections.get(
                    "Malwarebytes"
                ).get("category")
                == "undetected"
            )

        @pytest.mark.secret
        def test_detections_sophos(self, hashcheck_eicar_report_virus_total):
            """ Sophos is known to detect EICAR """
            assert (
                hashcheck_eicar_report_virus_total.reports.virustotal.detections.get(
                    "Sophos"
                ).get("category")
                == "malicious"
            )

        @pytest.mark.secret
        def test_investigation_url(self, hashcheck_eicar_report_virus_total):
            assert (
                hashcheck_eicar_report_virus_total.reports.virustotal.investigation_url
                == "https://virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/"
            )
