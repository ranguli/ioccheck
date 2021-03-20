import pytest


class TestHashReport:
    class TestVirusTotalReport:
        @pytest.mark.secret
        def test_detections_exist(self, ioccheck_eicar_report_virus_total):
            assert ioccheck_eicar_report_virus_total.reports.virustotal.detections

        @pytest.mark.secret
        def test_detections_malwarebytes(self, ioccheck_eicar_report_virus_total):
            """ Malwarebytes is known not to detect EICAR """
            assert (
                ioccheck_eicar_report_virus_total.reports.virustotal.detections.get(
                    "Malwarebytes"
                ).get("category")
                == "undetected"
            )

        @pytest.mark.secret
        def test_detections_sophos(self, ioccheck_eicar_report_virus_total):
            """ Sophos is known to detect EICAR """
            assert (
                ioccheck_eicar_report_virus_total.reports.virustotal.detections.get(
                    "Sophos"
                ).get("category")
                == "malicious"
            )

        @pytest.mark.secret
        def test_investigation_url(self, ioccheck_eicar_report_virus_total):
            assert (
                ioccheck_eicar_report_virus_total.reports.virustotal.investigation_url
                == "https://virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/"
            )

    class TestMalwareBazaarReport:
        @pytest.mark.secret
        def test_other_hashes(self, ioccheck_emotet_report_malwarebazaar):
            assert ioccheck_emotet_report_malwarebazaar.reports.malwarebazaar.hashes

        @pytest.mark.secret
        def test_other_hashes_2(self, ioccheck_emotet_report_malwarebazaar):
            assert (
                ioccheck_emotet_report_malwarebazaar.reports.malwarebazaar.hashes.get(
                    "sha3_384_hash"
                )
                == "86e1cbf6b132b980d805cd40980070275ba160b19ec1cf3bb97324470601e3bca9a416806d67c7ef76e6217b50638cb1"
            )

        @pytest.mark.secret
        def test_other_hashes_3(self, ioccheck_emotet_report_malwarebazaar):
            assert (
                ioccheck_emotet_report_malwarebazaar.reports.malwarebazaar.hashes.get(
                    "sha1_hash"
                )
                == "476c133118dddb3eeb192c3cfcd90080ebc07662"
            )

        @pytest.mark.secret
        def test_other_hashes_4(self, ioccheck_emotet_report_malwarebazaar):
            assert (
                ioccheck_emotet_report_malwarebazaar.reports.malwarebazaar.hashes.get(
                    "md5_hash"
                )
                == "7258d39f41a2bbf908aa0da116d71785"
            )

        @pytest.mark.secret
        def test_other_hashes_5(self, ioccheck_emotet_report_malwarebazaar):
            assert (
                ioccheck_emotet_report_malwarebazaar.reports.malwarebazaar.hashes.get(
                    "sha256_hash"
                )
                == "526866190c8081698169b4be19a6b987d494604343fe874475126527841c83a7"
            )
