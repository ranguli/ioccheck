# hashcheck

A tool for simplifying the process of researching file hashes.


## Features
* Look up hashes across multiple threat intelligence services, from a single command or a few lines of Python.
* Currenty supports the following services:
  * [VirusTotal](https://virustotal.com)
  * [MalwareBazaar](https://bazaar.abuse.ch/)
* Planned support:
  * [URLhaus](https://urlhaus.abuse.ch/)
  * [OTX](https://otx.alienvault.com/)
  * [InQuest Labs](https://labs.inquest.net/)
  * [MalShare](https://www.malshare.com/)
  * [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
  * [Maltiverse](https://maltiverse.com/)

## Quickstart
```bash
pip install hashcheck
```

You can also run the code directly
```bash
git clone https://github.com/ranguli/hashcheck && cd hashcheck
poetry install
```

## Usage
```
➜  hashcheck 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

Checking hash 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f.
[*] Hashing algorithm:
SHA256

[*] VirusTotal URL:
https://virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/

[*] VirusTotal detections:
61 engines (81%) detected this file.

╒══════════════╤════════════╤═══════════════════════════════╕
│ Antivirus    │ Detected   │ Result                        │
╞══════════════╪════════════╪═══════════════════════════════╡
│ Malwarebytes │ No         │                               │
├──────────────┼────────────┼───────────────────────────────┤
│ Avast        │ Yes        │ EICAR Test-NOT virus!!!       │
├──────────────┼────────────┼───────────────────────────────┤
│ ClamAV       │ Yes        │ Win.Test.EICAR_HDB-1          │
├──────────────┼────────────┼───────────────────────────────┤
│ Kaspersky    │ Yes        │ EICAR-Test-File               │
├──────────────┼────────────┼───────────────────────────────┤
│ BitDefender  │ Yes        │ EICAR-Test-File (not a virus) │
├──────────────┼────────────┼───────────────────────────────┤
│ Paloalto     │ No         │                               │
├──────────────┼────────────┼───────────────────────────────┤
│ TrendMicro   │ Yes        │ Eicar_test_file               │
├──────────────┼────────────┼───────────────────────────────┤
│ FireEye      │ Yes        │ EICAR-Test-File (not a virus) │
├──────────────┼────────────┼───────────────────────────────┤
│ Sophos       │ Yes        │ EICAR-AV-Test                 │
├──────────────┼────────────┼───────────────────────────────┤
│ Microsoft    │ Yes        │ Virus:DOS/EICAR_Test_File     │
├──────────────┼────────────┼───────────────────────────────┤
│ McAfee       │ Yes        │ EICAR test file               │
├──────────────┼────────────┼───────────────────────────────┤
│ Fortinet     │ Yes        │ EICAR_TEST_FILE               │
├──────────────┼────────────┼───────────────────────────────┤
│ AVG          │ Yes        │ EICAR Test-NOT virus!!!       │
╘══════════════╧════════════╧═══════════════════════════════╛

[*] VirusTotal reputation:
3392
```

## Using the API

Creating a hash
```python
>>> from hashcheck import Hash
>>> from hashcheck.services import VirusTotal
>>> eicar = Hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
>>> # What kind of hash is this?
>>> print(eicar.hash_type)
SHA256
```

Looking up a hash
```python
>>> # With no arguments, check() tries all supported services. API keys grabbed from ~/.hashcheck by default.
>>> eicar.check()
>>> # Alternatively:
>>> eicar.check(services=VirusTotal, config_path=/foo/bar/.hashcheck)
```

Researching a hash
```python
>>> # Check the VirusTotal report to see if Sophos detects our hash
>>> eicar.reports.virustotal.get_detections(engines=["Sophos"])
{'Sophos': {'category': 'malicious', 'engine_name': 'Sophos', 'engine_version': '1.0.2.0', 'result': 'EICAR-AV-Test', 'method': 'blacklist', 'engine_update': '20210314'}}
>>> # What is this hash known as?
>>> print(eicar.reports.virustotal.name)
'eicar.com-2224'
>>> # How many AV engines are detecting this hash?
>>> eicar.reports.virustotal.detection_count
60
```


```
>>> # Just show me the VirusTotal API response!
>>> eicar.reports.virustotal.api_response
<vt.object.Object file 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f>
```
