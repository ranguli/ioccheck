import sys
from hashcheck import Hash
from hashcheck.services import VirusTotal
from termcolor import colored, cprint
from tabulate import tabulate


def main():
    my_hash = Hash(sys.argv[1])

    print(f"Checking hash {sys.argv[1]}.")

    # is a {my_hash.hash_type} sum")
    cprint("[*] Hashing algorithm:", "blue")
    print(f"{my_hash.hash_type}\n")

    my_hash.check(services=VirusTotal)
    virustotal = my_hash.reports.virustotal

    # Return most popular AV providers
    detections = virustotal.get_detections()

    cprint("[*] VirusTotal URL:", "blue")
    print(f"{virustotal.investigation_url}\n")

    # Make a pretty table of the results
    cprint("[*] VirusTotal detections:", "blue")

    detection_count_string = f"{virustotal.detection_count} engines ({virustotal.detection_coverage*100}%) detected this file.\n"
    if virustotal.detection_count == 0:
        detection_count_string = colored(detection_count_string, "green")
    elif virustotal.detection_count > 0:
        detection_count_string = colored(detection_count_string, "red")

    print(detection_count_string)

    table = [["Antivirus", "Detected", "Result"]]

    for detection, result in detections.items():
        if result.get("category") == "malicious":
            malicious = colored("Yes", "red")
        else:
            malicious = colored("No", "green")

        table.append([detection, malicious, result.get("result")])

    print(tabulate(table, headers="firstrow", tablefmt="fancy_grid"))

    if virustotal.reputation < 0:
        reputation = colored(str(virustotal.reputation), "red")
    elif virustotal.reputation > 0:
        reputation = colored(str(virustotal.reputation), "green")
    else:
        reputation = colored(str(virustotal.reputation), "yellow")

    cprint("\n[*] VirusTotal reputation:", "blue")
    print(reputation)


if __name__ == "__main__":
    main()
