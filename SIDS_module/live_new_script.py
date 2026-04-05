import json
import time

input_file = "/var/log/suricata/eve.json"
output_file = "/home/whoami/Desktop/HYBRID_IDS/SIDS_module/labeled_dataset.json"

EXCLUDED_CATEGORY = "Generic Protocol Command Decode"


def classify_attack(signature):
    sig = signature.upper()

    # -------- RECON --------
    if "-SU" in sig:
        return "RECON", "NMAP UDP SCAN"
    if "-SA" in sig:
        return "RECON", "NMAP ACK SCAN"
    if "-SX" in sig:
        return "RECON", "NMAP XMAS SCAN"
    if "-SS" in sig:
        return "RECON", "NMAP SYN SCAN"
    if "PORT SCAN" in sig:
        return "RECON", "NMAP SCAN"

    # -------- DOS --------
    if "SYN FLOOD" in sig:
        return "DOS", "SYN FLOOD"
    if "ACK FLOOD" in sig:
        return "DOS", "ACK FLOOD"
    if "FIN FLOOD" in sig:
        return "DOS", "FIN FLOOD"
    if "UDP FLOOD" in sig:
        return "DOS", "UDP FLOOD"
    if "PING FLOOD" in sig or "ICMP FLOOD" in sig:
        return "DOS", "PING FLOOD"

    # -------- SQL INJECTION --------
    if "SQLI - OR BOOLEAN" in sig:
        return "SQLI", "SQLI_BOOLEAN_OR"
    if "SQLI - AND BOOLEAN" in sig:
        return "SQLI", "SQLI_BOOLEAN_AND"

    if "DOUBLE DASH COMMENT" in sig:
        return "SQLI", "SQLI_COMMENT_INLINE"
    if "BLOCK COMMENT" in sig:
        return "SQLI", "SQLI_COMMENT_BLOCK"

    if "UNION SELECT" in sig:
        return "SQLI", "SQLI_UNION_SELECT"
    if "UNION NULL ENUM" in sig:
        return "SQLI", "SQLI_UNION_ENUM"

    if "BENCHMARK" in sig:
        return "SQLI", "SQLI_TIME_BENCHMARK"
    if "WAITFOR DELAY" in sig:
        return "SQLI", "SQLI_TIME_DELAY"

    if "EXTRACTVALUE" in sig:
        return "SQLI", "SQLI_ERROR_EXTRACTVALUE"
    if "UPDATEXML" in sig:
        return "SQLI", "SQLI_ERROR_UPDATEXML"

    if "SELECT FROM" in sig:
        return "SQLI", "SQLI_GENERIC_SELECT"

    if "OBFUSCATION" in sig or "COMMENT OBFUSCATION" in sig:
        return "SQLI", "SQLI_OBFUSCATED"

    return "UNKNOWN", "UNKNOWN"

def follow(file):
    file.seek(0, 2)  # go to end of file
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line


with open(input_file, "r") as infile, open(output_file, "a") as outfile:

    loglines = follow(infile)

    for line in loglines:
        try:
            event = json.loads(line)

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {})

            if alert.get("category") == EXCLUDED_CATEGORY:
                continue

            signature = alert.get("signature", "")

            attack_type, attack_subtype = classify_attack(signature)

            record = {
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "src_port": event.get("src_port"),
                "dest_ip": event.get("dest_ip"),
                "dest_port": event.get("dest_port"),
                "signature": signature,
                "category": alert.get("category"),
                "severity": alert.get("severity"),
                "type": attack_type,
                "subtype": attack_subtype,
                "source":"SIDS",
                "label":"attack"
            }

            outfile.write(json.dumps(record) + "\n")
            outfile.flush()   # IMPORTANT → real-time write

        except json.JSONDecodeError:
            continue
