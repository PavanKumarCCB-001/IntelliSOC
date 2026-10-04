import csv
from pathlib import Path

# Find the IntelliSOC project directory
BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "detected_events.csv"
OUTPUT_FILE = BASE_DIR / "data" / "identified_events.csv"

# Attack identification mappings
ATTACK_MAPPINGS = {

    "Phishing Email": {
        "attack_type": "Credential Phishing",
        "possible_victim": "Employee / Account Holder",
        "psychological_technique": "Urgency, Fear, Authority",
        "potential_impact": "Credential theft / Account compromise"
    },

    "Suspicious URL": {
        "attack_type": "Phishing / Malicious URL",
        "possible_victim": "Employee / Web User",
        "psychological_technique": "Curiosity, Urgency, Trust",
        "potential_impact": "Credential theft / Malware delivery"
    },

    "USB Insertion": {
        "attack_type": "Malicious Removable Media",
        "possible_victim": "Employee / Workstation",
        "psychological_technique": "Curiosity, Trust",
        "potential_impact": "Malware infection / Data theft"
    },

    "Repeated Login Failure": {
        "attack_type": "Credential Attack",
        "possible_victim": "User Account / Administrator",
        "psychological_technique": "Persistence / Account targeting",
        "potential_impact": "Account compromise / Account lockout"
    },

    "Unusual DNS Request": {
        "attack_type": "DNS-based Suspicious Activity",
        "possible_victim": "Employee Workstation / Network",
        "psychological_technique": "Deception / Concealment",
        "potential_impact": "Malware communication / Data exfiltration"
    },

    "Suspicious Attachment": {
        "attack_type": "Malicious Attachment",
        "possible_victim": "Employee / Email User",
        "psychological_technique": "Curiosity, Urgency, Trust",
        "potential_impact": "Malware infection / Data theft"
    }
}

def identify_attacks():
    identified_events = []

    with open(INPUT_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for event in reader:

            event_type = event["event_type"]

            mapping = ATTACK_MAPPINGS.get(event_type)

            if mapping:
                event["attack_type"] = mapping["attack_type"]
                event["possible_victim"] = mapping["possible_victim"]
                event["psychological_technique"] = mapping["psychological_technique"]

                # Use the actual indicator observed in the dataset
                event["technical_indicator"] = event["indicator"]

                event["potential_impact"] = mapping["potential_impact"]

                identified_events.append(event)

    return identified_events

def save_identified_events(events):

    fieldnames = [
        "event_id",
        "timestamp",
        "event_type",
        "user",
        "description",
        "indicator",
        "source",
        "failed_attempts",
        "risk_score",
        "risk_level",
        "attack_type",
        "possible_victim",
        "psychological_technique",
        "technical_indicator",
        "potential_impact"
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:

        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(events)

if __name__ == "__main__":
    events = identify_attacks()
    save_identified_events(events)

    print("Attack identification completed successfully!")
    print(f"Events identified: {len(events)}")
    print(f"Results saved to: {OUTPUT_FILE}")