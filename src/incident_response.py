import csv
from pathlib import Path

# Find the IntelliSOC project directory
BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "identified_events.csv"
OUTPUT_FILE = BASE_DIR / "data" / "incident_response.csv"

# Incident response actions for each event type
RESPONSE_MAPPINGS = {

    "Phishing Email": {
        "verification": "Verify sender, links and message indicators",
        "containment": "Quarantine suspicious email",
        "reporting": "Record phishing incident",
        "recovery": "Reset credentials if required",
        "awareness": "Provide phishing-awareness training"
    },

    "Suspicious URL": {
        "verification": "Verify domain, redirects and URL indicators",
        "containment": "Block or isolate suspicious URL",
        "reporting": "Record malicious-URL incident",
        "recovery": "Restore affected browser or session",
        "awareness": "Provide safe-link and URL awareness"
    },

    "USB Insertion": {
        "verification": "Verify device identity and authorization",
        "containment": "Isolate unauthorized USB device",
        "reporting": "Record removable-media incident",
        "recovery": "Scan workstation and restore affected files if required",
        "awareness": "Provide removable-media security training"
    },

    "Repeated Login Failure": {
        "verification": "Review login source, time and failure count",
        "containment": "Temporarily restrict suspicious account activity",
        "reporting": "Record authentication incident",
        "recovery": "Reset credentials and restore account access if required",
        "awareness": "Provide password and account-security awareness"
    },

    "Unusual DNS Request": {
        "verification": "Verify domain reputation and DNS behavior",
        "containment": "Isolate suspicious network activity",
        "reporting": "Record DNS-security incident",
        "recovery": "Scan the affected workstation",
        "awareness": "Provide DNS and safe-browsing awareness"
    },

    "Suspicious Attachment": {
        "verification": "Verify sender, file type and attachment indicators",
        "containment": "Quarantine suspicious attachment",
        "reporting": "Record attachment incident",
        "recovery": "Scan affected system and restore files if required",
        "awareness": "Provide attachment-security awareness"
    }
}

def verify_event(risk_level):
    """
    Determine the verification status based on risk level.
    """

    if risk_level in ["High Risk", "Medium Risk"]:
        return "Confirmed Incident"

    return "Requires Review"

def process_incidents():
    incidents = []

    with open(INPUT_FILE, "r", newline="", encoding="utf-8") as file:

        reader = csv.DictReader(file)

        for event in reader:

            event_type = event["event_type"]
            risk_level = event["risk_level"]

            mapping = RESPONSE_MAPPINGS.get(event_type)

            if mapping:

                event["verification_status"] = verify_event(risk_level)

                event["containment_action"] = mapping["containment"]

                event["reporting_action"] = mapping["reporting"]

                event["recovery_action"] = mapping["recovery"]

                event["awareness_action"] = mapping["awareness"]

                incidents.append(event)

    return incidents

def save_incident_response(incidents):

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
        "potential_impact",
        "verification_status",
        "containment_action",
        "reporting_action",
        "recovery_action",
        "awareness_action"
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:

        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(incidents)

if __name__ == "__main__":
    incidents = process_incidents()
    save_incident_response(incidents)

    print("Incident response processing completed successfully!")
    print(f"Incidents processed: {len(incidents)}")
    print(f"Results saved to: {OUTPUT_FILE}")