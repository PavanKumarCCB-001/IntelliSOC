import csv
from pathlib import Path

# Find the IntelliSOC project directory
BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "attack_events.csv"
OUTPUT_FILE = BASE_DIR / "data" / "detected_events.csv"

def calculate_risk(event):
    score = 0

    description = event["description"].lower()
    indicator = event["indicator"].lower()
    event_type = event["event_type"]

    # Unknown or untrusted source indicators
    if any(word in indicator for word in [
        "unknown",
        "untrusted",
        "unfamiliar",
        "unapproved"
    ]):
        score += 10

    # Urgency, fear or pressure
    if any(word in indicator for word in [
        "urgent",
        "urgency",
        "fear",
        "pressure",
        "suspension",
        "immediately"
    ]):
        score += 10

    # Credential or password-related requests
    if any(word in description for word in [
        "password",
        "credential",
        "login details",
        "account details"
    ]):
        score += 20

    # Suspicious URL/domain indicators
    if event_type == "Suspicious URL":
        score += 20

    # USB-related indicators
    if event_type == "USB Insertion":
        score += 20

    # DNS-related indicators
    if event_type == "Unusual DNS Request":
        score += 20

    # Suspicious attachment
    if event_type == "Suspicious Attachment":
        score += 20
    
    # Executable or script attachment
    if any(word in indicator for word in [
        "executable",
        "script"
    ]):
        score += 30

        # Executable/script attachments are treated as high-severity indicators
        if event_type == "Suspicious Attachment":
            score += 20

    # Repeated login failures
    if event_type == "Repeated Login Failure":
        failed_attempts = int(event["failed_attempts"])

        # Maximum contribution from login failures = 30
        score += min(failed_attempts * 5, 30)

    # Cap the score at 100
    score = min(score, 100)

    # Convert score into risk level
    if score <= 30:
        risk_level = "Low Risk"
    elif score <= 60:
        risk_level = "Medium Risk"
    else:
        risk_level = "High Risk"

    return score, risk_level

def detect_events():
    detected_events = []

    with open(INPUT_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for event in reader:
            score, risk_level = calculate_risk(event)

            event["risk_score"] = score
            event["risk_level"] = risk_level

            detected_events.append(event)

    return detected_events

def save_detected_events(events):
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
        "risk_level"
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(events)

if __name__ == "__main__":
    events = detect_events()
    save_detected_events(events)
    print("Detection completed successfully!")
    print(f"Events analyzed: {len(events)}")
    print(f"Results saved to: {OUTPUT_FILE}")