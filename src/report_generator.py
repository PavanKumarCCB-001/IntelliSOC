import csv
from pathlib import Path
from collections import Counter

# Find the IntelliSOC project directory
BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "incident_response.csv"
REPORT_FILE = BASE_DIR / "reports" / "incident_report.txt"

def load_incidents():
    with open(INPUT_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return list(reader)

def generate_report(incidents):

    total_events = len(incidents)

    risk_counts = Counter(
        event["risk_level"] for event in incidents
    )

    verification_counts = Counter(
        event["verification_status"] for event in incidents
    )

    event_type_counts = Counter(
        event["event_type"] for event in incidents
    )

    confirmed_incidents = [
        event for event in incidents
        if event["verification_status"] == "Confirmed Incident"
    ]

    report_lines = []

    # --------------------------------------------------
    # REPORT HEADER
    # --------------------------------------------------

    report_lines.append("=" * 70)
    report_lines.append("                 INTELLISOC")
    report_lines.append("     SOCIAL ENGINEERING INCIDENT REPORT")
    report_lines.append("=" * 70)

    # --------------------------------------------------
    # EXECUTIVE SUMMARY
    # --------------------------------------------------

    report_lines.append("\n1. EXECUTIVE SUMMARY")
    report_lines.append("-" * 70)

    report_lines.append(
        f"Total Events Analyzed       : {total_events}"
    )

    report_lines.append(
        f"Low Risk Events             : {risk_counts.get('Low Risk', 0)}"
    )

    report_lines.append(
        f"Medium Risk Events          : {risk_counts.get('Medium Risk', 0)}"
    )

    report_lines.append(
        f"High Risk Events            : {risk_counts.get('High Risk', 0)}"
    )

    report_lines.append(
        f"Confirmed Incidents         : "
        f"{verification_counts.get('Confirmed Incident', 0)}"
    )

    report_lines.append(
        f"Events Requiring Review     : "
        f"{verification_counts.get('Requires Review', 0)}"
    )

    # --------------------------------------------------
    # EVENT TYPE SUMMARY
    # --------------------------------------------------

    report_lines.append("\n2. EVENT TYPE SUMMARY")
    report_lines.append("-" * 70)

    for event_type, count in sorted(event_type_counts.items()):
        report_lines.append(
            f"{event_type:<30} : {count}"
        )

    # --------------------------------------------------
    # INCIDENT RESPONSE WORKFLOW
    # --------------------------------------------------

    report_lines.append("\n3. INCIDENT RESPONSE WORKFLOW")
    report_lines.append("-" * 70)

    report_lines.append("Detection")
    report_lines.append("    ↓")
    report_lines.append("Verification")
    report_lines.append("    ↓")
    report_lines.append("Containment")
    report_lines.append("    ↓")
    report_lines.append("Reporting")
    report_lines.append("    ↓")
    report_lines.append("Recovery")
    report_lines.append("    ↓")
    report_lines.append("Awareness")

    # --------------------------------------------------
    # CONFIRMED INCIDENTS
    # --------------------------------------------------

    report_lines.append("\n4. CONFIRMED INCIDENTS")
    report_lines.append("-" * 70)

    if not confirmed_incidents:

        report_lines.append("No confirmed incidents found.")

    else:

        for event in confirmed_incidents:

            report_lines.append(
                f"\nEvent ID             : {event['event_id']}"
            )

            report_lines.append(
                f"Timestamp            : {event['timestamp']}"
            )

            report_lines.append(
                f"Event Type           : {event['event_type']}"
            )

            report_lines.append(
                f"User                 : {event['user']}"
            )

            report_lines.append(
                f"Risk Score           : {event['risk_score']}"
            )

            report_lines.append(
                f"Risk Level           : {event['risk_level']}"
            )

            report_lines.append(
                f"Attack Type          : {event['attack_type']}"
            )

            report_lines.append(
                f"Possible Victim      : {event['possible_victim']}"
            )

            report_lines.append(
                f"Psychological Method : "
                f"{event['psychological_technique']}"
            )

            report_lines.append(
                f"Technical Indicator  : "
                f"{event['technical_indicator']}"
            )

            report_lines.append(
                f"Potential Impact     : "
                f"{event['potential_impact']}"
            )

            report_lines.append(
                f"Verification         : "
                f"{event['verification_status']}"
            )

            report_lines.append(
                f"Containment          : "
                f"{event['containment_action']}"
            )

            report_lines.append(
                f"Reporting            : "
                f"{event['reporting_action']}"
            )

            report_lines.append(
                f"Recovery             : "
                f"{event['recovery_action']}"
            )

            report_lines.append(
                f"Awareness            : "
                f"{event['awareness_action']}"
            )

            report_lines.append("-" * 70)

    # --------------------------------------------------
    # CONCLUSION
    # --------------------------------------------------

    report_lines.append("\n5. CONCLUSION")
    report_lines.append("-" * 70)

    report_lines.append(
        "IntelliSOC analyzed synthetic social-engineering and "
        "security-related events, classified their risk levels, "
        "identified potential attack characteristics, and applied "
        "a simulated incident-response workflow."
    )

    report_lines.append(
        "The system supports Detection, Verification, Containment, "
        "Reporting, Recovery and Awareness activities without "
        "performing real-world attacks or system modifications."
    )

    report_lines.append("\n" + "=" * 70)
    report_lines.append("                 END OF REPORT")
    report_lines.append("=" * 70)

    return "\n".join(report_lines)

def save_report(report):

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        file.write(report)

if __name__ == "__main__":
    incidents = load_incidents()
    report = generate_report(incidents)
    save_report(report)
    print("Incident report generated successfully!")
    print(f"Events included: {len(incidents)}")
    print(f"Report saved to: {REPORT_FILE}")