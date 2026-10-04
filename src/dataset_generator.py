import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)         # Make the generated dataset reproducible

# Find the IntelliSOC project directory
BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_FILE = BASE_DIR / "data" / "attack_events.csv"       # Output file

users = [
    "user_01", "user_02", "user_03", "user_04", "user_05",
    "user_06", "user_07", "user_08", "user_09", "user_10" ]


event_templates = {
    "Phishing Email": [
        (
            "Email claims to be from the IT department and asks the user to verify their password.",
            "Urgent credential verification request"
        ),
        (
            "Email informs the user that their account will be suspended unless they verify immediately.",
            "Account suspension threat"
        ),
        (
            "Email contains a fake security alert asking the user to confirm account details.",
            "Credential harvesting request"
        ),
        (
            "Email impersonates an internal administrator and requests sensitive account information.",
            "Authority impersonation"
        ),
        (
            "Email claims the user has won a company reward and asks them to provide login details.",
            "Reward-based social engineering"
        ),
        (
            "Email creates urgency by claiming suspicious activity was detected on the user's account.",
            "Urgency and fear"
        ),
        (
            "Email requests the user to review an unexpected document through an external link.",
            "Unexpected external link"
        ),
        (
            "Email pretends to be from the HR department and requests immediate employee verification.",
            "HR impersonation"
        ),
        (
            "Email asks the user to reset their password using an unfamiliar website.",
            "Fake password reset"
        ),
        (
            "Email uses a trusted organization name and pressures the user to respond quickly.",
            "Brand impersonation and urgency"
        )
    ],

    "Suspicious URL": [
        (
            "User accessed a URL containing an unfamiliar domain and a login page.",
            "Unknown domain with login form"
        ),
        (
            "A shortened URL redirected the user to an external authentication page.",
            "URL shortener and external login"
        ),
        (
            "URL uses a misspelled version of a commonly used service.",
            "Typosquatting domain"
        ),
        (
            "URL contains a suspicious IP address instead of a normal domain name.",
            "IP-based URL"
        ),
        (
            "User clicked a link with an unusually long and encoded URL.",
            "Encoded URL parameters"
        ),
        (
            "URL redirects through multiple external domains before reaching a login page.",
            "Multiple redirects"
        ),
        (
            "A link received through email points to a newly observed domain.",
            "Newly observed domain"
        ),
        (
            "URL contains a misleading subdomain designed to resemble a trusted website.",
            "Misleading subdomain"
        ),
        (
            "User accessed a website flagged by the security gateway.",
            "Security gateway warning"
        ),
        (
            "A suspicious URL was accessed shortly after a phishing email was received.",
            "URL associated with phishing event"
        )
    ],

    "USB Insertion": [
        (
            "An unknown USB device was connected to a workstation.",
            "Unrecognized USB device"
        ),
        (
            "A removable storage device was inserted outside normal working hours.",
            "After-hours USB insertion"
        ),
        (
            "A USB device with an unknown manufacturer was connected.",
            "Unknown device manufacturer"
        ),
        (
            "Multiple USB devices were connected to the same workstation within a short period.",
            "Repeated USB insertion"
        ),
        (
            "A removable device was connected to a system handling sensitive files.",
            "USB on sensitive workstation"
        ),
        (
            "A USB device was connected by a user who rarely uses removable media.",
            "Unusual user behavior"
        ),
        (
            "A newly detected USB storage device was connected to a workstation.",
            "New removable device"
        ),
        (
            "A USB device was connected immediately before unusual file activity.",
            "USB followed by file activity"
        ),
        (
            "An unapproved removable storage device was detected.",
            "Unauthorized removable media"
        ),
        (
            "A USB device was connected repeatedly within a short time.",
            "Repeated device connection"
        )
    ],

    "Repeated Login Failure": [
        (
            "Multiple unsuccessful login attempts were detected for a user account.",
            "Repeated authentication failures"
        ),
        (
            "A user account experienced several failed login attempts within a short period.",
            "High login failure frequency"
        ),
        (
            "Login failures were detected from an unusual workstation.",
            "Unusual source workstation"
        ),
        (
            "Repeated failed authentication attempts occurred outside normal working hours.",
            "After-hours authentication failures"
        ),
        (
            "A large number of failed logins were detected against one account.",
            "High-volume authentication failures"
        ),
        (
            "Multiple failed login attempts occurred before a successful login.",
            "Failures followed by success"
        ),
        (
            "Login failures originated from an unfamiliar network source.",
            "Unknown network source"
        ),
        (
            "Several authentication failures were detected across a short time interval.",
            "Rapid authentication failures"
        ),
        (
            "An inactive user account experienced repeated login failures.",
            "Inactive account targeting"
        ),
        (
            "Repeated login failures were detected for an administrative account.",
            "Administrative account targeting"
        )
    ],

    "Unusual DNS Request": [
        (
            "Workstation generated DNS requests for an uncommon external domain.",
            "Rare external domain"
        ),
        (
            "A system repeatedly requested resolution for a newly observed domain.",
            "Repeated new-domain requests"
        ),
        (
            "DNS traffic contained an unusually long subdomain.",
            "Long DNS subdomain"
        ),
        (
            "Workstation contacted a domain with a suspicious naming pattern.",
            "Suspicious domain pattern"
        ),
        (
            "Multiple DNS requests were generated for domains not normally used by the organization.",
            "Unusual domain frequency"
        ),
        (
            "A workstation requested DNS resolution for a randomly generated-looking domain.",
            "Random-looking domain"
        ),
        (
            "DNS request was made to an external domain shortly after a suspicious email.",
            "DNS request following phishing"
        ),
        (
            "A system generated repeated requests for a low-reputation domain.",
            "Low-reputation domain"
        ),
        (
            "Unusual DNS activity was detected from a workstation outside normal hours.",
            "After-hours DNS activity"
        ),
        (
            "DNS requests showed an unexpected increase compared with normal activity.",
            "Abnormal DNS frequency"
        )
    ],

    "Suspicious Attachment": [
        (
            "An email contained an unexpected executable attachment.",
            "Executable attachment"
        ),
        (
            "User received an attachment with a double file extension.",
            "Double file extension"
        ),
        (
            "An email attachment was received from an unknown sender.",
            "Unknown sender"
        ),
        (
            "Attachment type was inconsistent with the email description.",
            "Mismatched attachment type"
        ),
        (
            "A compressed archive was received from an untrusted external sender.",
            "Untrusted compressed archive"
        ),
        (
            "An attachment requested the user to enable additional content.",
            "Request to enable content"
        ),
        (
            "A document attachment originated from an unfamiliar external address.",
            "Unfamiliar external sender"
        ),
        (
            "An attachment contained a potentially dangerous script file.",
            "Script file attachment"
        ),
        (
            "A password-protected archive was received unexpectedly.",
            "Unexpected password-protected archive"
        ),
        (
            "An attachment was flagged by the email security gateway.",
            "Email gateway detection"
        )
    ]
}

sources = {
    "Phishing Email": "Email Gateway",
    "Suspicious URL": "Web Security Gateway",
    "USB Insertion": "Endpoint Security",
    "Repeated Login Failure": "Authentication System",
    "Unusual DNS Request": "DNS Monitoring",
    "Suspicious Attachment": "Email Security"
}


# Start timestamp for synthetic events
start_time = datetime(2026, 10, 1, 9, 0, 0)

events = []
event_id = 1

for event_type, templates in event_templates.items():

    for description, indicator in templates:

        user = random.choice(users)

        timestamp = start_time + timedelta(
            minutes=random.randint(0, 3 * 24 * 60)
        )

        # Login failures get a meaningful count.
        # Other event types have zero failed attempts.
        if event_type == "Repeated Login Failure":
            failed_attempts = random.randint(3, 12)
        else:
            failed_attempts = 0

        events.append({
            "event_id": f"EVT{event_id:03d}",
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event_type,
            "user": user,
            "description": description,
            "indicator": indicator,
            "source": sources[event_type],
            "failed_attempts": failed_attempts
        })

        event_id += 1

# Shuffle events so the CSV is not grouped by attack type
random.shuffle(events)

# Create the data directory if it does not exist
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

# Write the dataset to CSV
fieldnames = [
    "event_id",
    "timestamp",
    "event_type",
    "user",
    "description",
    "indicator",
    "source",
    "failed_attempts"
]

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerows(events)

print(f"Dataset generated successfully!")
print(f"Total events: {len(events)}")
print(f"Saved to: {OUTPUT_FILE}")