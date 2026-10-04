# IntelliSOC

### Social Engineering Attack Detection and Incident Response System

---

## 📌 Project Description

**IntelliSOC** is a Python-based Social Engineering Attack Detection and Incident Response System developed as an educational cybersecurity project.

The system analyzes a synthetic dataset containing different types of suspicious security events, including:

- Phishing Email
- Suspicious URL
- USB Insertion
- Repeated Login Failure
- Unusual DNS Request
- Suspicious Attachment

IntelliSOC uses a **rule-based detection system** to calculate a risk score for every event and classify it into one of three levels:

- **Low Risk**
- **Medium Risk**
- **High Risk**

After detecting an event, the system identifies its attack characteristics, including the attack type, possible victim, psychological technique, technical indicator, and potential impact.

The identified events are then processed through a simulated incident-response workflow:

```text
Detection
    ↓
Verification
    ↓
Containment
    ↓
Reporting
    ↓
Recovery
    ↓
Awareness
```

Finally, IntelliSOC generates an automated incident report containing the important detected incidents and their corresponding response actions.

> **Note:** IntelliSOC uses synthetic data and simulated response actions. It does not perform real-world attacks or modify real systems.

---

# ⚙️ How Risk Detection Works

IntelliSOC uses a **rule-based scoring approach** instead of a machine-learning model.

Each security event contains indicators such as suspicious URLs, unknown sources, authentication failures, suspicious attachments, or other unusual behavior.

The detection engine assigns points according to the predefined rules.

### Risk Score Formula

The general scoring model can be represented as:

```text
Risk Score = Sum of Indicator Scores
```

For events involving repeated login failures, the number of failed attempts also contributes to the score according to the predefined rules.

The final score is bounded by:

```text
Final Risk Score = min(Risk Score, 100)
```

Therefore, the maximum possible risk score is **100**.

### Example

Suppose an event receives points from multiple suspicious indicators:

```text
Indicator 1 = 20 points
Indicator 2 = 20 points
Indicator 3 = 30 points
```

Then:

```text
Risk Score = 20 + 20 + 30
           = 70
```

Therefore:

```text
70 → High Risk
```

---

## 🚦 Risk Classification

The final risk score is classified using the following rules:

| Risk Score | Risk Level |
|------------|------------|
| 0 – 30     | Low Risk |
| 31 – 60    | Medium Risk |
| 61 – 100   | High Risk |

The classification can be represented mathematically as:

```text
Risk Level =
    Low Risk       if 0 ≤ Score ≤ 30
    Medium Risk    if 31 ≤ Score ≤ 60
    High Risk      if 61 ≤ Score ≤ 100
```

### Example

```text
Score = 20
→ Low Risk

Score = 40
→ Medium Risk

Score = 70
→ High Risk
```

This allows IntelliSOC to prioritize events according to their potential severity.

---

# 🔍 Attack Identification

After risk detection, IntelliSOC maps each event to five important security characteristics:

```text
Attack Type
Possible Victim
Psychological Technique
Technical Indicator
Potential Impact
```

For example:

```text
Suspicious Attachment
        ↓
Attack Type: Malicious Attachment
        ↓
Possible Victim: Employee / Email User
        ↓
Psychological Technique: Curiosity, Urgency, Trust
        ↓
Technical Indicator: Script file attachment
        ↓
Potential Impact: Malware infection / Data theft
```

This helps connect the technical event with the **social-engineering technique and possible consequences**.

---

# 🔄 Incident Response Workflow

Once an event has been identified, IntelliSOC applies the following workflow:

```text
                    ┌──────────────────────┐
                    │      Detection       │
                    │  Risk Score & Level  │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │     Verification     │
                    │ Confirmed / Review   │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │     Containment      │
                    │ Simulated Action     │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │      Reporting       │
                    │ Record Incident      │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │       Recovery       │
                    │ Simulated Recovery   │
                    └──────────┬───────────┘
                               ↓
                    ┌──────────────────────┐
                    │      Awareness       │
                    │ Security Guidance    │
                    └──────────────────────┘
```

### Verification Logic

The verification stage uses the detected risk level:

```text
Medium Risk / High Risk
        ↓
Confirmed Incident

Low Risk
        ↓
Requires Review
```

The containment, recovery, and awareness actions are **simulated actions** assigned according to the type of event.

---

# 🏗️ Complete IntelliSOC Architecture

The complete processing pipeline is:

```text
                 ┌─────────────────────────┐
                 │ Synthetic Attack Dataset│
                 │       60 Events         │
                 └────────────┬────────────┘
                              ↓
                 ┌─────────────────────────┐
                 │    Detection Engine     │
                 │  Rule-Based Risk Score  │
                 └────────────┬────────────┘
                              ↓
                 ┌─────────────────────────┐
                 │   Risk Classification   │
                 │ Low / Medium / High     │
                 └────────────┬────────────┘
                              ↓
                 ┌─────────────────────────┐
                 │  Attack Identification  │
                 │ Type / Victim / Impact  │
                 └────────────┬────────────┘
                              ↓
                 ┌─────────────────────────┐
                 │   Incident Response     │
                 │                         │
                 │ Detection               │
                 │ Verification            │
                 │ Containment             │
                 │ Reporting               │
                 │ Recovery                │
                 │ Awareness               │
                 └────────────┬────────────┘
                              ↓
                 ┌─────────────────────────┐
                 │ Automated Incident      │
                 │       Report            │
                 └─────────────────────────┘
```

---

# 📁 Project Structure

```text
IntelliSOC/
│
├── data/
│   ├── attack_events.csv
│   ├── detected_events.csv
│   ├── identified_events.csv
│   └── incident_response.csv
│
├── reports/
│   └── incident_report.txt
│
├── src/
│   ├── dataset_generator.py
│   ├── detector.py
│   ├── attack_identifier.py
│   ├── incident_response.py
│   ├── report_generator.py
│   └── main.py
│
└── README.md
```

---

# 🧩 Project Modules

### 1. `dataset_generator.py`

Generates the synthetic security-event dataset.

The dataset contains 60 events covering six event categories.

Output:

```text
data/attack_events.csv
```

---

### 2. `detector.py`

Analyzes each event using predefined security indicators.

It calculates:

```text
Risk Score
Risk Level
```

Output:

```text
data/detected_events.csv
```

---

### 3. `attack_identifier.py`

Maps each detected event to:

```text
Attack Type
Possible Victim
Psychological Technique
Technical Indicator
Potential Impact
```

Output:

```text
data/identified_events.csv
```

---

### 4. `incident_response.py`

Processes the identified events through the incident-response workflow.

It generates:

```text
Verification Status
Containment Action
Reporting Action
Recovery Action
Awareness Action
```

Output:

```text
data/incident_response.csv
```

---

### 5. `report_generator.py`

Creates the final human-readable incident report.

Output:

```text
reports/incident_report.txt
```

The report contains:

- Total events analyzed
- Risk distribution
- Event categories
- Incident-response workflow
- Confirmed incidents
- Attack characteristics
- Response actions
- Conclusion

---

### 6. `main.py`

Acts as the main entry point of IntelliSOC.

It automatically executes all five stages:

```text
Dataset Generation
        ↓
Detection
        ↓
Attack Identification
        ↓
Incident Response
        ↓
Automated Report Generation
```

---

# ▶️ How to Execute

## Step 1 — Clone the Repo

```
git clone https://github.com/PavanKumarCCB-001/IntelliSOC.git

cd IntelliSOC
```

## Step 2 — Run IntelliSOC

Execute:

```
python src/main.py
```

The complete pipeline will execute automatically.

Expected execution:

```text
[1/5] Generating synthetic attack dataset...

[2/5] Detecting and classifying events...

[3/5] Identifying attack characteristics...

[4/5] Processing incident response workflow...

[5/5] Generating automated incident report...
```

After successful execution, the generated files will be available in:

```text
data/
reports/
```

The final report is:

```text
reports/incident_report.txt
```

---

# 📊 Project Output

For the current synthetic dataset, IntelliSOC analyzes:

```text
Total Events Analyzed : 60
```

Risk distribution:

```text
Low Risk Events       : 56
Medium Risk Events    : 2
High Risk Events      : 2
```

Verification result:

```text
Confirmed Incidents   : 4
Requires Review       : 56
```

The six event categories each contain 10 synthetic events:

```text
Phishing Email          : 10
Suspicious URL          : 10
USB Insertion           : 10
Repeated Login Failure  : 10
Unusual DNS Request     : 10
Suspicious Attachment   : 10
```

---

# 🔐 Security and Ethical Considerations

IntelliSOC is developed strictly for educational and cybersecurity-learning purposes.

The system:

- Uses synthetic security events
- Does not send real phishing emails
- Does not execute malicious attachments
- Does not attack real accounts
- Does not exploit real websites
- Does not modify real systems
- Does not block real network traffic
- Does not perform real containment
- Does not deploy malware

The containment and recovery activities represented by IntelliSOC are **simulated actions** used to demonstrate the incident-response process.

---

# 📝 Conclusion

**IntelliSOC** demonstrates a complete rule-based approach for detecting and responding to social-engineering-related security events.

The system combines:

```text
Synthetic Data Generation
        +
Rule-Based Risk Detection
        +
Risk Classification
        +
Attack Identification
        +
Incident Response
        +
Automated Reporting
```

The project demonstrates how suspicious events can be analyzed using predefined security indicators, assigned a measurable risk score, classified into Low, Medium, or High risk, and processed through a structured incident-response workflow.

Since the project uses synthetic data and simulated response actions, it provides a safe and controlled environment for understanding the fundamentals of **social engineering detection and security incident response**.
