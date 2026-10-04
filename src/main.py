import subprocess
import sys
from pathlib import Path

# Find the IntelliSOC project directory
BASE_DIR = Path(__file__).resolve().parent.parent

def run_module(module_name):
    """Run one IntelliSOC module."""

    module_path = BASE_DIR / "src" / module_name

    result = subprocess.run(
        [sys.executable, str(module_path)],
        capture_output=True,
        text=True    )

    print(result.stdout)

    if result.returncode != 0:
        print(result.stderr)
        raise RuntimeError(
            f"{module_name} failed to execute."
        )

def main():

    print("=" * 60)
    print("                 INTELLISOC")
    print(" Social Engineering Detection & Response System")
    print("=" * 60)

    print("\n[1/5] Generating synthetic attack dataset...")
    run_module("dataset_generator.py")

    print("\n[2/5] Detecting and classifying events...")
    run_module("detector.py")

    print("\n[3/5] Identifying attack characteristics...")
    run_module("attack_identifier.py")

    print("\n[4/5] Processing incident response workflow...")
    run_module("incident_response.py")

    print("\n[5/5] Generating automated incident report...")
    run_module("report_generator.py")

    print("\n" + "=" * 60)
    print("INTELLISOC PIPELINE COMPLETED SUCCESSFULLY")
    print("=" * 60)
    print("\nGenerated files:")
    print("  data/attack_events.csv")
    print("  data/detected_events.csv")
    print("  data/identified_events.csv")
    print("  data/incident_response.csv")
    print("  reports/incident_report.txt")
    print("\nIntelliSOC processing complete!")

if __name__ == "__main__":
    main()