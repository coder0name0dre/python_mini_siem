import re
import json
from datetime import datetime

LOG_FILE = "logs.txt"
ALERT_OUTPUT = "alerts.json"

# Regex pattern for structured logs
LOG_PATTERN = re.compile(
    r'(?P<timestamp>\d{2}-\d{2}-\d{4}\s\d{2}:\d{2}:\d{2})\s\|\s'
    r'(?P<ip>[\d\.]+)\s\|\s'
    r'(?P<user>\w+)\s\|\s'
    r'(?P<event>\w+)'
)

SUSPICIOUS_EVENTS = [
    "RM_RF",
    "SUDO_FAIL",
    "UNAUTHORISED_ACCESS"
]

def run_siem():
    alerts = []

    with open(LOG_FILE, "r") as logs:
        for line in logs:
            match = LOG_PATTERN.match(line.strip())

            # Skip logs that don't match expected format
            if not match:
                continue

            log = match.groupdict()

            # Convert timestamp string to datetime object
            log["timestamp"] = datetime.strptime(
                log["timestamp"], "%d-%m-%Y %H:%M:%S"
            )

            # Check for suspicious actions
            if log["event"] in SUSPICIOUS_EVENTS:
                alerts.append({
                    "timestamp": log["timestamp"].strftime("%d-%m-%Y %H:%M:%S"),
                    "severity": "MEDIUM",
                    "ip": log["ip"],
                    "user": log["user"],
                    "event": log["event"],
                    "message": "Suspicious command detected"
                })

    with open(ALERT_OUTPUT, "w") as out:
        json.dump(alerts, out, indent=4)

    print(f"Finished. {len(alerts)} alerts saved.")

if __name__ == "__main__":
    run_siem()