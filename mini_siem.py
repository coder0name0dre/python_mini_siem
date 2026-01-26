import json

LOG_FILE = "logs.txt"
ALERT_OUTPUT = "alerts.json"

# These events are considered suspicious
SUSPICIOUS_EVENTS = [
    "RM_RF",
    "SUDO_FAIL",
    "UNAUTHORISED_ACCESS"
]

def run_siem():
    alerts = []

    # Open the log file
    with open(LOG_FILE, "r") as logs:
        for line in logs:
            # Split the log line into parts
            # Format: TIMESTAMP | IP | USER | EVENT
            parts = line.strip().split(" | ")

            # Skip malformed logs
            if len(parts) != 4:
                continue

            timestamp, ip, user, event = parts

            # Check if the event is suspicious
            if event in SUSPICIOUS_EVENTS:
                alerts.append({
                    "timestamp": timestamp,
                    "severity": "MEDIUM",
                    "ip": ip,
                    "user": user,
                    "event": event,
                    "message": "Suspicious command detected"
                })

    # Save alerts to JSON
    with open(ALERT_OUTPUT, "w") as out:
        json.dump(alerts, out, indent=4)

    print(f"Finished. {len(alerts)} alerts saved.")

if __name__ == "__main__":
    run_siem()
