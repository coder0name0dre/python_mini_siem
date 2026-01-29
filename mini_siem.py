import re
import json
from datetime import datetime, timedelta

LOG_FILE = "logs.txt"
ALERT_OUTPUT = "alerts.json"

FAILED_LOGIN_THRESHOLD = 3
TIME_WINDOW_SECONDS = 60

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
    failed_logins = {}

    with open(LOG_FILE, "r") as logs:
        for line in logs:
            match = LOG_PATTERN.match(line.strip())
            if not match:
                continue

            log = match.groupdict()
            log["timestamp"] = datetime.strptime(
                log["timestamp"], "%d-%m-%Y %H:%M:%S"
            )

            ip = log["ip"]
            event = log["event"]
            timestamp = log["timestamp"]


            # Brute Force Detection #

            if event == "LOGIN_FAIL":
                if ip not in failed_logins:
                    failed_logins[ip] = []

                failed_logins[ip].append(timestamp)

                # Remove old attempts
                failed_logins[ip] = [
                    t for t in failed_logins[ip]
                    if timestamp - t <= timedelta(seconds=TIME_WINDOW_SECONDS)
                ]

                if len(failed_logins[ip]) >= FAILED_LOGIN_THRESHOLD:
                    alerts.append({
                        "timestamp": timestamp.strftime("%d-%m-%Y %H:%M:%S"),
                        "severity": "HIGH",
                        "ip": ip,
                        "user": log["user"],
                        "event": event,
                        "message": "Multiple failed logins detected"
                    })


            # Suspicious Command Detection #

            if event in SUSPICIOUS_EVENTS:
                alerts.append({
                    "timestamp": timestamp.strftime("%d-%m-%Y %H:%M:%S"),
                    "severity": "MEDIUM",
                    "ip": ip,
                    "user": log["user"],
                    "event": event,
                    "message": "Suspicious command detected"
                })

    with open(ALERT_OUTPUT, "w") as out:
        json.dump(alerts, out, indent=4)

    print(f"Finished. {len(alerts)} alerts saved.")

if __name__ == "__main__":
    run_siem()