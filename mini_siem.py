import re
import json
from datetime import datetime, timedelta

# Configuration #

LOG_FILE = "logs.txt"                      # File containing logs to analyse
THREAT_INTEL_FILE = "threat_intel.txt"     # Known bad IP addresses
ALERT_OUTPUT = "alerts.json"               # Where alerts will be saved

FAILED_LOGIN_THRESHOLD = 3                 # How many failed logins before alert
TIME_WINDOW_SECONDS = 60                   # Time window for brute force detection


# Log Parsing Pattern #

# This regex tells Pyhton how a valid log line looks.

# Regex breaks the line into named pieces:
# timestamp, ip, user, event

LOG_PATTERN = re.compile(
    r'(?P<timestamp>[\d\-:\s]+)\s\|\s'
    r'(?P<ip>[\d\.]+)\s\|\s'
    r'(?P<user>\w+)\s\|\s'
    r'(?P<event>\w+)'
)


# Threat Intelligence Loader #

def load_threat_intel(filename):
# Reads a file containing known malicious IP addresses.

    bad_ips = set()

    with open(filename, "r") as file:
        for line in file:
            bad_ips.add(line.strip())

    return bad_ips


# Log Parser #

def parse_log_line(line):
# Takes one line from the log file and tries to parse it.
# If the log format is correct, it returns a dictionary with fields
# If not, it returns None

    # Try to match the line to our regex pattern
    match = LOG_PATTERN.match(line.strip())

    # If the line doesn't match, ignore it
    if not match:
        return None
    
    # Convert regex match into a dictionary
    log = match.groupdict()

    # Convert timestamp string into a datetime object
    # This allows time comparisons later
    log["timestamp"] = datetime.strptime(
        log["timestamp"],
        # "%d-%m-%Y %H:%M:%S"
        "%d-%m-%Y %H:%M:%S"
    )

    return log


# Alert Creator #

def create_alert(severity, message, log):
# Creates a standardisd alert
# This ensures all alerts have the same structure

    return {
        "timestamp": log["timestamp"].strftime("%d-%m-%Y %H:%M:%S"),
        "severity": severity,
        "ip": log["ip"],
        "user": log["user"],
        "event": log["event"],
        "message": message
    }


# Main SIEM Logic #

def run_siem():

    # Load known malicious IPs
    threat_ips = load_threat_intel(THREAT_INTEL_FILE)

    # This dictionary tracks failed login times per IP
    failed_login_tracker = {}

    # List to store all alrts we generate
    alerts = []

    # Open the log file and read it line by line
    with open(LOG_FILE, "r") as logs:
        for line in logs:

            # Pasrse the current log line
            log = parse_log_line(line)

            # Skip invalid or malformed logs
            if not log:
                continue

            ip = log["ip"]
            event = log["event"]
            timestamp = log["timestamp"]


            # Threat Intelligence Match #

            # If an IP is known bad, we immediately alert.
            if ip in threat_ips:
                alerts.append(
                    create_alert(
                        severity="CRITICAL",
                        message="Connection from known malicious IP",
                        log=log
                    )
                )


            # Brute Force Detection #

            # detect many failed logins in a short time.
            if event == "LOGIN_FAIL":

                # Initialise list if IP not seen before
                if ip not in failed_login_tracker:
                    failed_login_tracker[ip] = []

                # Record this failed attempt time
                failed_login_tracker[ip].append(timestamp)

                # Remove old login attempts outside time window
                failed_login_tracker[ip] = [
                    t for t in failed_login_tracker[ip]
                    if timestamp - t <= timedelta(seconds=TIME_WINDOW_SECONDS)
                ]

                # If failures exceed threshold, alert
                if len (failed_login_tracker[ip]) >= FAILED_LOGIN_THRESHOLD:
                    alerts.append(
                        create_alert(
                            severity="HIGH",
                            message="Multiple failed logins in short time window",
                            log=log
                        )
                    )


            # Suspicious Commands #
            
            # Certain actions are dangerous even once.

            if event in ["RM_RF", "SUDO_FAIL", "UNAUTHORISED_ACCESS"]:                                        
                    alerts.append(
                        create_alert(
                            severity="MEDIUM",
                            message=f"Suspicious command detected: {event}",
                            log=log
                        )
                    )


    # Save Alerts to File #

    with open(ALERT_OUTPUT, "w") as out:
        json.dump(alerts, out, indent=4)

    print(f"\nSIEM finished. {len(alerts)} alerts saved to {ALERT_OUTPUT}")


# Script Entry Point #

if __name__ == "__main__":
    run_siem()