# Python Mini SIEM

This is a Python project that demonstrates how a basic SIEM (Security Information and Event Management) ingests logs, parses events, correlates activity over time, checks threat intelligence and generates security alerts.

---

## Features

- Log ingestion from text files
- Regex based log parsing
- Time window correlation (brute force detection)
- Alert generation with severity levels
- Threat intelligence IP matching
- JSON alert output

---

## How It WOrks

1. Logs are read line by line from `logs.txt`
2. Each log entry is parsed into structured fields
3. Detection rules are applied:
    - Multiple failed logins in a short time window
    - Known malicious IP addresses
    - Suspicious or dangerous commands
4. Alerts are generated and written to `alerts.json`

---

## Example Log Format

Logs follow this format:

DD-MM-YYYY HH:MM:SS | IP_ADDRESS | USERNAME | EVENT

Example:

```
21-01-2026 09:18:30 | 192.168.1.50 | alice | LOGIN_FAIL
```

---

## How To Run

1. Clone the repository:

```
git clone https://github.com/coder0name0dre/python_mini_siem.git
cd python_mini_siem
```

2. Run the mini SIEM:

```
python mini_siem.py
```

After execution, alerts will be written to:

```
alerts.json
```
(automatically created)

### Example Alert Output

```
{
    "timestamp": "21-01-2026 09:18:30",
    "severity": "HIGH",
    "ip": "192.168.1.50",
    "user": "alice",
    "event": "LOGIN_FAIL",
    "message": "Multiple failed logins in short time window"
}
```

---

## License

This project is licensed under the [MIT License](https://github.com/coder0name0dre/python_mini_siem/blob/main/LICENSE).
