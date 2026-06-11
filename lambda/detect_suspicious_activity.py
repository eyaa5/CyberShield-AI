import json


DANGEROUS_ACTIONS = {
    "DeleteBucket": "CRITICAL",
    "StopLogging": "CRITICAL",
    "DeleteTrail": "CRITICAL",
    "AuthorizeSecurityGroupIngress": "HIGH",
    "CreateAccessKey": "HIGH"
}


def detect_suspicious_activity(event):
    alerts = []

    for record in event.get("Records", []):
        event_name = record.get("eventName", "")
        source_ip = record.get("sourceIPAddress", "Unknown")

        if event_name in DANGEROUS_ACTIONS:
            alerts.append({
                "eventName": event_name,
                "sourceIP": source_ip,
                "severity": DANGEROUS_ACTIONS[event_name],
                "message": f"Suspicious AWS activity detected: {event_name}"
            })

    return alerts


if __name__ == "__main__":
    with open("test-events/sample_cloudtrail_event.json", "r") as file:
        sample_event = json.load(file)

    result = detect_suspicious_activity(sample_event)

    for alert in result:
        print(alert)