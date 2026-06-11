import json

DANGEROUS_ACTIONS = {
    "DeleteBucket": {
        "severity": "CRITICAL",
        "score": 95
    },
    "StopLogging": {
        "severity": "CRITICAL",
        "score": 100
    },
    "DeleteTrail": {
        "severity": "CRITICAL",
        "score": 100
    },
    "AuthorizeSecurityGroupIngress": {
        "severity": "HIGH",
        "score": 80
    },
    "CreateAccessKey": {
        "severity": "HIGH",
        "score": 75
    }
}


def detect_suspicious_activity(event):
    alerts = []

    for record in event.get("Records", []):
        event_name = record.get("eventName", "")
        source_ip = record.get("sourceIPAddress", "Unknown")

        if event_name in DANGEROUS_ACTIONS:
            threat_info = DANGEROUS_ACTIONS[event_name]

            alerts.append({
                "eventName": event_name,
                "sourceIP": source_ip,
                "severity": threat_info["severity"],
                "score": threat_info["score"],
                "message": f"Suspicious AWS activity detected: {event_name}"
            })

    return alerts


def print_alert(alert):
    print("\n SECURITY ALERT")
    print("----------------------------")
    print(f"Event: {alert['eventName']}")
    print(f"Source IP: {alert['sourceIP']}")
    print(f"Severity: {alert['severity']}")
    print(f"Threat Score: {alert['score']}/100")
    print(f"Message: {alert['message']}")


if __name__ == "__main__":
    with open("test-events/sample_cloudtrail_event.json", "r") as file:
        sample_event = json.load(file)

    result = detect_suspicious_activity(sample_event)

    for alert in result:
        print_alert(alert)