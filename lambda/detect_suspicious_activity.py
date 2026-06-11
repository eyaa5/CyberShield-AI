def detect_suspicious_activity(event):
    suspicious_events = []

    for record in event.get("Records", []):
        event_name = record.get("eventName", "")
        source_ip = record.get("sourceIPAddress", "Unknown")

        dangerous_actions = [
            "DeleteBucket",
            "StopLogging",
            "DeleteTrail",
            "AuthorizeSecurityGroupIngress",
            "CreateAccessKey"
        ]

        if event_name in dangerous_actions:
            suspicious_events.append({
                "eventName": event_name,
                "sourceIP": source_ip,
                "severity": "HIGH",
                "message": f"Suspicious AWS activity detected: {event_name}"
            })

    return suspicious_events


sample_event = {
    "Records": [
        {
            "eventName": "CreateAccessKey",
            "sourceIPAddress": "192.168.1.10"
        },
        {
            "eventName": "ListBuckets",
            "sourceIPAddress": "192.168.1.20"
        }
    ]
}

result = detect_suspicious_activity(sample_event)

for alert in result:
    print(alert)