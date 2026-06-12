import json

def analyze_event(event_name):
    suspicious = [
        "DeleteTrail",
        "StopLogging",
        "DeleteBucket",
        "DeleteUser",
        "DetachRolePolicy"
    ]

    if event_name in suspicious:
        return f"ALERT: Suspicious action detected -> {event_name}"

    return f"OK: {event_name}"

# Test
print(analyze_event("DeleteBucket"))