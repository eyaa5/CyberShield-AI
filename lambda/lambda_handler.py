import json
import uuid
from datetime import datetime

from threat_engine import DANGEROUS_ACTIONS, calculate_risk_level
from report_generator import create_summary, save_incidents_to_report
from email_alert import send_email_alert


def generate_incident_id():
    return f"INC-{uuid.uuid4().hex[:8].upper()}"


def detect_suspicious_activity(event):
    alerts = []

    for record in event.get("Records", []):
        event_name = record.get("eventName", "")
        source_ip = record.get("sourceIPAddress", "Unknown")

        if event_name in DANGEROUS_ACTIONS:
            threat_info = DANGEROUS_ACTIONS[event_name]

            alert = {
                "incidentId": generate_incident_id(),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "eventName": event_name,
                "sourceIP": source_ip,
                "severity": threat_info["severity"],
                "score": threat_info["score"],
                "riskLevel": calculate_risk_level(threat_info["score"]),
                "category": threat_info["category"],
                "message": f"Suspicious AWS activity detected: {event_name}"
            }

            alerts.append(alert)

            if alert["riskLevel"] == "CRITICAL":
                send_email_alert(alert)

    return alerts


def lambda_handler(event, context=None):
    alerts = detect_suspicious_activity(event)
    summary = create_summary(alerts)
    save_incidents_to_report(alerts, summary)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "CyberShield AI detection completed",
            "summary": summary
        })
    }


if __name__ == "__main__":
    with open("test-events/sample_cloudtrail_event.json", "r") as file:
        sample_event = json.load(file)

    response = lambda_handler(sample_event)
    print(response)