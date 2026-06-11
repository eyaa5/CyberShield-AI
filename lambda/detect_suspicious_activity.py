import json
from datetime import datetime
import uuid

DANGEROUS_ACTIONS = {
    "DeleteBucket": {"severity": "CRITICAL", "score": 95, "category": "Data Destruction"},
    "StopLogging": {"severity": "CRITICAL", "score": 100, "category": "Logging Tampering"},
    "DeleteTrail": {"severity": "CRITICAL", "score": 100, "category": "Logging Tampering"},
    "AuthorizeSecurityGroupIngress": {"severity": "HIGH", "score": 80, "category": "Network Exposure"},
    "CreateAccessKey": {"severity": "HIGH", "score": 75, "category": "Identity Risk"}
}


def generate_incident_id():
    return f"INC-{uuid.uuid4().hex[:8].upper()}"


def calculate_risk_level(score):
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def detect_suspicious_activity(event):
    alerts = []

    for record in event.get("Records", []):
        event_name = record.get("eventName", "")
        source_ip = record.get("sourceIPAddress", "Unknown")

        if event_name in DANGEROUS_ACTIONS:
            threat_info = DANGEROUS_ACTIONS[event_name]

            alerts.append({
                "incidentId": generate_incident_id(),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "eventName": event_name,
                "sourceIP": source_ip,
                "severity": threat_info["severity"],
                "score": threat_info["score"],
                "riskLevel": calculate_risk_level(threat_info["score"]),
                "category": threat_info["category"],
                "message": f"Suspicious AWS activity detected: {event_name}"
            })

    return alerts


def create_summary(alerts):
    total_incidents = len(alerts)
    critical_count = sum(1 for alert in alerts if alert["riskLevel"] == "CRITICAL")
    high_count = sum(1 for alert in alerts if alert["riskLevel"] == "HIGH")
    medium_count = sum(1 for alert in alerts if alert["riskLevel"] == "MEDIUM")
    low_count = sum(1 for alert in alerts if alert["riskLevel"] == "LOW")

    average_score = 0
    if total_incidents > 0:
        average_score = sum(alert["score"] for alert in alerts) / total_incidents

    return {
        "totalIncidents": total_incidents,
        "criticalIncidents": critical_count,
        "highIncidents": high_count,
        "mediumIncidents": medium_count,
        "lowIncidents": low_count,
        "averageThreatScore": round(average_score, 2)
    }


def print_alert(alert):
    print("\n SECURITY ALERT")
    print("--------------------------------")
    print(f"Incident ID: {alert['incidentId']}")
    print(f"Timestamp: {alert['timestamp']}")
    print(f"Event: {alert['eventName']}")
    print(f"Source IP: {alert['sourceIP']}")
    print(f"Severity: {alert['severity']}")
    print(f"Category: {alert['category']}")
    print(f"Threat Score: {alert['score']}/100")
    print(f"Risk Level: {alert['riskLevel']}")
    print(f"Message: {alert['message']}")


def print_summary(summary):
    print("\n INCIDENT SUMMARY")
    print("--------------------------------")
    print(f"Total Incidents: {summary['totalIncidents']}")
    print(f"Critical Incidents: {summary['criticalIncidents']}")
    print(f"High Incidents: {summary['highIncidents']}")
    print(f"Medium Incidents: {summary['mediumIncidents']}")
    print(f"Low Incidents: {summary['lowIncidents']}")
    print(f"Average Threat Score: {summary['averageThreatScore']}/100")


def save_incidents_to_report(alerts, summary):
    report = {
        "generatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "incidents": alerts
    }

    with open("reports/incidents.json", "w") as file:
        json.dump(report, file, indent=4)


if __name__ == "__main__":
    with open("test-events/sample_cloudtrail_event.json", "r") as file:
        sample_event = json.load(file)

    result = detect_suspicious_activity(sample_event)
    summary = create_summary(result)

    for alert in result:
        print_alert(alert)

    print_summary(summary)
    save_incidents_to_report(result, summary)

    print("\n Incident report saved to reports/incidents.json")