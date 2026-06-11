import json
from datetime import datetime


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


def save_incidents_to_report(alerts, summary):
    report = {
        "generatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "incidents": alerts
    }

    with open("reports/incidents.json", "w") as file:
        json.dump(report, file, indent=4)