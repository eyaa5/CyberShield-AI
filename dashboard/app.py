import json

def load_incident_report():
    with open("reports/incidents.json", "r") as file:
        return json.load(file)

def print_dashboard(report):
    summary = report["summary"]
    incidents = report["incidents"]

    print("\nCYBERSHIELD AI DASHBOARD")
    print("=" * 40)
    print(f"Total Incidents: {summary['totalIncidents']}")
    print(f"Critical Incidents: {summary['criticalIncidents']}")
    print(f"High Incidents: {summary['highIncidents']}")
    print(f"Average Threat Score: {summary['averageThreatScore']}/100")

    print("\nRECENT INCIDENTS")
    print("-" * 40)

    for incident in incidents:
        print(f"Incident ID: {incident['incidentId']}")
        print(f"Event: {incident['eventName']}")
        print(f"Risk Level: {incident['riskLevel']}")
        print(f"Category: {incident['category']}")
        print("-" * 40)

if __name__ == "__main__":
    report = load_incident_report()
    print_dashboard(report)