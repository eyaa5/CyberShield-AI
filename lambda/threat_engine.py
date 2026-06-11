DANGEROUS_ACTIONS = {
    "DeleteBucket": {"severity": "CRITICAL", "score": 95, "category": "Data Destruction"},
    "StopLogging": {"severity": "CRITICAL", "score": 100, "category": "Logging Tampering"},
    "DeleteTrail": {"severity": "CRITICAL", "score": 100, "category": "Logging Tampering"},
    "AuthorizeSecurityGroupIngress": {"severity": "HIGH", "score": 80, "category": "Network Exposure"},
    "CreateAccessKey": {"severity": "HIGH", "score": 75, "category": "Identity Risk"}
}


def calculate_risk_level(score):
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    return "LOW"