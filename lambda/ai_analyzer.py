def generate_ai_analysis(alert):
    event_name = alert.get("eventName", "Unknown")
    risk_level = alert.get("riskLevel", "Unknown")
    category = alert.get("category", "Unknown")

    if event_name in ["DeleteTrail", "StopLogging"]:
        explanation = "This activity may indicate an attempt to disable AWS logging and hide malicious actions."
        recommendation = "Immediately review the IAM user, preserve CloudTrail logs, and investigate recent account activity."
    elif event_name == "DeleteBucket":
        explanation = "This activity may indicate possible data destruction or unauthorized removal of cloud storage."
        recommendation = "Verify whether the bucket deletion was authorized and check backups or versioning."
    elif event_name == "CreateAccessKey":
        explanation = "This activity may indicate credential creation that could be abused for persistent access."
        recommendation = "Verify the identity that created the access key and rotate credentials if suspicious."
    else:
        explanation = "This activity requires manual security review."
        recommendation = "Review CloudTrail context, IAM permissions, and source IP address."

    return {
        "aiSummary": f"{risk_level} security event detected in category: {category}.",
        "aiExplanation": explanation,
        "recommendedAction": recommendation
    }


if __name__ == "__main__":
    sample_alert = {
        "eventName": "DeleteTrail",
        "riskLevel": "CRITICAL",
        "category": "Logging Tampering"
    }

    analysis = generate_ai_analysis(sample_alert)

    print("AI INCIDENT ANALYSIS")
    print("--------------------")
    print("Summary:", analysis["aiSummary"])
    print("Explanation:", analysis["aiExplanation"])
    print("Recommended Action:", analysis["recommendedAction"])