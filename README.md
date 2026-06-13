# CyberShield AI

![AWS](https://img.shields.io/badge/AWS-Cloud-orange?logo=amazonaws)
![CloudTrail](https://img.shields.io/badge/CloudTrail-Enabled-blue)
![IAM](https://img.shields.io/badge/IAM-Secured-green)
![S3](https://img.shields.io/badge/S3-Log%20Storage-success)
![Security](https://img.shields.io/badge/Cybersecurity-AWS-red)


AI-Powered AWS Cloud Security Detection and Automated Incident Response Platform.

## Status

CyberShield AI v1.0 is portfolio-ready.

## Project Goal

CyberShield AI monitors AWS security activity, detects suspicious behavior, sends alerts, and later can automatically respond to threats.

## First Version Architecture


```text
AWS CloudTrail
      ↓
Amazon S3
      ↓
AWS Lambda
      ↓
Amazon SNS Email Alert
```

## Technologies

- AWS CloudTrail
- Amazon S3
- AWS Lambda
- Amazon SNS
- Python
- Docker
- Terraform
- Next.js

## Features

- Collect AWS security logs
- Detect suspicious activity
- Send email alerts
- Store incidents
- Future dashboard for monitoring threats

## AWS Security Evidence

### CloudTrail Enabled

CloudTrail was configured to record management events across all AWS regions.

![CloudTrail](screenshots/04-cloudtrail-created.png)

### S3 Log Storage

CloudTrail logs are stored securely in Amazon S3 buckets for auditing and security investigations.

![S3 Buckets](screenshots/05-s3-buckets.png)

### Email Alert Simulation

CyberShield AI generates security alerts when critical AWS actions are detected.

![Email Alert](screenshots/08-email-alert-simulation.png)

## Community

CyberShield AI is actively maintained and improved.

## AI Incident Analysis

CyberShield AI analyzes detected incidents and generates:

- Threat explanations
- Risk context
- Recommended security actions

Example:

DeleteTrail
↓
AI Analysis
↓
"This activity may indicate an attempt to disable AWS logging and hide malicious actions."
↓
Recommended Response

![AI Incident Analysis](screenshots/09-ai-incident-analysis.png)

## Dashboard Prototype

CyberShield AI includes a dashboard prototype that displays:

- Total incidents
- Critical incidents
- High-risk events
- Threat scores
- Incident summaries

### Dashboard Output

![Dashboard](screenshots/10-dashboard-prototype.png)

## Web Dashboard

CyberShield AI includes a Streamlit-powered security dashboard.

Features:

- Incident monitoring
- Threat score visualization
- AI recommendations
- Security event reporting

### Dashboard

![Dashboard](screenshots/11-streamlit-dashboard.png)

