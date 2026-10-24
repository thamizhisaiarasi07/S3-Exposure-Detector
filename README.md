# Real-Time S3 Bucket Exposure & Misconfiguration Detector

A lightweight, defensive Cloud Security posture management tool that scans Amazon S3 buckets in real time, identifies dangerous misconfigurations (public exposure, disabled encryption, disabled versioning), computes a transparent security risk score, and provides a web dashboard for security monitoring and remediation guidance.

---

## 1. Project Overview

Cloud storage services like **Amazon Simple Storage Service (Amazon S3)** host critical enterprise and personal data. However, misconfigurations in bucket access permissions, encryption, and object versioning remain one of the leading causes of accidental data exposure and cloud security breaches.

The **Real-Time S3 Bucket Exposure & Misconfiguration Detector** connects to AWS via the **Boto3 SDK**, inspects every accessible bucket in the account, calculates a risk score based on identified flaws, and presents findings in a web dashboard built with **Flask**, **SQLite**, and **Bootstrap 5**.

---

## 2. Problem Statement

Organizations and developers often make buckets publicly accessible during development or troubleshooting and forget to re-enable security controls. Common vulnerabilities include:
- Unrestricted public read/write access via missing Public Access Block controls.
- Unencrypted data at rest, making stored objects vulnerable in the event of compliance failures.
- Inactive object versioning, leaving buckets susceptible to accidental data deletion or ransomware overwrites.

Without an automated, local inspection tool, auditing these configurations manually across dozens of buckets in the AWS Management Console is tedious, error-prone, and slow.

---

## 3. Objectives

- **Automated Auditing**: Automatically query the AWS S3 API for each bucket's security configurations using Boto3.
- **Accurate Risk Scoring**: Apply deterministic, weighted risk scoring to classify buckets into `LOW`, `MEDIUM`, or `HIGH` risk tiers.
- **Defensive & Read-Only**: Audit security posture without modifying, deleting, uploading, or downloading any S3 data.
- **Actionable Remediation**: Provide clear, beginner-friendly recommendations for every detected vulnerability.
- **Audit Logging**: Store scan histories locally in an embedded SQLite database for historical compliance tracking.
- **Zero Additional AWS Costs**: Operate locally using standard free-tier AWS read APIs without deploying paid cloud resources (EC2, Lambda, DynamoDB, RDS).

---

## 4. Features

- 🔍 **Real-Time S3 Scanner**: Scans all accessible S3 buckets on demand.
- 🛡️ **Public Access Detection**: Inspects the 4 S3 Public Access Block settings (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`).
- 🔐 **Encryption Verification**: Validates whether default server-side encryption (SSE) is enabled.
- 📦 **Versioning Check**: Identifies whether bucket versioning is active to protect against accidental deletions.
- 📊 **Risk Scoring & Badging**: Scores each bucket from 0 to 80+ and marks it with colored badges (`LOW` = Green, `MEDIUM` = Orange, `HIGH` = Red).
- 📋 **Interactive Dashboard**: High-level metric summary cards (Total Buckets, High Risk, Medium Risk, Low Risk) and a findings table.
- 💡 **Bucket Detail & Recommendations**: Detailed view for individual buckets with remediation steps.
- 📜 **Scan History**: Full historical log of previous scans stored in SQLite.
- 🛡️ **Resilient Error Handling**: Gracefully handles missing AWS credentials, invalid keys, `AccessDenied` permissions, and empty accounts without crashing.

---

## 5. Technology Stack

- **Backend**: Python 3.10+ (tested with Python 3.13) & Flask
- **Cloud SDK**: Boto3 (AWS SDK for Python) & Botocore
- **Database**: SQLite3 (embedded, zero-configuration)
- **Frontend**: HTML5, CSS3, Bootstrap 5.3, Bootstrap Icons
- **Cloud Provider**: Amazon Web Services (Amazon S3)

---

## 6. System Architecture

```
+-------------------------------------------------------------+
|                      User Web Browser                       |
|          (Dashboard, Details, History, Scan Trigger)        |
+------------------------------+------------------------------+
                               | HTTP (Port 5000)
                               v
+-------------------------------------------------------------+
|                     Flask Application                       |
|                          (app.py)                           |
+--------------+-------------------------------+--------------+
               |                               |
               | Triggers Audit                | Queries / Stores
               v                               v
+-----------------------------+ +-----------------------------+
|       Scanner Engine        | |       SQLite Database       |
|        (scanner.py)         | |       (s3_detector.db)      |
+--------------+--------------+ +-----------------------------+
               |
               | Reads Config via Boto3
               v
+-------------------------------------------------------------+
|                        Amazon S3                            |
|  - GetPublicAccessBlock                                     |
|  - GetBucketEncryption                                      |
|  - GetBucketVersioning                                      |
+-------------------------------------------------------------+
```

---

## 7. Project Folder Structure

```
S3-Exposure-Detector/
│
├── app.py               # Flask web server, application routes, and error handling
├── scanner.py           # Boto3 S3 auditing engine and risk calculation
├── database.py          # SQLite database connection, table initialization, and queries
├── requirements.txt     # Python project dependencies (Flask, Boto3)
├── .gitignore           # Git ignore file excluding venv, secrets, cache, and db
├── README.md            # Comprehensive project documentation
├── s3_detector.db       # SQLite database file (created automatically on startup)
│
├── templates/
│   ├── base.html        # Base HTML layout, navigation bar, and flash notifications
│   ├── index.html       # Main dashboard with summary cards and scan trigger
│   ├── results.html     # Scan results table and granular bucket detail view
│   └── history.html     # Historical scan log view
│
└── static/
    └── style.css        # Custom CSS styling and responsive layout rules
```

---

## 8. How the S3 Scanner Works

When a security scan is triggered:
1. The application initializes an S3 client using `boto3.client("s3")`.
2. Boto3 automatically searches the standard credential provider chain (environment variables, `~/.aws/credentials` configured via `aws configure`, or IAM roles).
3. The scanner retrieves the list of accessible buckets with `s3.list_buckets()`.
4. For each bucket, the scanner performs read-only inspection calls:
   - Queries `s3.get_public_access_block(Bucket=bucket_name)`
   - Queries `s3.get_bucket_encryption(Bucket=bucket_name)`
   - Queries `s3.get_bucket_versioning(Bucket=bucket_name)`
5. Calculates the risk score and assigns the risk level (`LOW`, `MEDIUM`, `HIGH`).
6. Saves the findings into the SQLite database.
7. Redirects the user to the web results page to review the findings.

---

## 9. Security Checks Performed

| Security Check | AWS API Call | Secure Condition | Flagged Condition |
| :--- | :--- | :--- | :--- |
| **Public Access Block** | `get_public_access_block` | All 4 block settings are `True` | Any setting is `False`, or configuration is missing |
| **Server-Side Encryption** | `get_bucket_encryption` | Server-side encryption is enabled | `ServerSideEncryptionConfigurationNotFoundError` |
| **Bucket Versioning** | `get_bucket_versioning` | Status is `Enabled` | Status is `Disabled`, `Suspended`, or `None` |

---

## 10. Risk Scoring & Levels

The detector applies transparent, point-based risk calculations:

| Security Check | Condition | Risk Score Added |
| :--- | :--- | :---: |
| **Public Access Block** | Missing or not fully blocked | **+50** |
| **Server-Side Encryption** | Disabled | **+20** |
| **Bucket Versioning** | Disabled or Suspended | **+10** |

### Risk Level Tiers:
- 🟢 **LOW (`0 - 19`)**: The bucket adheres to baseline security best practices.
- 🟡 **MEDIUM (`20 - 49`)**: Minor or moderate security concerns (e.g., encryption or versioning disabled).
- 🔴 **HIGH (`50+`)**: Critical security risk (public access is permitted or unblocked).

---

## 11. Installation Steps

Clone the repository or navigate to your project folder in **Windows PowerShell**:

```powershell
Set-Location -Path "C:\S3-Exposure-Detector"
```

---

## 12. Virtual Environment Setup

Create and activate an isolated Python virtual environment:

```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment in PowerShell
.\venv\Scripts\Activate.ps1
```

> **PowerShell Execution Policy Note**: If you encounter a script execution error when running `Activate.ps1`, run:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

---

## 13. Requirements Installation

Install the required Python packages:

```powershell
pip install -r requirements.txt
```

---

## 14. AWS CLI Configuration

> ⚠️ **CRITICAL SECURITY REQUIREMENT**:
> **NEVER hardcode AWS Access Keys, Secret Keys, or Session Tokens inside the source code, `.env` files, or git commits.**

Configure your AWS credentials locally using the official AWS CLI:

```powershell
aws configure
```

When prompted, provide your IAM user credentials:
- **AWS Access Key ID**: `YOUR_ACCESS_KEY_ID`
- **AWS Secret Access Key**: `YOUR_SECRET_ACCESS_KEY`
- **Default region name**: `us-east-1` (or your preferred region, e.g., `ap-south-1`)
- **Default output format**: `json`

### Credential Resolution via Boto3:
Boto3 automatically resolves your credentials from the standard credential chain:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
2. Shared credentials file (`~/.aws/credentials`).
3. Shared configuration file (`~/.aws/config`).
4. IAM instance profiles or ECS container credentials.

### Recommended IAM Permissions:
Use an IAM user or role with least-privilege read-only permissions (such as the AWS-managed policy `AmazonS3ReadOnlyAccess`):
- `s3:ListAllMyBuckets`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetEncryptionConfiguration`
- `s3:GetBucketVersioning`

---

## 15. Running the Flask Application

Start the Flask local web server:

```powershell
python app.py
```

You will see console output confirming startup:
```
=================================================================
Real-Time S3 Bucket Exposure & Misconfiguration Detector
Starting Flask web server on http://127.0.0.1:5000 ...
Press Ctrl+C to stop.
=================================================================
```

Open your browser and navigate to:
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 16. Example Workflow

1. **Dashboard Home (`/`)**: View current summary metrics and audited buckets.
2. **Run Scan (`/scan`)**: Click **"Run Security Scan"** to perform live auditing of your S3 buckets.
3. **View Results (`/results`)**: Review all scanned buckets, their encryption, versioning, and public access states.
4. **Inspect Bucket Details (`/bucket/<bucket_name>`)**: Click **"View Details"** on any bucket to see its specific misconfiguration breakdown and remediation recommendations.
5. **View History (`/history`)**: Track previous audit logs stored chronologically in SQLite.

---

## 17. Security Considerations

- **Strictly Read-Only**: The tool only reads bucket metadata. It does not alter bucket settings, modify access control lists (ACLs), delete buckets, or download object data.
- **No Secret Storage**: No credentials or tokens are stored in the SQLite database or codebase.
- **Fail-Safe Exception Handling**: If an individual check fails due to IAM permission limits (`AccessDenied`), the scanner flags that check as `Unknown / Permission Denied` and continues scanning remaining checks without crashing.
- **Ignored Runtime Files**: Database files (`*.db`), virtual environments (`venv/`), Python cache (`__pycache__/`), and local secrets are excluded from Git via `.gitignore`.

---

## 18. Future Enhancements

- **S3 Bucket Policy AST Analyzer**: In-depth parsing of IAM Condition keys (e.g., `aws:SourceVpce`, `aws:PrincipalOrgID`).
- **S3 Object Lock & Lifecycle Rules**: Audit whether compliance Object Lock or automated data lifecycle retention rules are configured.
- **Export Reports**: Generate downloadable PDF and CSV compliance summary reports.
- **Automated Remediation (Opt-In)**: Provide optional, one-click scripts to enable S3 Block Public Access with explicit user confirmation.
