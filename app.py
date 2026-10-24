"""
app.py
Main Flask Web Application for:
Real-Time S3 Bucket Exposure & Misconfiguration Detector

Provides web dashboard, security scan trigger, scan results view,
bucket detail inspection, and historical audit logs.
"""

import os
from flask import Flask, render_template, request, redirect, url_for, flash
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

import database
import scanner

app = Flask(__name__)
app.secret_key = "s3-exposure-detector-flask-secret-key"

# Automatically initialize SQLite database and required tables on application startup
database.init_db()


def get_latest_unique_buckets():
    """
    Helper function to retrieve the most recent scan record for each unique bucket name.
    """
    all_records = database.get_all_results()
    latest_buckets_dict = {}

    for row in all_records:
        b_name = row["bucket_name"]
        if b_name not in latest_buckets_dict:
            latest_buckets_dict[b_name] = dict(row)

    return list(latest_buckets_dict.values())


def compute_summary_stats(buckets):
    """
    Helper function to calculate summary statistics for the dashboard cards.
    """
    total = len(buckets)
    high = sum(1 for b in buckets if b["risk_level"] == "HIGH")
    medium = sum(1 for b in buckets if b["risk_level"] == "MEDIUM")
    low = sum(1 for b in buckets if b["risk_level"] == "LOW")

    return {
        "total_buckets": total,
        "high_risk": high,
        "medium_risk": medium,
        "low_risk": low
    }


def generate_recommendations(bucket_data):
    """
    Generates actionable remediation recommendations based on bucket misconfigurations.
    """
    recommendations = []

    if bucket_data.get("public_access") == "Enabled":
        recommendations.append("Enable S3 Block Public Access (activate all 4 public block protections).")

    if bucket_data.get("encryption") == "Disabled":
        recommendations.append("Enable default server-side encryption (SSE-S3 or AWS KMS) for data at rest.")

    if bucket_data.get("versioning") == "Disabled":
        recommendations.append("Enable bucket versioning to safeguard against accidental object overwrites and deletions.")

    if not recommendations:
        recommendations.append("All baseline security checks passed! Keep monitoring periodically.")

    return recommendations


@app.route("/")
def index():
    """
    Dashboard home page: Displays summary cards, latest scan results, and scan trigger button.
    """
    latest_buckets = get_latest_unique_buckets()
    stats = compute_summary_stats(latest_buckets)
    return render_template("index.html", stats=stats, buckets=latest_buckets)


@app.route("/scan", methods=["POST", "GET"])
def run_scan():
    """
    Triggers a live AWS S3 security audit.
    Uses Boto3 default credentials configured via 'aws configure'.
    """
    try:
        # Pre-check credentials with Boto3
        s3 = boto3.client("s3")
        try:
            buckets_response = s3.list_buckets()
            raw_buckets = buckets_response.get("Buckets", [])
        except (NoCredentialsError, PartialCredentialsError):
            flash("AWS credentials not found. Please run 'aws configure' in PowerShell to configure your AWS credentials.", "danger")
            return redirect(url_for("index"))
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "ClientError")
            flash(f"AWS Error ({error_code}): {e}", "danger")
            return redirect(url_for("index"))

        if not raw_buckets:
            flash("Connected to AWS S3 successfully, but no S3 buckets were found in your account.", "info")
            return redirect(url_for("results"))

        # Run scanner logic
        results = scanner.scan_buckets()
        flash(f"Security scan completed successfully! Audited {len(results)} S3 bucket(s).", "success")
        return redirect(url_for("results"))

    except (NoCredentialsError, PartialCredentialsError):
        flash("AWS credentials not found. Please configure AWS CLI credentials using 'aws configure'.", "danger")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"An unexpected error occurred during scan: {str(e)}", "danger")
        return redirect(url_for("index"))


@app.route("/results")
def results():
    """
    Displays the latest scan results for all scanned buckets.
    """
    latest_buckets = get_latest_unique_buckets()
    stats = compute_summary_stats(latest_buckets)
    return render_template("results.html", stats=stats, buckets=latest_buckets)


@app.route("/history")
def history():
    """
    Displays historical scan logs stored in the SQLite database.
    """
    all_records = database.get_all_results()
    return render_template("history.html", history=all_records)


@app.route("/bucket/<bucket_name>")
def bucket_detail(bucket_name):
    """
    Displays detailed misconfiguration findings and recommendations for a specific bucket.
    """
    latest_buckets = get_latest_unique_buckets()
    bucket_info = next((b for b in latest_buckets if b["bucket_name"] == bucket_name), None)

    if not bucket_info:
        flash(f"No scan records found for bucket '{bucket_name}'. Please run a security scan first.", "warning")
        return redirect(url_for("index"))

    recommendations = generate_recommendations(bucket_info)

    return render_template(
        "results.html",
        selected_bucket=bucket_info,
        recommendations=recommendations,
        is_detail_view=True
    )


@app.errorhandler(404)
def page_not_found(e):
    return render_template("base.html", error_title="Page Not Found (404)", error_msg="The requested page does not exist."), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template("base.html", error_title="Internal Server Error", error_msg="An unexpected error occurred on the server."), 500


if __name__ == "__main__":
    print("=" * 65)
    print("Real-Time S3 Bucket Exposure & Misconfiguration Detector")
    print("Starting Flask web server on http://127.0.0.1:5000 ...")
    print("Press Ctrl+C to stop.")
    print("=" * 65)
    app.run(host="127.0.0.1", port=5000, debug=True)
