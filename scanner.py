import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from database import save_scan_result


def check_public_access(s3, bucket_name):
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)

        config = response["PublicAccessBlockConfiguration"]

        if all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False)
        ]):
            return "Blocked"

        return "Enabled"

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code in ["NoSuchPublicAccessBlockConfiguration",
                          "AccessDenied"]:
            return "Enabled"

        return "Unknown"


def check_encryption(s3, bucket_name):
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return "Enabled"

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            return "Disabled"

        if error_code == "AccessDenied":
            return "Unknown"

        return "Unknown"


def check_versioning(s3, bucket_name):
    try:
        response = s3.get_bucket_versioning(Bucket=bucket_name)

        status = response.get("Status")

        if status == "Enabled":
            return "Enabled"

        return "Disabled"

    except ClientError:
        return "Unknown"


def calculate_risk(public_access, encryption, versioning):
    score = 0

    if public_access == "Enabled":
        score += 50

    if encryption == "Disabled":
        score += 20

    if versioning == "Disabled":
        score += 10

    if score >= 50:
        risk_level = "HIGH"
    elif score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return score, risk_level


def scan_buckets():
    try:
        s3 = boto3.client("s3")

        response = s3.list_buckets()

        buckets = response.get("Buckets", [])

        print(f"\nFound {len(buckets)} S3 bucket(s).\n")

        results = []

        for bucket in buckets:

            bucket_name = bucket["Name"]

            print(f"Scanning: {bucket_name}")

            public_access = check_public_access(
                s3,
                bucket_name
            )

            encryption = check_encryption(
                s3,
                bucket_name
            )

            versioning = check_versioning(
                s3,
                bucket_name
            )

            risk_score, risk_level = calculate_risk(
                public_access,
                encryption,
                versioning
            )

            save_scan_result(
                bucket_name,
                public_access,
                encryption,
                versioning,
                risk_score,
                risk_level
            )

            result = {
                "bucket_name": bucket_name,
                "public_access": public_access,
                "encryption": encryption,
                "versioning": versioning,
                "risk_score": risk_score,
                "risk_level": risk_level
            }

            results.append(result)

            print(
                f"  Public Access : {public_access}"
            )
            print(
                f"  Encryption    : {encryption}"
            )
            print(
                f"  Versioning    : {versioning}"
            )
            print(
                f"  Risk Score    : {risk_score}"
            )
            print(
                f"  Risk Level    : {risk_level}"
            )
            print()

        return results

    except NoCredentialsError:
        print("\nERROR: AWS credentials were not found.")
        print("Please configure AWS credentials using:")
        print("aws configure")

        return []

    except ClientError as e:
        print("\nAWS ERROR:")
        print(e)

        return []


if __name__ == "__main__":
    scan_buckets()