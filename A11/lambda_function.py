import boto3
import json
from botocore.exceptions import ClientError


def assume_role(role_arn, session_name="AuditSession"):
    sts_client = boto3.client('sts')
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
        credentials = response['Credentials']
        return {
            'AccessKeyId': credentials['AccessKeyId'],
            'SecretAccessKey': credentials['SecretAccessKey'],
            'SessionToken': credentials['SessionToken']
        }
    except ClientError as e:
        raise Exception(f"Failed to assume role: {e}")


def generate_and_get_credential_report(iam_client):
    try:
        iam_client.generate_credential_report()
        response = iam_client.get_credential_report()
        return response['Content'].decode('utf-8')
    except ClientError as e:
        raise Exception(f"Failed to generate or retrieve credential report: {e}")


def parse_csv_report(csv_content):
    rows = csv_content.strip().split("\n")
    headers = rows[0].split(",")
    return [dict(zip(headers, row.split(","))) for row in rows[1:]]


def audit_cis_controls(credential_report):
    results = {}
    # CIS 1.1
    for entry in credential_report:
        if entry['user'] == "<root_account>":
            results["CIS 1.1"] = entry.get("password_last_used", "No information")
    
    # CIS 1.2
    results["CIS 1.2"] = [
        entry['user'] for entry in credential_report
        if entry['mfa_active'] == "false" and entry['password_enabled'] == "true"
    ]
    
    # CIS 1.12
    for entry in credential_report:
        if entry['user'] == "<root_account>":
            if entry['access_key_1_active'] == "true" or entry['access_key_2_active'] == "true":
                results["CIS 1.12"] = "Access key(s) are attached to the root account."
            else:
                results["CIS 1.12"] = "No access keys are attached to the root account."
    
    return results


def send_sns_notification(topic_arn, subject, message):
    sns_client = boto3.client('sns')
    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        raise Exception(f"Failed to send SNS notification: {e}")


def lambda_handler(event, context):
    # Role ARN for the IAM-Auditor-role
    role_arn = "arn:aws:iam::297904909452:role/IAM-Auditor-role"
    sns_topic_arn = "arn:aws:sns:us-east-1:297904909452:CISAuditNotifications"

    try:
        print("Step 1: Assuming IAM-Auditor-role...")
        credentials = assume_role(role_arn)
        print("Successfully assumed role.")

        print("Step 2: Creating IAM client...")
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        print("IAM client created.")

        print("Step 3: Generating IAM credential report...")
        csv_report = generate_and_get_credential_report(iam_client)
        print("Credential report generated.")

        print("Step 4: Parsing credential report...")
        credential_report = parse_csv_report(csv_report)
        print("Credential report parsed.")

        print("Step 5: Auditing CIS controls...")
        audit_results = audit_cis_controls(credential_report)
        print("CIS audit completed.")

        print("Step 6: Generating report text...")
        text_report = f"""
        AWS CIS Audit Results:
        ------------------------
        CIS 1.1 - Last root account usage: {audit_results["CIS 1.1"]}
        CIS 1.2 - IAM users with MFA disabled: {', '.join(audit_results["CIS 1.2"])}
        CIS 1.12 - Root account access keys: {audit_results["CIS 1.12"]}
        """
        print("Report generated:", text_report)

        print("Step 7: Sending report via SNS...")
        send_sns_notification(
            topic_arn=sns_topic_arn,
            subject="AWS CIS Audit Report",
            message=text_report
        )
        print("Report sent successfully via SNS.")

        return {
            "statusCode": 200,
            "body": json.dumps("CIS Audit report sent successfully!")
        }
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps(f"Error: {str(e)}")
        }