AWS Cloud Misconfiguration Scanner
- This is a python tool made to scan AWS accounts in order to find common security gaps / risks.

- Upon launch the tool will initiate checks to scan the following:
S3:
- Public access block disabled
- Versioning disabled
- Encryption disabled

IAM:
- Root account MFA disabled
- IAM users with MFA disabled
- IAM users with AdministratorAccess
- Access keys older than 90 days

CloudTrail:
- No trails configured
- Log file validation disabled

EC2:
- Security groups with SSH (port 22) open to the internet
- Security groups with RDP (port 3389) open to the internet
- Security groups with all ports open to the internet

The output will be a list of "risks" printed in the console.


PREREQUISITES:
To run this script, you will need the following:
- python
- boto3
- AWS CLI
- An AWS account with credentials configured
- ReadOnlyAccess policy on the scanning user.

SETUP:
- Clone the repo
- Install boto3
- Use 'aws configure' in the terminal to configure AWS Credentials


TO RUN:
Use the command below:
- python scanner.py


EXAMPLE OUTPUT:

Scanning S3 bucket security checks...
 [RISK] S3 Bucket 'michael-security-test-jn2026' has public access enabled.
 [RISK] S3 Bucket 'michael-security-test-jn2026' does not have versioning enabled.

Scanning IAM security checks...
 [RISK] IAM user 'scanner-user' does not have MFA enabled.

Scanning CloudTrail security checks...
 [RISK] No CloudTrail trails found.

Scanning EC2 security checks...
 [SAFE] No EC2 security issues found.


Note: This tool is made for educational purposes and should only be run on accounts you own or have explicit permission to scan.
