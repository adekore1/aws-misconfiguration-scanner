import datetime

import boto3

def check_bucket_public_access(s3, name):
    """Return public access faults for a single bucket."""
    try:
        public_access_block = s3.get_public_access_block(Bucket=name)
        config = public_access_block['PublicAccessBlockConfiguration']
        all_blocked = all([
            config.get('BlockPublicAcls'),
            config.get('IgnorePublicAcls'),
            config.get('BlockPublicPolicy'),
            config.get('RestrictPublicBuckets')
        ])
        if not all_blocked:
            return [f" [RISK] S3 Bucket '{name}' has public access enabled."]
    except Exception:
        return [f" [RISK] S3 Bucket '{name}' does not have a public access block configuration."]

    return []


def check_bucket_versioning(s3, name):
    """Return versioning faults for a single bucket."""
    try:
        versioning = s3.get_bucket_versioning(Bucket=name)
        if versioning.get('Status') != 'Enabled':
            return [f" [RISK] S3 Bucket '{name}' does not have versioning enabled."]
    except Exception:
        return [f" [RISK] S3 Bucket '{name}' versioning check failed."]

    return []


def check_bucket_encryption(s3, name):
    """Return encryption faults for a single bucket."""
    try:
        encryption = s3.get_bucket_encryption(Bucket=name)
        rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        if not rules:
            return [f" [RISK] S3 Bucket '{name}' does not have encryption enabled."]
    except Exception:
        return [f" [RISK] S3 Bucket '{name}' encryption check failed."]

    return []


def check_s3_bucket_security():
    """Run all S3 bucket checks and return a combined fault list."""
    s3 = boto3.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])

    faults = []
    for bucket in buckets:
        name = bucket.get('Name')
        if not name:
            continue

        faults.extend(check_bucket_public_access(s3, name))
        faults.extend(check_bucket_versioning(s3, name))
        faults.extend(check_bucket_encryption(s3, name))

    return faults


#function 2: IAM, Root account and IAM users with no MFA, IAM users with admin permissions, Access keys older than 90 days
def check_iam_security():
    iam = boto3.client('iam')
    users = iam.list_users().get('Users', [])

    faults = []
    now = datetime.datetime.now(datetime.timezone.utc)

    summary = iam.get_account_summary()
    if summary.get('SummaryMap', {}).get('AccountMFAEnabled', 0) == 0:
        faults.append(" [RISK] Root account does not have MFA enabled.")

    for user in users:
        username = user.get('UserName')
        if not username:
            continue

        mfa_devices = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
        if not mfa_devices:
            faults.append(f" [RISK] IAM user '{username}' does not have MFA enabled.")

        policies = iam.list_attached_user_policies(UserName=username).get('AttachedPolicies', [])
        if any(policy.get('PolicyName') == 'AdministratorAccess' for policy in policies):
            faults.append(f" [RISK] IAM user '{username}' has admin permissions.")

        access_keys = iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
        for key in access_keys:
            create_date = key.get('CreateDate')
            if not create_date:
                continue 
            if create_date.tzinfo is None:
                create_date = create_date.replace(tzinfo=datetime.timezone.utc)
            if (now - create_date).days > 90:
                faults.append(f" [RISK] IAM user '{username}' has access keys older than 90 days.")

    return faults


#function 3: CloudTrail enabled check, CloudTrail log validation disabled check.
def check_cloudtrail_security():
    cloudtrail = boto3.client('cloudtrail')
    trails = cloudtrail.describe_trails()

    trailList = trails.get('trailList', [])
    faults = []

    if not trailList:
        faults.append(" [RISK] No CloudTrail trails found.")
    else:
        for trail in trailList:
            name = trail.get('Name')
            log_validation_disabled = trail.get('LogFileValidationEnabled', False) is False
            if log_validation_disabled:
                faults.append(f" [RISK] CloudTrail trail '{name}' has log validation disabled.")
            
    return faults


#function 4: EC2/Networking checls, security groups with 0.0.0.0/0 on SSH, RDP and all ports.
def ec2_security_check():
    ec2 = boto3.client('ec2')

    faults = []

    securityGroups = ec2.describe_security_groups().get('SecurityGroups', [])    
    for group in securityGroups:
        groupName = group.get('GroupName')
        groupId = group.get('GroupId')

        for permission in group.get('IpPermissions', []):
            for ipRange in permission.get('IpRanges', []):
                cidrIp = ipRange.get('CidrIp')
                if cidrIp == '0.0.0.0/0':
                    port = permission.get('FromPort')
                    ipProtocol = permission.get('IpProtocol')
                    if port == 22:
                        faults.append(f" [RISK] Security group '{groupName}' ({groupId}) has SSH (port 22) open to the internet.")
                    elif port == 3389:
                        faults.append(f" [RISK] Security group '{groupName}' ({groupId}) has RDP (port 3389) open to the internet.")
                    elif port is None and ipProtocol == '-1':
                        faults.append(f" [RISK] Security group '{groupName}' ID: {groupId} has open access to all ports.")

            for ipv6Range in permission.get('Ipv6Ranges', []):
                    if ipv6Range.get('CidrIpv6') == '::/0':
                        port = permission.get('FromPort')
                        ipProtocol = permission.get('IpProtocol')
                        if port == 22:
                            faults.append(f" [RISK] Security group '{groupName}' ({groupId}) has SSH (port 22) open to the internet (IPv6).")
                        elif port == 3389:
                            faults.append(f" [RISK] Security group '{groupName}' ({groupId}) has RDP (port 3389) open to the internet (IPv6).")
                        elif port is None and ipProtocol == '-1':
                            faults.append(f" [RISK] Security group '{groupName}' ({groupId}) has open access to all ports (IPv6).")
                
    return faults

def main():
    print("Scanning S3 bucket security checks...")
    s3_faults = check_s3_bucket_security()
    if s3_faults:
        print("\n".join(s3_faults))
    else:
        print(" [SAFE] No S3 bucket security issues found.")

    print("\nScanning IAM security checks...")
    iam_faults = check_iam_security()
    if iam_faults:
        print("\n".join(iam_faults))
    else:
        print(" [SAFE] No IAM security issues found.")

    print("\nScanning CloudTrail security checks...")
    cloudtrail_faults = check_cloudtrail_security()
    if cloudtrail_faults:
        print("\n".join(cloudtrail_faults))
    else:
        print(" [SAFE] No CloudTrail security issues found.")

    print("\nScanning EC2 security checks...")
    ec2_faults = ec2_security_check()
    if ec2_faults:
        print("\n".join(ec2_faults))
    else:
        print(" [SAFE] No EC2 security issues found.")

if __name__ == "__main__":
    main()