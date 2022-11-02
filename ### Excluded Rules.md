### Excluded Rules

Unimplemented rules from the NSISM 3.6 Conformance Pack.

| AWS Config Rule Name                                      | Summary                                                                                     | Relevant Control ID(s) | Reason for Exclusion from NagPak |
| ----------------------------------------------------------|---------------------------------------------------------------------------------------------|------------------------|----------------------------------|
| acm-certificate-expiration-check							| AWS Certificate Manager Certificates in your account are valid and not marked for expiration within the specified number of days.        | SHOULD 14.5.8.C.01[CID:1667] | Account Level Check |
| cloudfront-default-root-object-configured                	|   		  | SHOULD 14.5.6.C.01[CID:1661] | Not Yet Implemented |																				|	            |
| cloudtrail-enabled										| The AWS account has cloudtrail enabled	|  16.6.6.C.02[CID:1998],  16.6.10.C.02[CID:2013], 16.4.35.C.02[CID:6860], 23.5.11.C.01[CID:7496] | Account Level Check |
| cloudtrail-s3-dataevents-enabled							| The AWS Account has at least once AWS CloudTrail that logs Amazon S3 data events for all S3 buckets      | SHOULD 22.1.24.C.03[CID:4838] | Account Level Check |
| cloudtrail-security-trail-enabled							| The AWS Account has at least once AWS CloudTrail that records global service events, is a multi-region trail, has Log file validation enabled, encrypted with a KMS key, records events for reads and writes, records management events, and does not exclude any management events.     | MUST 16.4.35.C.03[CID:6861] | Account Level Check |
| ebs-snapshot-public-restorable-check						| EBS snapshots can be publicly restored | SHOULD 22.1.24.C.03[CID:4838] | Not Yet Implemented |
| ec2-critical-security-patch-auto-approval					| Patch Baselines for Windows and/or Linux have been configured in Patch Manager, including auto-approval of critical security patches within 2 days of release   | SHOULD 12.4.4.C.04[CID:3451] | Account Level Check |
| ec2-ebs-encryption-by-default								| Default encryption for EBS volumes is enabled at the AWS Account level.   | SHOULD 17.1.46.C.04[CID:2082] | Account Level Check | 
| ec2-hardening-and-state-management						| Hardened EC2 server image build processes and State Manager Associations are configured to remove unneeded components and services, and install anti-malware software and log agents | SHOULD 14.1.8.C.01[CID:1149] | Account Level Check |    
| ec2-imdsv2-check											| EC2 instances have IMDSV2 (instance metadata service version 2) enabled.  | MUST 19.1.12.C.01[CID:3562], MUST 23.4.10.C.01[CID:7466] | Not Yet Implemented |
| ec2-instance-managed-by-systems-manager					| EC2 instances are managed by Systems Manager. | SHOULD 14.1.8.C.01[CID:1149] | Not Yet Implemented | 
| ec2-managedinstance-association-compliance-status-check	| Managed EC2 instances are compliant with their association's standards | SHOULD 14.1.8.C.01[CID:1149] | ??? |
| ec2-managedinstance-patch-compliance-status-check			| EC2 instances are compliant with their patch requirements | MUST 12.4.4.C.02[CID:3449], SHOULD 12.4.4.C.04[CID:3451], SHOULD 12.4.4.C.05[CID:3452], SHOULD 12.4.4.C.06[CID:3453] | Account Level Check |
| ecr-private-image-scanning-enabled						|       | MUST 12.4.4.C.02[CID:3449] | Account Level Check |
| ecs-containers-readonly-access							|       | SHOULD 14.1.8.C.01[CID:1149] | ???? |
| elb-custom-security-policy-ssl-check						|       | SHOULD 17.4.16.C.01[CID:2598], SHOULD NOT 17.4.16.C.02[CID:2600] | Not Yet Implemented |
| emr-master-no-public-ip									| EMR clusters' master nodes have no public IP | MUST 19.1.12.C.01[CID:3562], MUST 23.4.10.C.01[CID:7466] | ??? |
| federate-with-central-idp									|       | MUST 19.1.12.C.01[CID:3562], MUST 18.4.9.C.01[CID:3815], SHOULD 18.4.12.C.01[CID:3875], MUST 23.4.10.C.01[CID:7466] | Account Level Check | 
| iam-password-policy										| Account password policy for IAM users meet the specified requirements indicated in the parameters.      | SHOULD 16.1.40.C.02[CID:1858] | Account Level Check |
| iam-root-access-key-check									| The Account IAM Root User has an access key(s) | SHOULD 16.3.5.C.02[CID:1946] | Account Level Check |
| iam-user-unused-credentials-check							| IAM User passwords and active access keys have been used within a specified number of days.      | SHOULD 16.1.46.C.02[CID:1893], MUST 16.4.33.C.01[CID:6852] | Account Level Check |
| kms-cmk-for-each-data-classification						|       | SHOULD 17.9.25.C.01[CID:3021] | Account Level Check |
| lambda-function-public-access-prohibited					| Lambda function policies should not be publically invokable | MUST 19.1.12.C.01[CID:3562], MUST 23.4.10.C.01[CID:7466] | Not Yet Implemented |
| mfa-enabled-for-iam-console-access						| IAM Users have MFA enabled for console access | SHOULD 16.1.35.C.02[CID:1841], SHOULD 16.4.31.C.02[CID:6843], SHOULD 16.7.34.C.02[CID:6953], MUST 23.3.19.C.01[CID:7436], MUST 23.3.19.C.01[CID:7437] | Account Level Check |
| rds-snapshot-encrypted									| RDS snapshots are encrypted     | SHOULD 17.1.46.C.04[CID:2082], SHOULD 20.4.4.C.02[CID:4441], SHOULD 22.1.24.C.04[CID:4839] | ???? |
| rds-snapshots-public-prohibited							| RDS snapshots are not public      | SHOULD 20.4.4.C.02[CID:4441] | ????? |
| root-account-hardware-mfa-enabled							| The AWS Account root user is hardware MFA enabled.      | SHOULD 16.1.35.C.02[CID:1841], SHOULD 16.4.31.C.02[CID:6843], SHOULD 16.7.34.C.02[CID:6953], MUST 23.3.19.C.01[CID:7436], MUST 23.3.19.C.01[CID:7437] | Account Level Check | 
| root-account-mfa-enabled									| The AWS Account root user is MFA enabled      | SHOULD 16.1.35.C.02[CID:1841], MUST 23.3.19.C.01[CID:7436], MUST 23.3.19.C.01[CID:7437] | Account Level Check |
| securityhub-enabled									    | The AWS Account has Security Hub enabled.      | SHOULD 18.4.12.C.01[CID:3875] | Account Level Check |
| ssm-document-not-public                                  	| SSM documents are not public      | MUST 23.4.10.C.01[CID:7466] | Account Level Check |
| vpc-sg-open-only-to-authorized-ports						| Security Groups only allow inbound 0.0.0.0/0 from authorized TCP or UDP ports | SHOULD 18.1.13.C.02[CID:3205] | ?????? |
