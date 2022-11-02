## Operational Best Practices for NZISM 3.6

The Operational Best Practices for NZISM3.6 provides  a sample mapping between the New Zealand Government Communications Security Bureau (GCSB) Information Security Manual (NZISM) and AWS Managed Config rules. Each Config rule applies to a specific AWS resource, and relates to one or more NZISM controls. An NZISM control can be related to multiple Config rules

### Errors

| Rule ID            | Cause                                                                                             | Explanation                                        |     Relevent Control ID(s)    |                                                                            
| ------------------ | --------------------------------------------------------------------------------------------------|--------------------------------------------------- | ------------------------------|
| NZISM3.6-APIGWExecutionLoggingEnabled | The API Gateway stage does not have execution logging enabled for all methods  | API Gateway logging displays detailed views of users who accessed the API and the way they accessed the API. This insight enables visibility of user activities. | 16.6.10.C.02[CID:2013], 23.5.11.C.01[CID:7496] |                                                                                      


### Warnings

| Rule ID            							| Cause                                                                                              	| Explanation | Relevent Control ID(s)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------------------------| ------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NZISM3.6-CloudFrontDistributionAccessLogging | The CloudFront distribution does not have access logging enabled 			|  Enabling access logs helps operators track all viewer requests for the content delivered through the Content Delivery Network. | 16.6.10.C.02[CID:2013], 23.5.11.C.01[CID:7496] |                                                                                                                                                 | Provisioning the cluster within a VPC allows for better flexibility and control over the cache clusters security, availability, traffic routing and more.                                                                                                                                                                                                                                                                                                                                                                                                              |


### Excluded Rules

Unimplemented rules from the AWS PCI DSS 3.2.1 Conformance Pack.

| AWS Config Rule Name                                             	| Summary                                                                                     | Relevant Control ID(s) |
| ------------------------------------------------------------------|---------------------------------------------------------------------------------------------|------------------------|
| NZISM3.6-cloudfront-default-root-object-configured                |   																						|	            |
| NZISM3.6-ebs-snapshot-public-restorable-check						| 
| NZISM3.6-c2-ebs-encryption-by-default								|
| NZISM3.6-ec2-managedinstance-association-compliance-status-check	|
| NZISM3.6-ec2-managedinstance-patch-compliance-status-check		|
| NZISM3.6-ec2-hardening-and-state-management						|
| NZISM3.6-ec2-imdsv2-check											|
| NZISM3.6-ec2-critical-security-patch-auto-approval				|
| NZISM3.6-ecs-containers-readonly-access							|
| NZISM3.6-elb-custom-security-policy-ssl-check						|
| NZISM3.6-emr-master-no-public-ip									|
| NZISM3.6-rds-snapshot-encrypted									|
| NZISM3.6-vpc-sg-open-only-to-authorized-ports						|
| NZISM3.6-acm-certificate-expiration-check							|
| NZISM3.6-cloudtrail-enabled										|	The AWS account has cloudtrail enabled	|  16.6.6.C.02[CID:1998],  16.6.10.C.02[CID:2013], 16.4.35.C.02[CID:6860], 23.5.11.C.01[CID:7496]
| NZISM3.6-loudtrail-s3-dataevents-enabled							|
| NZISM3.6-cloudtrail-security-trail-enabled						|
| NZISM3.6-ec2-instance-managed-by-systems-manager					|
| NZISM3.6-ecr-private-image-scanning-enabled						|
| NZISM3.6-federate-with-central-idp								|
| NZISM3.6-iam-password-policy										|
| NZISM3.6-iam-root-access-key-check								|
| NZISM3.6-iam-user-unused-credentials-check						|
| NZISM3.6-kms-cmk-for-each-data-classification						|
| NZISM3.6-mfa-enabled-for-iam-console-access						|
| NZISM3.6-rds-snapshots-public-prohibited							|
| NZISM3.6-root-account-hardware-mfa-enabled						|
| NZISM3.6-root-account-mfa-enabled									|
| NZISM3.6-securityhub-enabled									    |
| NZISM3.6-ssm-document-not-public                                  |
