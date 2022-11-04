## cloudfront-default-root-object-configured

Checks if an Amazon CloudFront distribution is configured to return a specific object that is the default root object. The rule is NON_COMPLIANT if Amazon CloudFront distribution does not have a default root object configured.

Identifier: CLOUDFRONT_DEFAULT_ROOT_OBJECT_CONFIGURED

Trigger type: Configuration changes

AWS Region: Only available in US East (N. Virginia) Region

Parameters:

None


## ebs-snapshot-public-restorable-check

Checks whether Amazon Elastic Block Store (Amazon EBS) snapshots are not publicly restorable. The rule is NON_COMPLIANT if one or more snapshots with RestorableByUserIds field are set to all, that is, Amazon EBS snapshots are public.

Identifier: EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK

Trigger type: Periodic

AWS Region: All supported AWS regions except Asia Pacific (Jakarta), Middle East (UAE), Asia Pacific (Osaka) Region

Parameters:

None

## ec2-imdsv2-check

Checks whether your Amazon Elastic Compute Cloud (Amazon EC2) instance metadata version is configured with Instance Metadata Service Version 2 (IMDSv2). The rule is NON_COMPLIANT if the HttpTokens is set to optional.

Identifier: EC2_IMDSV2_CHECK

Trigger type: Configuration changes

AWS Region: All supported AWS regions except Asia Pacific (Jakarta), Africa (Cape Town), Middle East (UAE), Asia Pacific (Osaka), Europe (Milan) Region

Parameters:

None

## ec2-instance-managed-by-systems-manager

Checks whether the Amazon EC2 instances in your account are managed by AWS Systems Manager.

Identifier: EC2_INSTANCE_MANAGED_BY_SSM

Trigger type: Configuration changes

AWS Region: All supported AWS regions except Asia Pacific (Jakarta), Middle East (UAE) Region

Parameters:

None

## elb-custom-security-policy-ssl-check

Checks whether your Classic Load Balancer SSL listeners are using a custom policy. The rule is only applicable if there are SSL listeners for the Classic Load Balancer.

Identifier: ELB_CUSTOM_SECURITY_POLICY_SSL_CHECK

Trigger type: Configuration changes

AWS Region: All supported AWS regions except Asia Pacific (Jakarta), Africa (Cape Town), Middle East (UAE), Asia Pacific (Osaka), Europe (Milan), AWS GovCloud (US-East) Region

Parameters:

sslProtocolsAndCiphers
Type: String
Comma separated list of ciphers and protocols.


## lambda-function-public-access-prohibited

Checks if the AWS Lambda function policy attached to the Lambda resource prohibits public access. If the Lambda function policy allows public access it is NON_COMPLIANT.

Identifier: LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED

Trigger type: Configuration changes

AWS Region: All supported AWS regions except Middle East (UAE), Asia Pacific (Osaka), China (Ningxia) Region

Parameters:

None


~~## vpc-sg-open-only-to-authorized-ports~~


~~Checks whether any security groups with inbound 0.0.0.0/0 have TCP or UDP ports accessible. The rule is NON_COMPLIANT when a security group with inbound 0.0.0.0/0 has a port accessible which is not specified in the rule parameters.

Identifier: VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS

Trigger type: Configuration changes

AWS Region: All supported AWS regions except Asia Pacific (Jakarta), Middle East (UAE), Asia Pacific (Osaka) Region

Parameters: 443 TCP

authorizedTcpPorts (Optional)
Type: String
Comma-separated list of TCP ports authorized to be open to 0.0.0.0/0. Ranges are defined by dash, for example, "443,1020-1025".

authorizedUdpPorts (Optional)
Type: String
Comma-separated list of UDP ports authorized to be open to 0.0.0.0/0. Ranges are defined by dash, for example, "500,1020-1025".

Description: "SHOULD 18.1.13.C.02[CID:3205]| Network security/Network Management/Limiting network access"