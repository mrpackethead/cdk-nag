/*
 * This work is a derviate work based on the NZISM Conformance Paks, and cdk-nag from Amazon.com Inc. or its affiliates.
 * Written by Andrew Frazer
 * SPDX-License-Identifier: Apache-2.0
 * The author of this nag-pak, makes no warranty or claims about its suitability or accuracy for any purpose, and accepts no liablity for its use.
 */

import { CfnResource } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';
import { NagMessageLevel, NagPack, NagPackProps } from '../nag-pack';
import { APIGWExecutionLoggingEnabled } from '../rules/apigw';
import {
  CloudFrontDistributionAccessLogging,
  CloudFrontDistributionHttpsViewerNoOutdatedSSL,
  CloudFrontDistributionWAFIntegration,
} from '../rules/cloudfront';
import {
  CloudTrailCloudWatchLogsEnabled,
  CloudTrailEncryptionEnabled,
  CloudTrailLogFileValidationEnabled,
} from '../rules/cloudtrail';
import { CloudWatchLogGroupRetentionPeriod } from '../rules/cloudwatch';
import { DMSReplicationNotPublic } from '../rules/dms';
import {
  DynamoDBAutoScalingEnabled,
  DynamoDBInBackupPlan,
  DynamoDBPITREnabled,
} from '../rules/dynamodb';
import {
  EC2EBSInBackupPlan,
  EC2InstanceNoPublicIp,
  EC2InstancesInVPC,
  EC2RestrictedSSH,
  EC2EBSVolumeEncrypted,
} from '../rules/ec2';
import { ECSTaskDefinitionUserForHostMode } from '../rules/ecs';
import { EFSEncrypted, EFSInBackupPlan } from '../rules/efs';
import { ElastiCacheRedisClusterAutomaticBackup } from '../rules/elasticache';
import { ElasticBeanstalkManagedUpdatesEnabled } from '../rules/elasticbeanstalk';
import {
  ALBHttpToHttpsRedirection,
  ALBWAFEnabled,
  ELBCrossZoneLoadBalancingEnabled,
  ELBLoggingEnabled,
  ELBTlsHttpsListenersOnly,
} from '../rules/elb';
import { IAMPolicyNoStatementsWithAdminAccess } from '../rules/iam';
import { KMSBackingKeyRotationEnabled } from '../rules/kms';
import { LambdaInsideVPC } from '../rules/lambda';
import {
  OpenSearchEncryptedAtRest,
  OpenSearchInVPCOnly,
  OpenSearchNodeToNodeEncryption,
} from '../rules/opensearch';
import {
  RDSInBackupPlan,
  RDSInstanceDeletionProtectionEnabled,
  RDSInstancePublicAccess,
  RDSLoggingEnabled,
  RDSMultiAZSupport,
  RDSStorageEncrypted,
} from '../rules/rds';
import {
  RedshiftRequireTlsSSL,
  RedshiftBackupEnabled,
  RedshiftClusterConfiguration,
  RedshiftClusterMaintenanceSettings,
  RedshiftClusterPublicAccess,
} from '../rules/redshift';
import {
  S3BucketLevelPublicAccessProhibited,
  S3BucketLoggingEnabled,
  S3BucketPublicReadProhibited,
  S3BucketPublicWriteProhibited,
  S3BucketServerSideEncryptionEnabled,
  S3BucketSSLRequestsOnly,
  S3BucketVersioningEnabled,
  S3DefaultEncryptionKMS,
} from '../rules/s3';
import {
  SageMakerEndpointConfigurationKMSKeyConfigured,
  SageMakerNotebookInstanceKMSKeyConfigured,
  SageMakerNotebookNoDirectInternetAccess,
} from '../rules/sagemaker';
import { SecretsManagerUsingKMSKey } from '../rules/secretsmanager';
import { SNSEncryptedKMS } from '../rules/sns';
import {
  VPCFlowLogsEnabled,
  VPCDefaultSecurityGroupClosed,
} from '../rules/vpc';
import { WAFv2LoggingEnabled } from '../rules/waf';

/**
 * Check for NZISM v36-1022-20 compliance.
 * Based on the NZISM v36-1022-20: <URL To be updated once published>
 *
 * The following rules are not yet included and are TODO items.
 *
 * CloudfrontDefaultRootObjectConfigured
 * DynamodbTableEncryptedKms
 * EbsSnapshotPublicRestorableCheck
 * Ec2HardeningAndStateManagement
 * Ec2Imdsv2Check
 * EcsContainersReadonlyAccess
 * ElbCustomSecurityPolicySslCheck
 * EmrMasterNoPublicIp
 * RdsSnapshotEncrypted
 * VpcSgOpenOnlyToAuthorizedPorts
 *
 * A number of other checks from the NZISM Conformance Packs are account level checkes, and are excluded from stack level checks.
 *
 *
 * */

export class NZISM36Checks extends NagPack {
  constructor(props?: NagPackProps) {
    super(props);
    this.packName = 'NZISM.36.1022.20';
  }
  public visit(node: IConstruct): void {
    if (node instanceof CfnResource) {
      this.checkELB(node);
      this.checkAPIGW(node);
      this.checkCloudTrail(node);
      this.checkCloudFront(node);
      this.checkKMS(node);
      this.checkCloudWatch(node);
      this.checkRDS(node);
      this.checkECS(node);
      this.checkEFS(node);
      this.checkDMS(node);
      this.checkDynamoDB(node);
      this.checkEC2(node);
      this.checkElasticBeanstalk(node);
      this.checkElastiCache(node);
      this.checkOpenSearch(node);
      this.checkIAM(node);
      this.checkLambda(node);
      this.checkRedshift(node);
      this.checkS3(node);
      this.checkSageMaker(node);
      this.checkSecretsManager(node);
      this.checkSNS(node);
      this.checkVPC(node);
      this.checkWAF(node);
    }
  }

  /**
   * Check API Gateway Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkAPIGW(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 16.6.10.C.02[CID:2013], MUST 23.5.11.C.01[CID:7496]| Access Control and Passwords/Event Logging and Auditing/Additional events to be logged & Public Cloud Security/Logging and Alerting in Public Cloud/Logging requirements.',
      explanation:
        'API Gateway logging displays detailed views of users who accessed the API and the way they accessed the API. This insight enables visibility of user activities.',
      level: NagMessageLevel.ERROR,
      rule: APIGWExecutionLoggingEnabled,
      node: node,
    });
  }

  /**
   * Check CloudFront Resources
   * @param node
   * @param ignores
   */
  private checkCloudFront(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 16.6.10.C.02[CID:2013], MUST 23.5.11.C.01[CID:7496]| Access Control and Passwords/Event Logging and Auditing/Additional events to be logged & Public Cloud Security/Logging and Alerting in Public Cloud/Logging requirements',
      explanation: 'CloudFrontDistributionAccessLogging',
      level: NagMessageLevel.ERROR,
      rule: CloudFrontDistributionAccessLogging,
      node: node,
    });
    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562]| Gateway security/Gateways/Configuration of gateways',
      explanation:
        'The Web Application Firewall can help protect against application-layer attacks that can compromise the security of the system or place unnecessary load on them.',
      level: NagMessageLevel.ERROR,
      rule: CloudFrontDistributionWAFIntegration,
      node: node,
    });

    this.applyRule({
      info: 'MUST 16.1.37.C.01[CID:1847]| Access Control and Passwords/Identification, Authentication and Passwords/Protecting authentication data in transit',
      explanation:
        'Vulnerabilities have been and continue to be discovered in the deprecated SSL and TLS protocols. Help protect viewer connections by specifying a viewer certificate that enforces a minimum of TLSv1.1 or TLSv1.2 in the security policy. Distributions that use the default CloudFront viewer certificate or use vip for the SslSupportMethod are non-compliant with this rule, as the minimum security policy is set to TLSv1 regardless of the specified MinimumProtocolVersion',
      level: NagMessageLevel.ERROR,
      rule: CloudFrontDistributionHttpsViewerNoOutdatedSSL,
      node: node,
    });
  }

  /**
   * Check CloudTrail Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkCloudTrail(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 16.6.6.C.02[CID:1998], MUST 16.4.35.C.02[CID:6860]| Access Control and Passwords: (Event Logging and Auditing/Maintaining system management logs & Privileged Access Management/Monitoring and Review)',
      explanation:
        'Use Amazon CloudWatch to centrally collect and manage log event activity. Inclusion of AWS CloudTrail data provides details of API call activity within your AWS account.',
      level: NagMessageLevel.ERROR,
      rule: CloudTrailCloudWatchLogsEnabled,
      node: node,
    });

    this.applyRule({
      info: 'SHOULD 17.1.46.C.04[CID:2082]| Cryptography/Cryptographic Fundamentals/Reducing storage and physical transfer requirements',
      explanation:
        'Because sensitive data may exist and to help protect data at rest, ensure encryption is enabled for your AWS CloudTrail trails.',
      level: NagMessageLevel.ERROR,
      rule: CloudTrailEncryptionEnabled,
      node: node,
    });

    this.applyRule({
      info: 'MUST 16.6.12.C.01[CID:2022], MUST 23.5.11.C.01[CID:7496]| Access Control and Passwords/Event Logging and Auditing/Event log protection & Public Cloud Security/Logging and Alerting in Public Cloud/Logging requirements.',
      explanation:
        'Utilize AWS CloudTrail log file validation to check the integrity of CloudTrail logs. Log file validation helps determine if a log file was modified or deleted or unchanged after CloudTrail delivered it. This feature is built using industry standard algorithms: SHA-256 for hashing and SHA-256 with RSA for digital signing. This makes it computationally infeasible to modify, delete or forge CloudTrail log files without detection.',
      level: NagMessageLevel.ERROR,
      rule: CloudTrailLogFileValidationEnabled,
      node: node,
    });
  }

  /**
   * Check CloudWatch Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */

  private checkCloudWatch(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 16.6.6.C.02[CID:1998], MUST 16.6.13.C.01[CID:2028]| Access Control and Passwords/Event Logging and Auditing: (Maintaining system management logs & Event log archives)',
      explanation:
        'Ensure a minimum duration of event log data is retained for your log groups to help with troubleshooting and forensics investigations. The lack of available past event log data makes it difficult to reconstruct and identify potentially malicious events.',
      level: NagMessageLevel.ERROR,
      rule: CloudWatchLogGroupRetentionPeriod,
      node: node,
    });
  }

  /**
   * Check DMS Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkDMS(node: CfnResource) {
    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways/Configuration of gateways & Public Cloud Security/Data Protection in Public Cloud/Data accessibility',
      explanation:
        'DMS replication instances can contain sensitive information and access control is required for such accounts.',
      level: NagMessageLevel.ERROR,
      rule: DMSReplicationNotPublic,
      node: node,
    });
  }

  /**
   * Check DynamoDB Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkDynamoDB(node: CfnResource) {
    this.applyRule({
      info: 'MUST 22.1.23.C.01[CID:4829]| Enterprise systems security/Cloud Computing/System Availability',
      explanation:
        'Amazon DynamoDB auto scaling uses the AWS Application Auto Scaling service to adjust provisioned throughput capacity that automatically responds to actual traffic patterns. This enables a table or a global secondary index to increase its provisioned read/write capacity to handle sudden increases in traffic, without throttling.',
      level: NagMessageLevel.ERROR, // TODO:  Why is this an error.
      rule: DynamoDBAutoScalingEnabled,
      node: node,
    });
    this.applyRule({
      info: 'MUST 22.1.26.C.01[CID:4849]| Enterprise systems security/Cloud Computing/Backup, Recovery Archiving and Data Remanenc',
      explanation:
        'To help with data back-up processes, ensure your Amazon DynamoDB tables are a part of an AWS Backup plan. AWS Backup is a fully managed backup service with a policy-based backup solution. This solution simplifies your backup management and enables you to meet your business and regulatory backup compliance requirements.',
      level: NagMessageLevel.ERROR,
      rule: DynamoDBInBackupPlan,
      node: node,
    });
    this.applyRule({
      info: 'MUST 22.1.26.C.01[CID:4849]| Enterprise systems security/Cloud Computing/Backup, Recovery Archiving and Data Remanence',
      explanation:
        'The recovery maintains continuous backups of your table for the last 35 days.',
      level: NagMessageLevel.ERROR,
      rule: DynamoDBPITREnabled,
      node: node,
    });
  }

  /**
   * Check EC2 Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkEC2(node: CfnResource): void {
    this.applyRule({
      info: 'MUST 22.1.26.C.01[CID:4849]| Enterprise systems security/Cloud Computing/Backup, Recovery Archiving and Data Remanence',
      explanation:
        'To help with data back-up processes, ensure your Amazon Elastic Block Store (Amazon EBS) volumes are a part of an AWS Backup plan. AWS Backup is a fully managed backup service with a policy-based backup solution. This solution simplifies your backup management and enables you to meet your business and regulatory backup compliance requirements.',
      level: NagMessageLevel.ERROR,
      rule: EC2EBSInBackupPlan,
      node: node,
    });

    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways/Configuration of gateways & Public Cloud Security/Data Protection in Public Cloud/Data accessibilit',
      explanation:
        'Manage access to the AWS Cloud by ensuring Amazon Elastic Compute Cloud (Amazon EC2) instances cannot be publicly accessed. Amazon EC2 instances can contain sensitive information and access control is required for such accounts.',
      level: NagMessageLevel.ERROR,
      rule: EC2InstanceNoPublicIp,
      node: node,
    });

    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways/Configuration of gateways & Public Cloud Security/Data Protection in Public Cloud/Data accessibilit',
      explanation:
        'Deploy Amazon Elastic Compute Cloud (Amazon EC2) instances within an Amazon Virtual Private Cloud (Amazon VPC) to enable secure communication between an instance and other services within the amazon VPC, without requiring an internet gateway, NAT device, or VPN connection. All traffic remains securely within the AWS Cloud. Because of their logical isolation, domains that reside within anAmazon VPC have an extra layer of security when compared to domains that use public endpoints. Assign Amazon EC2 instances to an Amazon VPC to properly manage access.',
      level: NagMessageLevel.ERROR,
      rule: EC2InstancesInVPC,
      node: node,
    });

    this.applyRule({
      info: 'SHOULD 17.1.46.C.04[CID:2082], SHOULD 22.1.24.C.04[CID:4839]| Cryptography/Cryptographic Fundamentals/Reducing storage and physical transfer requirements & Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'With EBS encryption, you aren not required to build, maintain, and secure your own key management infrastructure. EBS encryption uses KMS keys when creating encrypted volumes and snapshots. This helps protect data at rest.',
      level: NagMessageLevel.ERROR,
      rule: EC2EBSVolumeEncrypted,
      node: node,
    });

    this.applyRule({
      info: 'SHOULD 17.5.8.C.02[CID:2726]| Cryptography/Secure Shell/Automated remote access',
      explanation:
        'Not allowing ingress (or remote) traffic from 0.0.0.0/0 or ::/0 to port 22 on your resources helps to restrict remote access.',
      level: NagMessageLevel.ERROR,
      rule: EC2RestrictedSSH,
      node: node,
    });
  }

  /**
   * Check ECS Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkECS(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 14.1.8.C.01[CID:1149]| Software security/Standard Operating Environments/Developing hardened SOEs',
      explanation:
        'If a task definition has elevated privileges it is because you have specifically opted-in to those configurations. This rule checks for unexpected privilege escalation when a task definition has host networking enabled but the customer has not opted-in to elevated privileges.',
      level: NagMessageLevel.ERROR,
      rule: ECSTaskDefinitionUserForHostMode,
      node: node,
    });
  }

  /**
   * Check EFS Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkEFS(node: CfnResource) {
    this.applyRule({
      info: 'MUST 22.1.26.C.01[CID:4849]| Enterprise systems security/Cloud Computing/Backup, Recovery Archiving and Data Remanence',
      explanation:
        'To help with data back-up processes, ensure your Amazon Elastic File System (Amazon EFS) file systems are a part of an AWS Backup plan. AWS Backup is a fully managed backup service with a policy-based backup solution. This solution simplifies your backup management and enables you to meet your business and regulatory backup compliance requirements.',
      level: NagMessageLevel.ERROR,
      rule: EFSInBackupPlan,
      node: node,
    });
    this.applyRule({
      info: 'SHOULD 17.1.46.C.04[CID:2082], SHOULD 22.1.24.C.04[CID:4839]| Cryptography/Cryptographic Fundamentals/Reducing storage and physical transfer requirements & Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'Because sensitive data can exist and to help protect data at rest, ensure encryption is enabled for your Amazon Elastic File System (EFS).',
      level: NagMessageLevel.ERROR,
      rule: EFSEncrypted,
      node: node,
    });
  }

  /**
   * Check ElastiCache Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkElastiCache(node: CfnResource) {
    this.applyRule({
      info: 'MUST 22.1.26.C.01[CID:4849]| Enterprise systems security/Cloud Computing/Backup, Recovery Archiving and Data Remanence',
      explanation:
        'Automatic backups can help guard against data loss. If a failure occurs, you can create a new cluster, which restores your data from the most recent backup.',
      level: NagMessageLevel.ERROR,
      rule: ElastiCacheRedisClusterAutomaticBackup,
      node: node,
    });
  }

  /**
   * Check Elastic Beanstalk Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkElasticBeanstalk(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 12.4.4.C.05[CID:3452]| Product Security/Product Patching and Updating/Patching vulnerabilities in products.',
      explanation:
        'Enabling managed platform updates for an Amazon Elastic Beanstalk environment ensures that the latest available platform fixes, updates, and features for the environment are installed. Keeping up to date with patch installation is a best practice in securing systems.',
      level: NagMessageLevel.ERROR,
      rule: ElasticBeanstalkManagedUpdatesEnabled,
      node: node,
    });
  }

  /**
   * Check Elastic Load Balancer Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */

  private checkELB(node: CfnResource): void {
    this.applyRule({
      info: 'MUST 16.1.37.C.01[CID:1847], MUST 17.1.48.C.03[CID:2091]| Access Control and Passwords/Identification, Authentication and Passwords/Protecting authentication data in transit & Cryptography/Cryptographic Fundamentals/Information and Systems Protection',
      explanation:
        'To help protect data in transit, ensure that your Application Load Balancer automatically redirects unencrypted HTTP requests to HTTPS. Because sensitive data can exist, enable encryption in transit to help protect that data.',
      level: NagMessageLevel.ERROR,
      rule: ALBHttpToHttpsRedirection,
      node: node,
    });

    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], SHOULD 20.3.7.C.02[CID:4333], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways/Configuration of gateways & Data management/Content Filtering/Content validation & Public Cloud Security/Data Protection in Public Cloud...',
      explanation:
        'A WAF helps to protect your web applications or APIs against common web exploits. These web exploits may affect availability, compromise security, or consume excessive resources within your environment.',
      level: NagMessageLevel.ERROR,
      rule: ALBWAFEnabled,
      node: node,
    });

    this.applyRule({
      info: 'MUST 22.1.23.C.01[CID:4829]| Enterprise systems security/Cloud Computing/System Availability',
      explanation:
        "Enable cross-zone load balancing for your Classic Load Balancers (CLBs) to help maintain adequate capacity and availability. The cross-zone load balancing reduces the need to maintain equivalent numbers of instances in each enabled availability zone. It also improves your application's ability to handle the loss of one or more instances.",
      level: NagMessageLevel.ERROR,
      rule: ELBCrossZoneLoadBalancingEnabled,
      node: node,
    });
    this.applyRule({
      info: 'SHOULD 16.6.10.C.02[CID:2013], MUST 23.5.11.C.01[CID:7496]| Access Control and Passwords/Event Logging and Auditing/Additional events to be logged & Public Cloud Security/Logging and Alerting in Public Cloud/Logging requirements',
      explanation:
        "Elastic Load Balancing activity is a central point of communication within an environment. Ensure ELB logging is enabled. The collected data provides detailed information about requests sent to The ELB. Each log contains information such as the time the request was received, the client's IP address, latencies, request paths, and server responses.",
      level: NagMessageLevel.ERROR,
      rule: ELBLoggingEnabled,
      node: node,
    });
    this.applyRule({
      info: 'SHOULD 14.5.8.C.01[CID:1667], MUST 16.1.37.C.01[CID:1847], MUST 17.1.48.C.03[CID:2091], SHOULD 22.1.24.C.04[CID:4839]| Software security/Web Application Development/Web applications & Access Control and Passwords/Identification, Authentication and Pa...',
      explanation:
        'Ensure that your Classic Load Balancers (CLBs) are configured with SSL or HTTPS listeners. Because sensitive data can exist, enable encryption in transit to help protect that data.',
      level: NagMessageLevel.ERROR,
      rule: ELBTlsHttpsListenersOnly,
      node: node,
    });
  }

  /**
   * Check IAM Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkIAM(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 16.3.5.C.02[CID:1946]| Access Control and Passwords/Privileged User Access/Use of privileged accounts',
      explanation:
        'AWS Identity and Access Management (IAM) can help you incorporate the principles of least privilege and separation of duties with access permissions and authorizations, by ensuring that IAM groups have at least one IAM user. Placing IAM users in groups based on their associated permissions or job function is one way to incorporate least privilege.',
      level: NagMessageLevel.ERROR,
      rule: IAMPolicyNoStatementsWithAdminAccess,
      node: node,
    });
  }

  /**
   * Check KMS Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkKMS(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 17.9.25.C.01[CID:3021]| Cryptography/Key Management/Contents of KMPs.',
      explanation:
        'Enable key rotation to ensure that keys are rotated once they have reached the end of their crypto period.',
      level: NagMessageLevel.ERROR,
      rule: KMSBackingKeyRotationEnabled,
      node: node,
    });
  }

  /**
   * Check Lambda Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkLambda(node: CfnResource) {
    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways/Configuration of gateways & Public Cloud Security/Data Protection in Public Cloud/Data accessibility',
      explanation:
        'Because of their logical isolation, domains that reside within an Amazon VPC have an extra layer of security when compared to domains that use public endpoints.',
      level: NagMessageLevel.ERROR,
      rule: LambdaInsideVPC,
      node: node,
    });
  }

  /**
   * Check OpenSearch Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkOpenSearch(node: CfnResource) {
    this.applyRule({
      info: 'SHOULD 17.1.46.C.04[CID:2082], SHOULD 20.4.4.C.02[CID:4441], SHOULD 22.1.24.C.04[CID:4839]| Cryptography/Cryptographic Fundamentals/Reducing storage and physical transfer requirements & Data management/Databases/Database files & Enterprise systems se..',
      explanation:
        'Because sensitive data can exist and to help protect data at rest, ensure encryption is enabled for your Amazon OpenSearch Service (OpenSearch Service) domains.',
      level: NagMessageLevel.ERROR,
      rule: OpenSearchEncryptedAtRest,
      node: node,
    });

    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], SHOULD 19.1.14.C.02[CID:3623], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways: (Configuration of gateways & Demilitarised zones) & Public Cloud Security/Data Protection in Public Cloud/Data accessibility',
      explanation:
        'VPCs help secure your AWS resources and provide an extra layer of protection.',
      level: NagMessageLevel.ERROR,
      rule: OpenSearchInVPCOnly,
      node: node,
    });

    this.applyRule({
      info: 'MUST 16.1.37.C.01[CID:1847], SHOULD 22.1.24.C.04[CID:4839]| Access Control and Passwords/Identification, Authentication and Passwords/Protecting authentication data in transit & Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'Because sensitive data can exist, enable encryption in transit to help protect that data within your Amazon OpenSearch Service (OpenSearch Service) domains.',
      level: NagMessageLevel.ERROR,
      rule: OpenSearchNodeToNodeEncryption,
      node: node,
    });
  }

  /**
   * Check RDS Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkRDS(node: CfnResource): void {
    this.applyRule({
      info: 'MUST 22.1.26.C.01[CID:4849]| Enterprise systems security/Cloud Computing/Backup, Recovery Archiving and Data Remanence',
      explanation:
        'Ensure Amazon Relational Database Service (Amazon RDS) instances and clusters have deletion protection enabled. Use deletion protection to prevent your Amazon RDS DB instances and clusters from being accidentally or maliciously deleted, which can lead to loss of availability for your applications.',
      level: NagMessageLevel.ERROR,
      rule: RDSInstanceDeletionProtectionEnabled,
      node: node,
    });

    this.applyRule({
      info: 'The RDS DB Instance does not have multi-AZ support - (Control IDs: CP-1a.1(b), CP-1a.2, CP-2a, CP-2a.6, CP-2a.7, CP-2d, CP-2e, CP-2(5), CP-2(6), CP-6(2), CP-10, SC-5(2), SC-6, SC-22, SC-36, SI-13(5)).',
      explanation:
        'MUST 22.1.23.C.01[CID:4829]| Enterprise systems security/Cloud Computing/System Availability',
      level: NagMessageLevel.ERROR,
      rule: RDSMultiAZSupport,
      node: node,
    });

    this.applyRule({
      info: 'MUST 22.1.26.C.01[CID:4849]| Enterprise systems security/Cloud Computing/Backup, Recovery Archiving and Data Remanence',
      explanation:
        'To help with data back-up processes, ensure your Amazon Relational Database Service (Amazon RDS) instances are a part of an AWS Backup plan. AWS Backup is a fully managed backup service with a policy-based backup solution. This solution simplifies your backup management and enables you to meet your business and regulatory backup compliance requirements.',
      level: NagMessageLevel.ERROR,
      rule: RDSInBackupPlan,
      node: node,
    });

    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], SHOULD 19.1.14.C.02[CID:3623], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways: (Configuration of gateways & Demilitarised zones) & Public Cloud Security/Data Protection in Public Cloud/Data accessibility',
      explanation:
        'Amazon RDS database instances can contain sensitive information, and principles and access control is required for such accounts.',
      level: NagMessageLevel.ERROR,
      rule: RDSInstancePublicAccess,
      node: node,
    });

    this.applyRule({
      info: 'SHOULD 16.6.10.C.02[CID:2013], SHOULD 20.4.4.C.02[CID:4441], SHOULD 20.4.5.C.02[CID:4445], MUST 23.5.11.C.01[CID:7496]| Access Control and Passwords/Event Logging and Auditing/Additional events to be logged & Data management/Databases: (Database file...',
      explanation:
        'To help with logging and monitoring within your environment, ensure Amazon Relational Database Service (Amazon RDS) logging is enabled. With Amazon RDS logging, you can capture events such as connections, disconnections, queries, or tables queried.' +
        "This is a granular rule that returns individual findings that can be suppressed with 'appliesTo'. The findings are in the format 'LogExport::<log>' for exported logs. Example: appliesTo: ['LogExport::audit'].",
      level: NagMessageLevel.ERROR,
      rule: RDSLoggingEnabled,
      node: node,
    });

    this.applyRule({
      info: 'SHOULD 17.1.46.C.04[CID:2082], SHOULD 20.4.4.C.02[CID:4441], SHOULD 22.1.24.C.04[CID:4839]| Cryptography/Cryptographic Fundamentals/Reducing storage and physical transfer requirements & Data management/Databases/Database files & Enterprise systems se..',
      explanation:
        'Because sensitive data can exist at rest in Amazon RDS instances, enable encryption at rest to help protect that data.',
      level: NagMessageLevel.ERROR,
      rule: RDSStorageEncrypted,
      node: node,
    });

    // below this not checked
  }

  /**
   * Check Redshift Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkRedshift(node: CfnResource): void {
    this.applyRule({
      info: 'MUST 22.1.26.C.01[CID:4849]| Enterprise systems security/Cloud Computing/Backup, Recovery Archiving and Data Remanence',
      explanation:
        'To help with data back-up processes, ensure your Amazon Redshift clusters have automated snapshots. When automated snapshots are enabled for a cluster, Redshift periodically takes snapshots of that cluster. By default, Redshift takes a snapshot every eight hours or every 5 GB per node of data changes, or whichever comes first.',
      level: NagMessageLevel.ERROR,
      rule: RedshiftBackupEnabled,
      node: node,
    });

    this.applyRule({
      info: 'SHOULD 20.4.4.C.02[CID:4441], SHOULD 20.4.5.C.02[CID:4445], SHOULD 22.1.24.C.04[CID:4839]| Data management/Databases: (Database files & Accountability) & Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'To protect data at rest, ensure that encryption is enabled for your Amazon Redshift clusters. You must also ensure that required configurations are deployed on Amazon Redshift clusters. The audit logging should be enabled to provide information about connections and user activities in the database.',
      level: NagMessageLevel.ERROR,
      rule: RedshiftClusterConfiguration,
      node: node,
    });

    this.applyRule({
      info: 'MUST 12.4.4.C.02[CID:3449], SHOULD 12.4.4.C.06[CID:3453]| Product Security/Product Patching and Updating/Patching vulnerabilities in products',
      explanation:
        'Ensure that Amazon Redshift clusters have the preferred settings for your organization. Specifically, that they have preferred maintenance windows and automated snapshot retention periods for the database.                                                                            ',
      level: NagMessageLevel.ERROR,
      rule: RedshiftClusterMaintenanceSettings,
      node: node,
    });

    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], SHOULD 19.1.14.C.02[CID:3623], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways: (Configuration of gateways & Demilitarised zones) & Public Cloud Security/Data Protection in Public Cloud/Data accessibility',
      explanation:
        'Amazon Redshift clusters can contain sensitive information and principles and access control is required for such accounts.',
      level: NagMessageLevel.ERROR,
      rule: RedshiftClusterPublicAccess,
      node: node,
    });

    this.applyRule({
      info: 'MUST 17.1.48.C.03[CID:2091], SHOULD 22.1.24.C.04[CID:4839]| Cryptography/Cryptographic Fundamentals/Information and Systems Protection & Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'Ensure that your Amazon Redshift clusters require TLS/SSL encryption to connect to SQL clients. Because sensitive data can exist, enable encryption in transit to help protect that data.',
      level: NagMessageLevel.ERROR,
      rule: RedshiftRequireTlsSSL,
      node: node,
    });
  }

  /**
   * Check Amazon S3 Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkS3(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 22.1.24.C.03[CID:4838]| Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'Keep sensitive data safe from unauthorized remote users by preventing public access at the bucket level.',
      level: NagMessageLevel.ERROR,
      rule: S3BucketLevelPublicAccessProhibited,
      node: node,
    });
    this.applyRule({
      info: 'SHOULD 17.1.46.C.04[CID:2082]| Cryptography/Cryptographic Fundamentals/Reducing storage and physical transfer requirements',
      explanation:
        'Because sensitive data can exist at rest in Amazon S3 buckets, enable encryption to help protect that data.',
      level: NagMessageLevel.ERROR,
      rule: S3BucketServerSideEncryptionEnabled,
      node: node,
    });
    this.applyRule({
      info: 'SHOULD 22.1.24.C.04[CID:4839]| Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'To help protect data in transit, ensure that your Amazon Simple Storage Service (Amazon S3) buckets require requests to use Secure Socket Layer (SSL). Because sensitive data can exist, enable encryption in transit to help protect that data.',
      level: NagMessageLevel.ERROR,
      rule: S3BucketSSLRequestsOnly,
      node: node,
    });
    this.applyRule({
      info: 'MUST 22.1.26.C.01[CID:4849]| Enterprise systems security/Cloud Computing/Backup, Recovery Archiving and Data Remanence',
      explanation:
        'Amazon Simple Storage Service (Amazon S3) server access logging provides a method to monitor the network for potential cybersecurity events. The events are monitored by capturing detailed records for the requests that are made to an Amazon S3 bucket. Each access log record provides details about a single access request. The details include the requester, bucket name, request time, request action, response status, and an error code, if relevant.',
      level: NagMessageLevel.ERROR,
      rule: S3BucketLoggingEnabled,
      node: node,
    });

    this.applyRule({
      info: 'SHOULD 22.1.24.C.03[CID:4838]| Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'The management of access should be consistent with the classification of the data.',
      level: NagMessageLevel.ERROR,
      rule: S3BucketPublicReadProhibited,
      node: node,
    });
    this.applyRule({
      info: 'SHOULD 22.1.24.C.03[CID:4838]| Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'The management of access should be consistent with the classification of the data.',
      level: NagMessageLevel.ERROR,
      rule: S3BucketPublicWriteProhibited,
      node: node,
    });
    this.applyRule({
      info: 'MUST 22.1.26.C.01[CID:4849]| Enterprise systems security/Cloud Computing/Backup, Recovery Archiving and Data Remanence',
      explanation:
        'Use versioning to preserve, retrieve, and restore every version of every object stored in your Amazon S3 bucket. Versioning helps you to easily recover from unintended user actions and application failures.',
      level: NagMessageLevel.ERROR,
      rule: S3BucketVersioningEnabled,
      node: node,
    });
    this.applyRule({
      info: 'SHOULD 17.1.46.C.04[CID:2082]| Cryptography/Cryptographic Fundamentals/Reducing storage and physical transfer requirements',
      explanation:
        'Ensure that encryption is enabled for your Amazon Simple Storage Service (Amazon S3) buckets. Because sensitive data can exist at rest in an Amazon S3 bucket, enable encryption at rest to help protect that data.',
      level: NagMessageLevel.ERROR,
      rule: S3DefaultEncryptionKMS,
      node: node,
    });
  }

  /**
   * Check SageMaker Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkSageMaker(node: CfnResource) {
    this.applyRule({
      info: 'SHOULD 22.1.24.C.04[CID:4839]| Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'Because sensitive data can exist at rest in SageMaker endpoint, enable encryption at rest to help protect that data.',
      level: NagMessageLevel.ERROR,
      rule: SageMakerEndpointConfigurationKMSKeyConfigured,
      node: node,
    });
    this.applyRule({
      info: 'SHOULD 22.1.24.C.04[CID:4839]| Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'Because sensitive data can exist at rest in SageMaker notebook, enable encryption at rest to help protect that data.',
      level: NagMessageLevel.ERROR,
      rule: SageMakerNotebookInstanceKMSKeyConfigured,
      node: node,
    });
    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways/Configuration of gateways & Public Cloud Security/Data Protection in Public Cloud/Data accessibility',
      explanation:
        'By preventing direct internet access, you can keep sensitive data from being accessed by unauthorized users.',
      level: NagMessageLevel.ERROR,
      rule: SageMakerNotebookNoDirectInternetAccess,
      node: node,
    });
  }

  /**
   * Check Secrets Manager Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkSecretsManager(node: CfnResource): void {
    this.applyRule({
      info: 'The secret is not encrypted with a KMS Customer managed key - (Control IDs: AU-9(3), CP-9d, SC-8(3), SC-8(4), SC-13a, SC-28(1), SI-19(4)).',
      explanation:
        'SHOULD 22.1.24.C.04[CID:4839]| Enterprise systems security/Cloud Computing/Unauthorised Access',
      level: NagMessageLevel.ERROR,
      rule: SecretsManagerUsingKMSKey,
      node: node,
    });
  }

  /**
   * Check Amazon SNS Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkSNS(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 22.1.24.C.04[CID:4839]| Enterprise systems security/Cloud Computing/Unauthorised Access',
      explanation:
        'To help protect data at rest, ensure that your Amazon Simple Notification Service (Amazon SNS) topics require encryption using AWS Key Management Service (AWS KMS) Because sensitive data can exist at rest in published messages, enable encryption at rest to help protect that data.',
      level: NagMessageLevel.ERROR,
      rule: SNSEncryptedKMS,
      node: node,
    });
  }

  /**
   * Check VPC Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkVPC(node: CfnResource): void {
    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways/Configuration of gateways & Public Cloud Security/Data Protection in Public Cloud/Data accessibility',
      explanation:
        'Amazon Elastic Compute Cloud (Amazon EC2) security groups can help in the management of network access by providing stateful filtering of ingress and egress network traffic to AWS resources. Restricting all the traffic on the default security group helps in restricting remote access to your AWS resources.',
      level: NagMessageLevel.WARN,
      rule: VPCDefaultSecurityGroupClosed,
      node: node,
    });
    this.applyRule({
      info: 'MUST 19.1.12.C.01[CID:3562], MUST 23.4.10.C.01[CID:7466]| Gateway security/Gateways/Configuration of gateways & Public Cloud Security/Data Protection in Public Cloud/Data accessibility',
      explanation:
        'The VPC flow logs provide detailed records for information about the IP traffic going to and from network interfaces in your Amazon Virtual Private Cloud (Amazon VPC). By default, the flow log record includes values for the different components of the IP flow, including the source, destination, and protocol.',
      level: NagMessageLevel.ERROR,
      rule: VPCFlowLogsEnabled,
      node: node,
    });
  }

  /**
   * Check WAF Resources
   * @param node the CfnResource to check
   * @param ignores list of ignores for the resource
   */
  private checkWAF(node: CfnResource): void {
    this.applyRule({
      info: 'SHOULD 16.6.10.C.02[CID:2013], MUST 23.5.11.C.01[CID:7496]| Access Control and Passwords/Event Logging and Auditing/Additional events to be logged & Public Cloud Security/Logging and Alerting in Public Cloud/Logging requirements',
      explanation:
        'AWS WAF logging provides detailed information about the traffic that is analyzed by your web ACL. The logs record the time that AWS WAF received the request from your AWS resource, information about the request, and an action for the rule that each request matched.',
      level: NagMessageLevel.ERROR,
      rule: WAFv2LoggingEnabled,
      node: node,
    });
  }
}
