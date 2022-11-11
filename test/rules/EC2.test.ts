/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
import {
  AutoScalingGroup,
  CfnAutoScalingGroup,
  CfnLaunchConfiguration,
  Monitoring,
} from 'aws-cdk-lib/aws-autoscaling';
import { BackupPlan, BackupResource } from 'aws-cdk-lib/aws-backup';
import {
  Instance,
  InstanceClass,
  InstanceType,
  MachineImage,
  Peer,
  Port,
  SecurityGroup,
  Vpc,
  CfnInstance,
  CfnSecurityGroupIngress,
  CfnSecurityGroup,
  InstanceSize,
  Volume,
  CfnLaunchTemplate,
} from 'aws-cdk-lib/aws-ec2';

import * as cdk_ec2 from 'aws-cdk-lib/aws-ec2';

import { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { Aspects, Stack, Size } from 'aws-cdk-lib/core';
import {
  EC2EBSInBackupPlan,
  EC2EBSOptimizedInstance,
  EC2EBSVolumeEncrypted,
  EC2InstanceDetailedMonitoringEnabled,
  EC2InstanceNoPublicIp,
  EC2InstanceProfileAttached,
  EC2InstanceTerminationProtection,
  EC2InstancesInVPC,
  EC2RestrictedCommonPorts,
  EC2RestrictedInbound,
  EC2RestrictedSSH,
  EC2SecurityGroupDescription,
  EC2SecurityGroupOnlyTcp443,
  EC2IMDSv2,
} from '../../src/rules/ec2';
import { validateStack, TestType, TestPack } from './utils';

const testPack = new TestPack([
  EC2EBSInBackupPlan,
  EC2EBSOptimizedInstance,
  EC2EBSVolumeEncrypted,
  EC2InstanceDetailedMonitoringEnabled,
  EC2InstanceNoPublicIp,
  EC2InstanceProfileAttached,
  EC2InstanceTerminationProtection,
  EC2InstancesInVPC,
  EC2RestrictedCommonPorts,
  EC2RestrictedInbound,
  EC2RestrictedSSH,
  EC2SecurityGroupDescription,
  EC2SecurityGroupOnlyTcp443,
  EC2IMDSv2,
]);
let stack: Stack;

beforeEach(() => {
  stack = new Stack();
  Aspects.of(stack).add(testPack);
});

describe('Amazon Elastic Compute Cloud (Amazon EC2)', () => {
  describe('EC2EBSInBackupPlan: EBS volumes are part of AWS Backup plan(s)', () => {
    const ruleId = 'EC2EBSInBackupPlan';
    test('Noncompliance 1', () => {
      new Volume(stack, 'rVolume', {
        availabilityZone: 'us-east-1a',
        size: Size.gibibytes(42),
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 2', () => {
      new Volume(stack, 'rVolume', {
        availabilityZone: 'us-east-1a',
        size: Size.gibibytes(42),
      });
      BackupPlan.dailyWeeklyMonthly5YearRetention(stack, 'rPlan').addSelection(
        'Selection',
        {
          resources: [
            BackupResource.fromArn(
              'arn:aws:ec2:us-east-1:123456789012:volume/' +
                new Volume(stack, 'rVolume2', {
                  availabilityZone: 'us-east-1a',
                  size: Size.gibibytes(42),
                }).volumeId
            ),
          ],
        }
      );
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      BackupPlan.dailyWeeklyMonthly5YearRetention(stack, 'rPlan').addSelection(
        'Selection',
        {
          resources: [
            BackupResource.fromArn(
              'arn:aws:ec2:us-east-1:123456789012:volume/' +
                new Volume(stack, 'rVolume', {
                  availabilityZone: 'us-east-1a',
                  size: Size.gibibytes(42),
                }).volumeId
            ),
          ],
        }
      );
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });

  describe('EC2EBSOptimizedInstance: EC2 instance types that support EBS optimization and are not EBS optimized by default have EBS optimization enabled', () => {
    const ruleId = 'EC2EBSOptimizedInstance';
    test('Noncompliance 1', () => {
      new Instance(stack, 'rInstance', {
        vpc: new Vpc(stack, 'rVpc'),
        instanceType: InstanceType.of(InstanceClass.C3, InstanceSize.XLARGE),
        machineImage: MachineImage.latestAmazonLinux(),
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      new Instance(stack, 'rInstance', {
        vpc: new Vpc(stack, 'rVpc'),
        instanceType: InstanceType.of(InstanceClass.C3, InstanceSize.XLARGE),
        machineImage: MachineImage.latestAmazonLinux(),
      }).instance.ebsOptimized = true;
      new Instance(stack, 'rInstance2', {
        vpc: new Vpc(stack, 'rVpc2'),
        instanceType: InstanceType.of(InstanceClass.A1, InstanceSize.MEDIUM),
        machineImage: MachineImage.latestAmazonLinux(),
      });
      new CfnInstance(stack, 'rInstance3');
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });

  describe('EC2InstanceDetailedMonitoringEnabled: EC2 instances have detailed monitoring enabled', () => {
    const ruleId = 'EC2InstanceDetailedMonitoringEnabled';
    test('Noncompliance 1', () => {
      new Instance(stack, 'rInstance', {
        vpc: new Vpc(stack, 'rVpc'),
        instanceType: new InstanceType(InstanceClass.T3),
        machineImage: MachineImage.latestAmazonLinux(),
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 1', () => {
      new AutoScalingGroup(stack, 'rAsg', {
        vpc: new Vpc(stack, 'rVpc'),
        instanceType: new InstanceType(InstanceClass.T3),
        machineImage: MachineImage.latestAmazonLinux(),
        instanceMonitoring: Monitoring.BASIC,
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      new Instance(stack, 'rInstance', {
        vpc: new Vpc(stack, 'rVpc'),
        instanceType: new InstanceType(InstanceClass.T3),
        machineImage: MachineImage.latestAmazonLinux(),
      }).instance.monitoring = true;
      new AutoScalingGroup(stack, 'rAsg', {
        vpc: new Vpc(stack, 'rVpc2'),
        instanceType: new InstanceType(InstanceClass.T3),
        machineImage: MachineImage.latestAmazonLinux(),
        instanceMonitoring: Monitoring.DETAILED,
      });
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });

  describe('EC2InstanceNoPublicIp: EC2 instances do not have public IPs', () => {
    const ruleId = 'EC2InstanceNoPublicIp';
    test('Noncompliance 1', () => {
      new CfnInstance(stack, 'rInstance', {
        imageId: 'nonCompliantInstance',
        networkInterfaces: [
          {
            associatePublicIpAddress: true,
            deviceIndex: '0',
          },
        ],
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      new CfnInstance(stack, 'rInstance1', {
        imageId: 'compliantInstance',
        networkInterfaces: [
          {
            associatePublicIpAddress: false,
            deviceIndex: '0',
          },
        ],
      });
      new CfnInstance(stack, 'rInstance2', {
        imageId: 'compliantInstance',
        networkInterfaces: [],
      });
      new Instance(stack, 'rInstance3', {
        vpc: new Vpc(stack, 'rVpc'),
        instanceType: new InstanceType(InstanceClass.T3),
        machineImage: MachineImage.latestAmazonLinux(),
      });
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });

  describe('EC2InstanceProfileAttached: EC2 instances have an instance profile attached', () => {
    const ruleId = 'EC2InstanceProfileAttached';
    test('Noncompliance 1', () => {
      new CfnInstance(stack, 'rInstance');
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });

    test('Compliance', () => {
      new Instance(stack, 'rInstance', {
        vpc: new Vpc(stack, 'rVpc'),
        instanceType: InstanceType.of(InstanceClass.C3, InstanceSize.XLARGE),
        machineImage: MachineImage.latestAmazonLinux(),
      }).addToRolePolicy(
        new PolicyStatement({
          actions: ['s3:ListAllMyBuckets'],
          resources: ['arn:aws:s3:::*'],
        })
      );
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });

  describe('EC2InstanceTerminationProtection: EC2 Instances outside of an ASG have Termination Protection enabled', () => {
    const ruleId = 'EC2InstanceTerminationProtection';
    test('Noncompliance 1', () => {
      new Instance(stack, 'rInstance', {
        vpc: new Vpc(stack, 'rVpc'),
        instanceType: new InstanceType(InstanceClass.T3),
        machineImage: MachineImage.latestAmazonLinux(),
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });

    test('Compliance', () => {
      const instance = new Instance(stack, 'rInstance', {
        vpc: new Vpc(stack, 'rVpc'),
        instanceType: new InstanceType(InstanceClass.T3),
        machineImage: MachineImage.latestAmazonLinux(),
      });
      instance.instance.disableApiTermination = true;
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });

  describe('EC2InstancesInVPC: EC2 instances are created within VPCs', () => {
    const ruleId = 'EC2InstancesInVPC';
    test('Noncompliance 1', () => {
      new CfnInstance(stack, 'rInstance1', {
        imageId: 'nonCompliantInstance',
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      new CfnInstance(stack, 'rInstance2', {
        imageId: 'compliantInstance',
        subnetId: 'describeSubnet',
      });
      new Instance(stack, 'rInstance', {
        vpc: new Vpc(stack, 'rVpc'),
        instanceType: new InstanceType(InstanceClass.T3),
        machineImage: MachineImage.latestAmazonLinux(),
      });
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });

  describe('EC2RestrictedCommonPorts: EC2 instances have all common TCP ports restricted for ingress IPv4 traffic', () => {
    const ruleId = 'EC2RestrictedCommonPorts';
    test('Noncompliance 1', () => {
      new CfnSecurityGroup(stack, 'rSecurityGroup', {
        groupDescription: 'security group tcp port 20 open',
        securityGroupIngress: [
          {
            fromPort: 20,
            ipProtocol: 'tcp',
            cidrIp: '0.0.0.0/0',
          },
        ],
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 2', () => {
      new CfnSecurityGroup(stack, 'rSecurityGroup', {
        groupDescription: 'security group with SSH unrestricted',
        securityGroupIngress: [
          {
            fromPort: 21,
            ipProtocol: 'tcp',
            cidrIp: '0.0.0.0/0',
          },
        ],
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 3', () => {
      new SecurityGroup(stack, 'rSg', {
        vpc: new Vpc(stack, 'rVpc'),
      }).addIngressRule(Peer.anyIpv4(), Port.allTraffic());
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 4', () => {
      new CfnSecurityGroup(stack, 'rSecurityGroup', {
        groupDescription: 'security group with port 21 open',
        securityGroupIngress: [
          {
            fromPort: 1,
            toPort: 10000,
            ipProtocol: 'tcp',
            cidrIp: '0.0.0.0/0',
          },
        ],
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      new CfnSecurityGroup(stack, 'rSecurityGroup1', {
        groupDescription: 'security group with no rules',
        securityGroupIngress: [],
      });
      new CfnSecurityGroup(stack, 'rSecurityGroup2', {
        groupDescription:
          'security group with SSH ingress allowed for a specific IP address',
        securityGroupIngress: [
          {
            fromPort: 21,
            ipProtocol: 'tcp',
            cidrIp: '72.21.210.165',
          },
        ],
      });
      new CfnSecurityGroup(stack, 'rSecurityGroup3', {
        groupDescription:
          'security group with an open-world ingress rule for HTTP traffic',
        securityGroupIngress: [
          {
            fromPort: 80,
            ipProtocol: 'tcp',
            cidrIp: '0.0.0.0/0',
          },
        ],
      });
      new CfnSecurityGroup(stack, 'rSecurityGroup4', {
        groupDescription: 'security group allowing unrestricted udp traffic',
        securityGroupIngress: [
          {
            fromPort: 21,
            ipProtocol: 'udp',
            cidrIp: '0.0.0.0/0',
          },
        ],
      });
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });

  describe('EC2RestrictedInbound: EC2 security groups do not allow for 0.0.0.0/0 or ::/0 inbound access', () => {
    const ruleId = 'EC2RestrictedInbound';
    test('Noncompliance 1', () => {
      new SecurityGroup(stack, 'rSg', {
        vpc: new Vpc(stack, 'rVpc'),
      }).addIngressRule(Peer.anyIpv4(), Port.allTraffic());
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 2', () => {
      new CfnSecurityGroupIngress(stack, 'rIngress', {
        ipProtocol: 'tcp',
        cidrIp: '0.0.0.0/0',
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 3', () => {
      new CfnSecurityGroupIngress(stack, 'rIngress', {
        ipProtocol: 'tcp',
        cidrIpv6: 'ff:ff:ff:ff:ff:ff:ff:ff/0',
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 4', () => {
      new SecurityGroup(stack, 'rSg', {
        vpc: new Vpc(stack, 'rVpc'),
      }).addIngressRule(Peer.anyIpv6(), Port.allTraffic());
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      new SecurityGroup(stack, 'rSg', {
        vpc: new Vpc(stack, 'rVpc'),
      }).addIngressRule(Peer.ipv4('1.2.3.4/32'), Port.allTraffic());
      new CfnSecurityGroupIngress(stack, 'rIngress', {
        ipProtocol: 'tcp',
        cidrIp: '1.2.3.4/32',
      });
      new CfnSecurityGroupIngress(stack, 'rIngress2', {
        ipProtocol: 'tcp',
        cidrIpv6: '1234:5678:9abc:def1:2345:6789:abcd:ef12/128',
      });
      new SecurityGroup(stack, 'rSg2', {
        vpc: new Vpc(stack, 'rVpc2'),
      });
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });

  describe('EC2RestrictedSSH: Security Groups do not allow for unrestricted SSH traffic', () => {
    const ruleId = 'EC2RestrictedSSH';
    test('Noncompliance 1', () => {
      new CfnSecurityGroup(stack, 'rSecurityGroup', {
        groupDescription: 'security group with SSH unrestricted',
        securityGroupIngress: [
          {
            fromPort: 22,
            ipProtocol: 'tcp',
            cidrIp: '0.0.0.0/0',
          },
        ],
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 2', () => {
      new CfnSecurityGroup(stack, 'rSecurityGroup', {
        groupDescription: 'security group with SSH unrestricted',
        securityGroupIngress: [
          {
            fromPort: 22,
            ipProtocol: 'tcp',
            cidrIpv6: '::/0',
          },
        ],
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 3', () => {
      new SecurityGroup(stack, 'rSg', {
        vpc: new Vpc(stack, 'rVpc'),
      }).addIngressRule(Peer.anyIpv4(), Port.allTraffic());
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 4', () => {
      new CfnSecurityGroup(stack, 'rSecurityGroup', {
        groupDescription: 'security group with SSH unrestricted',
        securityGroupIngress: [
          {
            fromPort: 1,
            toPort: 10000,
            ipProtocol: 'tcp',
            cidrIpv6: '::/0',
          },
        ],
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Noncompliance 5', () => {
      new CfnSecurityGroupIngress(stack, 'rSgIngress', {
        fromPort: 1,
        toPort: 10000,
        ipProtocol: 'tcp',
        cidrIp: '1.0.0.0/0',
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      new CfnSecurityGroup(stack, 'rSecurityGroup1', {
        groupDescription: 'security group with no rules',
        securityGroupIngress: [],
      });
      new CfnSecurityGroup(stack, 'rSecurityGroup2', {
        groupDescription:
          'security group with SSH ingress allowed for a specific IP address',
        securityGroupIngress: [
          {
            fromPort: 22,
            ipProtocol: 'tcp',
            cidrIp: '72.21.210.165',
          },
        ],
      });
      new CfnSecurityGroup(stack, 'rSecurityGroup3', {
        groupDescription:
          'security group with an open-world ingress rule for HTTP traffic',
        securityGroupIngress: [
          {
            fromPort: 80,
            ipProtocol: 'tcp',
            cidrIp: '0.0.0.0/0',
          },
        ],
      });
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });

  describe('EC2SecurityGroupDescription: Security Groups have descriptions', () => {
    const ruleId = 'EC2SecurityGroupDescription';
    test('Noncompliance 1', () => {
      new SecurityGroup(stack, 'rSg', {
        vpc: new Vpc(stack, 'rVpc'),
        description: ' ',
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      new SecurityGroup(stack, 'rSg', {
        vpc: new Vpc(stack, 'rVpc'),
        description: 'lorem ipsum dolor sit amet',
      });
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });
});

describe('Amazon Elastic Block Store (EBS)', () => {
  describe('EC2EBSVolumeEncrypted: EBS volumes have encryption enabled', () => {
    const ruleId = 'EC2EBSVolumeEncrypted';
    test('Noncompliance 1', () => {
      new Volume(stack, 'rVolume', {
        availabilityZone: stack.availabilityZones[0],
        size: Size.gibibytes(42),
        encrypted: false,
      });
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      new Volume(stack, 'rVolume', {
        availabilityZone: stack.availabilityZones[0],
        size: Size.gibibytes(42),
        encrypted: true,
      });
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });
});

describe('EC2SecurityGroupOnlyTcp443: Security Groups should only allow TCP 443 for ingress iPv4 traffic', () => {
  const ruleId = 'EC2SecurityGroupOnlyTcp443';
  test('Noncompliance 1', () => {
    new CfnSecurityGroup(stack, 'rSecurityGroup', {
      groupDescription: 'security group tcp port 80 open',
      securityGroupIngress: [
        {
          fromPort: 80,
          ipProtocol: 'tcp',
          cidrIp: '0.0.0.0/0',
        },
      ],
    });
    validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
  });

  test('Noncompliance 2', () => {
    new CfnSecurityGroup(stack, 'rSecurityGroup2', {
      groupDescription: 'security group with udp port 53',
      securityGroupIngress: [
        {
          fromPort: 53,
          ipProtocol: 'udp',
          cidrIp: '0.0.0.0/0',
        },
      ],
    });
    validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
  });

  test('Compliance', () => {
    new CfnSecurityGroup(stack, 'rSecurityGroup1', {
      groupDescription: 'security group with inbound tcp 443',
      securityGroupIngress: [],
    });
    new CfnSecurityGroup(stack, 'rSecurityGroup2', {
      groupDescription: 'security group with tcp 443 ingress allowed',
      securityGroupIngress: [
        {
          fromPort: 443,
          ipProtocol: 'tcp',
          cidrIp: '0.0.0.0/0',
        },
      ],
    });
    //validateStack(stack, ruleId, TestType.COMPLIANCE)
  });
});

describe('EC2IMDSv2: Instances use IMDSv2', () => {
  const ruleId = 'EC2IMDSv2';

  //test an ec2 instnace with a template that does not have meta defined.
  test('Compliance_namedtemplate1', () => {
    const launchtemplate = new CfnLaunchTemplate(stack, 'LaunchTemplate', {
      launchTemplateData: {
        instanceType: 't3.small',
        metadataOptions: {
          httpTokens: 'optional',
        },
      },
    });

    new CfnInstance(stack, 'testinstance', {
      imageId: 'ami-00112233444',
      instanceType: 't3.micro',
      subnetId: 'subnet-0123455667',
      launchTemplate: {
        version: launchtemplate.attrLatestVersionNumber,
        launchTemplateId: launchtemplate.ref,
      },
    });
    validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
  });
  // test a ec2 instance without imdsv2
  test('Noncompliance_noimdsv2', () => {
    const vpc = new Vpc(stack, 'testvpc', {});
    new Instance(stack, 'testinstance', {
      vpc: vpc,
      instanceType: cdk_ec2.InstanceType.of(
        cdk_ec2.InstanceClass.R5,
        cdk_ec2.InstanceSize.LARGE
      ),
      machineImage: cdk_ec2.MachineImage.latestAmazonLinux(),
      requireImdsv2: false, //
    });
    validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
  });

  // test an ec2 instance with imdsv2 using a named launch template
  test('Compliance_namedtemplate', () => {
    const vpc = new Vpc(stack, 'testvpc', {});
    new Instance(stack, 'testinstance', {
      vpc: vpc,
      instanceType: cdk_ec2.InstanceType.of(
        cdk_ec2.InstanceClass.R5,
        cdk_ec2.InstanceSize.LARGE
      ),
      machineImage: cdk_ec2.MachineImage.latestAmazonLinux(),
      requireImdsv2: true,
    });
    validateStack(stack, ruleId, TestType.COMPLIANCE);
  });

  //test an ec2 instance using a template id
  test('Compliance_namedtemplate', () => {
    const launchtemplate = new CfnLaunchTemplate(stack, 'LaunchTemplate', {
      launchTemplateData: {
        instanceType: 't3.small',
        metadataOptions: {
          httpTokens: 'required',
        },
      },
    });

    new CfnInstance(stack, 'testinstance', {
      imageId: 'ami-00112233444',
      instanceType: 't3.micro',
      subnetId: 'subnet-0123455667',
      launchTemplate: {
        version: launchtemplate.attrLatestVersionNumber,
        launchTemplateId: launchtemplate.ref,
      },
    });
    validateStack(stack, ruleId, TestType.COMPLIANCE);
  });

  //test an autoscaling instance using a ec2 styled LaunchTemplate with no tokens
  test('Autoscaling_1', () => {
    const launchtemplate = new CfnLaunchTemplate(stack, 'LaunchTemplate', {
      launchTemplateData: {
        instanceType: 't3.small',
      },
    });

    new CfnAutoScalingGroup(stack, 'testinstance', {
      maxSize: '2',
      minSize: '1',
      //launchConfigurationName: 'string'
      launchTemplate: {
        version: launchtemplate.attrLatestVersionNumber,
        launchTemplateId: launchtemplate.ref,
      },
    });
    validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
  });

  //test an autoscaling instance using a ec2 syteled LaunchTemplate by id
  test('Autoscaling_2', () => {
    const launchtemplate = new CfnLaunchTemplate(stack, 'LaunchTemplate', {
      launchTemplateData: {
        instanceType: 't3.small',
        metadataOptions: {
          httpTokens: 'required',
        },
      },
    });

    new CfnAutoScalingGroup(stack, 'testinstance', {
      maxSize: '2',
      minSize: '1',
      //launchConfigurationName: 'string'
      launchTemplate: {
        version: launchtemplate.attrLatestVersionNumber,
        launchTemplateId: launchtemplate.ref,
      },
    });
    validateStack(stack, ruleId, TestType.COMPLIANCE);
  });

  //test an autoscaling instance using a ec2 syteled LaunchTemplate by name
  test('Autoscaling_3', () => {
    const launchtemplate = new CfnLaunchTemplate(stack, 'LaunchTemplate', {
      launchTemplateData: {
        instanceType: 't3.small',
        metadataOptions: {
          httpTokens: 'required',
        },
      },
    });

    new CfnAutoScalingGroup(stack, 'testinstance', {
      maxSize: '2',
      minSize: '1',
      //launchConfigurationName: 'string'
      launchTemplate: {
        version: launchtemplate.attrLatestVersionNumber,
        launchTemplateName: launchtemplate.launchTemplateName,
      },
    });
    validateStack(stack, ruleId, TestType.COMPLIANCE);
  });

  test('Autoscaling_4', () => {
    const launchconfiguration = new CfnLaunchConfiguration(
      stack,
      'LaunchTemplate',
      {
        imageId: 'ami-123456',
        instanceType: 't3.small',
        metadataOptions: {
          httpTokens: 'required',
        },
        launchConfigurationName: 'thename',
      }
    );

    new CfnAutoScalingGroup(stack, 'testinstance', {
      maxSize: '2',
      minSize: '1',
      launchConfigurationName: launchconfiguration.launchConfigurationName,
    });
    validateStack(stack, ruleId, TestType.COMPLIANCE);
  });

  test('Autoscaling_5', () => {
    const launchconfiguration = new CfnLaunchConfiguration(
      stack,
      'LaunchTemplate',
      {
        imageId: 'ami-123456',
        instanceType: 't3.small',
        metadataOptions: {
          httpTokens: 'optional',
        },
        launchConfigurationName: 'thename',
      }
    );

    new CfnAutoScalingGroup(stack, 'testinstance', {
      maxSize: '2',
      minSize: '1',
      launchConfigurationName: launchconfiguration.launchConfigurationName,
    });
    validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
  });

  test('Autoscaling_6', () => {
    const launchconfiguration = new CfnLaunchConfiguration(
      stack,
      'LaunchTemplate',
      {
        imageId: 'ami-123456',
        instanceType: 't3.small',
        launchConfigurationName: 'thename',
      }
    );

    new CfnAutoScalingGroup(stack, 'testinstance', {
      maxSize: '2',
      minSize: '1',
      launchConfigurationName: launchconfiguration.launchConfigurationName,
    });
    validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
  });
});
