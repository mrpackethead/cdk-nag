/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
import { parse } from 'path';
import { CfnResource, Stack } from 'aws-cdk-lib';
import { CfnSecurityGroupIngress, CfnSecurityGroup } from 'aws-cdk-lib/aws-ec2';
import { NagRuleCompliance, NagRules } from '../../nag-rules';

/**
 * Security Groups should only allow inbound access to tcp443
 * @param node the CfnResource to check
 */
export default Object.defineProperty(
  (node: CfnResource): NagRuleCompliance => {
    if (node instanceof CfnSecurityGroup) {
      const ingressRules = Stack.of(node).resolve(node.securityGroupIngress);
      if (ingressRules != undefined) {
        //For each ingress rule, ensure that it only allows TCP 443
        for (const rule of ingressRules) {
          const resolvedRule = Stack.of(node).resolve(rule);
          const ipProtocol = NagRules.resolveIfPrimitive(
            node,
            resolvedRule.ipProtocol
          );

          const fromPort = NagRules.resolveIfPrimitive(
            node,
            resolvedRule.fromPort
          );
          const toPort = NagRules.resolveIfPrimitive(node, resolvedRule.toPort);

          if (!(fromPort == 443 && toPort == 443 && ipProtocol == 'tcp')) {
            return NagRuleCompliance.NON_COMPLIANT;
          }
        }
      }
      return NagRuleCompliance.COMPLIANT;
    } else if (node instanceof CfnSecurityGroupIngress) {
      const ipProtocol = NagRules.resolveIfPrimitive(node, node.ipProtocol);
      const fromPort = NagRules.resolveIfPrimitive(node, node.fromPort);
      const toPort = NagRules.resolveIfPrimitive(node, node.toPort);

      if (!(fromPort == 443 && toPort == 443 && ipProtocol == 'tcp')) {
        return NagRuleCompliance.NON_COMPLIANT;
      } else {
        return NagRuleCompliance.NON_COMPLIANT;
      }
    } else {
      return NagRuleCompliance.NOT_APPLICABLE;
    }
  },
  'name',
  { value: parse(__filename).name }
);
