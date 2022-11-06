/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
import { parse } from 'path';
import { CfnResource, Stack } from 'aws-cdk-lib';
import { CfnInstance, CfnLaunchTemplate } from 'aws-cdk-lib/aws-ec2';
import { NagRuleCompliance, NagRules } from '../../nag-rules';

// Check to see if the EC2 Istance is configured with a launch profile
//Ec2imdsv2

/**
 * Determine if the EC2 Instance has a launch profile
 * @param node the CfnResource to check
 */
export default Object.defineProperty(
  (node: CfnResource): NagRuleCompliance => {
    if (node instanceof CfnInstance) {
      // to use imdsv2 there must be a launchtemplate.
      if (node.launchTemplate == undefined) {
        return NagRuleCompliance.NON_COMPLIANT;
      }

      // find the launchTemplate
      let instanceLaunchTemplateName = Stack.of(node).resolve(
        node.launchTemplate
      ).launchTemplateName;

      // find the launchTemplate by name, and see if its got httpTokens set as 'required'
      for (const child of Stack.of(node).node.findAll()) {
        if (child instanceof CfnLaunchTemplate) {
          if (
            isMatchingLaunchTemplate(child, instanceLaunchTemplateName) &&
            hasHttpTokens(child)
          ) {
            return NagRuleCompliance.COMPLIANT;
          }
        }
      }

      return NagRuleCompliance.NON_COMPLIANT;
    } else {
      return NagRuleCompliance.NOT_APPLICABLE;
    }
  },
  'name',
  { value: parse(__filename).name }
);

function isMatchingLaunchTemplate(
  node: CfnLaunchTemplate,
  launchTemplateName: string | undefined
): boolean {
  const templateName = NagRules.resolveResourceFromInstrinsic(
    node,
    node.launchTemplateName
  );
  return templateName === launchTemplateName;
}

function hasHttpTokens(node: CfnLaunchTemplate): boolean {
  const launchTemplateData: CfnLaunchTemplate.LaunchTemplateDataProperty =
    NagRules.resolveResourceFromInstrinsic(node, node.launchTemplateData);
  const meta =
    launchTemplateData.metadataOptions as CfnLaunchTemplate.MetadataOptionsProperty;

  if (meta !== undefined) {
    return true;
  }
  return false;
}
