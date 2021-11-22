/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
import { parse } from 'path';
import { CfnResource, Stack } from 'aws-cdk-lib';
import { CfnUserPool } from 'aws-cdk-lib/aws-cognito';
import { resolveIfPrimitive } from '../../nag-pack';

/**
 * Cognito user pools have AdvancedSecurityMode set to ENFORCED
 * @param node the CfnResource to check
 */
export default Object.defineProperty(
  (node: CfnResource): boolean => {
    if (node instanceof CfnUserPool) {
      const userPoolAddOns = Stack.of(node).resolve(node.userPoolAddOns);
      if (userPoolAddOns == undefined) {
        return false;
      }
      const advancedSecurityMode = resolveIfPrimitive(
        node,
        userPoolAddOns.advancedSecurityMode
      );
      if (
        advancedSecurityMode == undefined ||
        advancedSecurityMode != 'ENFORCED'
      ) {
        return false;
      }
    }
    return true;
  },
  'name',
  { value: parse(__filename).name }
);