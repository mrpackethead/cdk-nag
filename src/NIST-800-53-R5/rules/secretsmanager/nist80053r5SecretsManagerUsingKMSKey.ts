/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

import { CfnSecret } from '@aws-cdk/aws-secretsmanager';
import { CfnResource } from '@aws-cdk/core';
import { resolveIfPrimitive } from '../../../nag-pack';

/**
 * Secrets are encrypted with KMS Customer managed keys - (Control IDs: AU-9(3), CP-9d, SC-8(3), SC-8(4), SC-13a, SC-28(1), SI-19(4))
 * @param node the CfnResource to check
 */
export default function (node: CfnResource): boolean {
  if (node instanceof CfnSecret) {
    const kmsKeyId = resolveIfPrimitive(node, node.kmsKeyId);
    if (kmsKeyId === undefined || kmsKeyId === 'aws/secretsmanager') {
      return false;
    }
  }
  return true;
}