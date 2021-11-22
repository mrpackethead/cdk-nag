/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
import { parse } from 'path';
import { CfnResource } from 'aws-cdk-lib';
import { CfnProject } from 'aws-cdk-lib/aws-codebuild';
import { resolveIfPrimitive } from '../../nag-pack';

/**
 * Codebuild projects use an AWS KMS key for encryption
 * @param node the CfnResource to check
 */
export default Object.defineProperty(
  (node: CfnResource): boolean => {
    if (node instanceof CfnProject) {
      const encryptionKey = resolveIfPrimitive(node, node.encryptionKey);
      if (encryptionKey == undefined || encryptionKey == 'alias/aws/s3') {
        return false;
      }
    }
    return true;
  },
  'name',
  { value: parse(__filename).name }
);