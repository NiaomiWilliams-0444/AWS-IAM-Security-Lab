# Security Assessment

## 1. Objective

This asessment evaluates the security of an AWS IAM user configured for access to a dedicated s3 security-lab bucket.

The objective was to:

- Identify excessive permissions in an intentionally vulnerable IAM configuration.
- Apply a least-privilege IAM policy.
- Validate the resulting permissions using the IAM Policy Simulator.
- Test the permissions through AWS CLI API requests.
- Use AWS CloudTrail data events to investigate and verify S3 object-level activity.
  
## 2. Initial Vulnerable Configuration

An intentionally over-permissioned IAM policy was created as a baseline for the security assessment.

The baseline policy granted the simulated developer access to:

- `s3:GetObject`
- `s3:PutObject`
- `s3:DeleteObject`
- `s3:ListBucket`
- `s3:DeleteBucket`
- `s3:PutBucketPolicy`

The policy also used `Resource: "*"` rather than restricting access to the designated S3 lab bucket.

These permissions exceeded the requirements of the simulated developer workflow. The workflow only required the ability to upload and delete objects within the designated lab bucket.

The baseline therefore provided a comparison point for evaluating the effectiveness of a least-privilege remediation.

## 3. Environment

The assessment was performed in an AWS environment using the following resources:

- **AWS Region:** us-east-1 (N. Virginia)
- **IAM user:** Niaomi-Developer
- **IAM group:** Niaomi-cloudDevelopers
- **S3 lab bucket:** `niaomi-myiam-security-lab-[ACCOUNT-ID]-us-east-1-an`
- **IAM policy:** NiaomiDeveloperS3ObjectAccess
- **CloudTrail trail:** MySecurity-cloudlab
- **CloudTrail log destination:** Dedicated S3 bucket configured for CloudTrail logs
- **Testing method:** AWS CLI using the `niaomi-developer` profile

## 4. Remediated Configuration

The lab used a separate administrative IAM identity, Niaomi-Admin, to manage the environment. The developer identity, Niaomi-Developer, was intentionally configured separately for permission testing.

Niaomi-Developer received a customer-managed policy that granted only s3:PutObject and s3:DeleteObject permissions on objects within the designated S3 lab bucket.

The S3 lab bucket was configured with Block Public Access enabled, bucket-owner-enforced object ownership, and default S3 server-side encryption.

The security assessment therefore focused on IAM authorization rather than public S3 exposure.

## 5. Security Issue

The initial baseline policy granted the simulated developer more S3 permissions than required for the intended workflow.

The excessive permissions included:

- `s3:GetObject`
- `s3:ListBucket`
- `s3:DeleteBucket`
- `s3:PutBucketPolicy`

The baseline also used `Resource: "*"` rather than restricting access to the designated S3 lab bucket.

These permissions increased the scope of actions available to the simulated developer beyond the requirements of the workflow. In particular, object retrieval, bucket listing, bucket deletion, and bucket policy modification were not required.

The remediation replaced the over-permissioned baseline with a customer-managed policy granting only:

- `s3:PutObject`
- `s3:DeleteObject`

The permissions were scoped to objects within the designated S3 lab bucket.

## 6. Permission Validation

After the least-privilege policy was applied, the permissions were validated using both the IAM Policy Simulator and AWS CLI requests.

The IAM Policy Simulator confirmed that:

- `s3:PutObject` was allowed.
- `s3:DeleteObject` was allowed.
- `s3:GetObject` was denied.
- `s3:DeleteBucket` was denied.

The permissions were then tested through AWS CLI using the `niaomi-developer` profile.

The `s3:PutObject` request completed successfully, confirming that the developer could upload objects to the designated S3 bucket.

The `s3:GetObject` request returned `AccessDenied`, confirming that the developer could not retrieve objects.

The `s3:DeleteObject` request completed successfully, confirming that the developer could delete objects.

The `s3:DeleteBucket` request returned `AccessDenied`, confirming that the developer could not delete the bucket.

These results matched the permissions defined in the IAM policy and demonstrated that the developer identity had the intended object-level access without additional S3 administrative permissions.

## 7. CloudTrail Evidence

CloudTrail data events were used to investigate S3 object-level activity generated during permission testing.

The captured events corresponded to the AWS CLI requests performed by the `Niaomi-Developer` identity against the lab S3 bucket.

The investigation identified the following activity:

- `s3:PutObject` — successful object upload.
- `s3:GetObject` — denied with `AccessDenied`.
- `s3:DeleteObject` — successful object deletion.

The CloudTrail records captured the IAM identity, event name, event time, AWS region, S3 bucket, object key, request status, and AWS CLI user agent associated with the requests.

The `GetObject` event was particularly useful because CloudTrail recorded the authorization failure and the corresponding `AccessDenied` error.

This provided audit evidence that the least-privilege policy prevented the developer identity from retrieving objects outside its authorized permissions.

## 8. Findings and Conclusion

The assessment identified excessive permissions in the intentionally over-permissioned developer baseline. The baseline allowed additional S3 actions and used a wildcard resource scope that exceeded the requirements of the simulated workflow.

The remediated policy allowed:

- `s3:PutObject`
- `s3:DeleteObject`

The policy did not grant object retrieval, bucket deletion, bucket listing, bucket policy modification, or other administrative S3 permissions.

Permission testing through the IAM Policy Simulator and AWS CLI produced results consistent with the policy configuration. Upload and deletion operations were successful, while object retrieval and bucket deletion were denied.

CloudTrail data events provided additional audit evidence of the S3 activity. The recorded events identified the developer IAM identity, the requested S3 actions, the target bucket and object, and the resulting request status.

The assessment demonstrates the application of least-privilege access controls by limiting an identity to the specific S3 operations required for the simulated developer workflow while preventing unrelated access.
