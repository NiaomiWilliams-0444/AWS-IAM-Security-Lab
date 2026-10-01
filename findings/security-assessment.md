# Security Assessment: AWS IAM Least-Privilege Lab

## Executive Summary

This assessment tested how AWS IAM policies control a developer identity's access to a dedicated S3 bucket. The same identity was tested under four policy configurations, and each result was confirmed three ways: the IAM Policy Simulator, live AWS CLI requests, and CloudTrail audit logs.

**Key results:**

- **Phase 1:** An `s3:*` policy, even when scoped to a single bucket, gave the developer destructive and administrative permissions the workflow never needed, including deleting the bucket and rewriting its bucket policy.
- **Phase 2:** A time-based condition denied every action it applied to, showing that conditions can restrict an Allow statement.
- **Phase 3:** The target least-privilege policy limited the developer to the two actions the workflow required. Everything else was blocked by implicit deny.
- **Phase 4:** An explicit Deny attached to the user overrode an Allow from the group policy. AWS named the denying policy in both the CLI error and the CloudTrail log.
- **Consistency:** Simulator, CLI, and CloudTrail results agreed in every phase.

Over-permissioned IAM identities are a common real-world risk. In the 2019 Capital One breach, an IAM role with broader S3 access than it needed allowed an attacker to read data from many buckets once its credentials were obtained ([A Systematic Analysis of the Capital One Data Breach: Critical Lessons Learned](https://dl.acm.org/doi/full/10.1145/3546068) (ACM Transactions on Privacy and Security)). This lab demonstrates the controls that limit and prevents that kind of exposure.

## 1. Objective

The objective was to test one developer identity under four policy configurations, each changing a single variable:

| Phase | Configuration | What it demonstrates |
| --- | --- | --- |
| 1 | Over-broad policy (`s3:*` on the lab bucket) | Risk of granting more actions than the workflow needs |
| 2 | Conditional policy (time-based `aws:CurrentTime` condition) | How a condition restricts an otherwise allowed action |
| 3 | Least-privilege policy (`s3:PutObject`, `s3:DeleteObject` only) | Implicit deny for every action not explicitly allowed |
| 4 | Explicit deny attached to the user, layered on the Phase 3 group policy | Explicit deny overriding an allow |

Each phase was validated in three ways:

- **IAM Policy Simulator:** expected policy evaluation result.
- **AWS CLI:** actual API requests made as the developer identity.
- **AWS CloudTrail:** audit record of the resulting S3 activity.

## 2. Environment

| Item | Value |
| --- | --- |
| AWS Region | us-east-1 (N. Virginia) |
| Developer IAM user | `Niaomi-Developer` |
| IAM group | `Niaomi-cloudDevelopers` |
| Administrative identity | `Niaomi-Admin` (used only to manage the environment) |
| S3 lab bucket | `niaomi-myiam-security-lab-[ACCOUNT-ID]-us-east-1-an` |
| Least-privilege group policy | `NiaomiDeveloperS3ObjectAccess` |
| CloudTrail trail | `MySecurity-cloudlab` (S3 data events enabled) |
| CloudTrail log destination | Separate S3 bucket for CloudTrail logs |
| Testing method | AWS CLI using the `niaomi-developer` profile with temporary credentials |

The S3 lab bucket had Block Public Access enabled, bucket-owner-enforced object ownership, and default server-side encryption (SSE-S3). The assessment therefore focused on IAM authorization rather than public S3 exposure.

The developer identity was never granted administrative access. The lab contained only test objects; no production data was used.

The policy documents for each phase are stored in the `policies/` folder:

- `phase1-overbroad-policy.json`
- `phase2-conditional-policy.json`
- `phase3-developer-policy.json`
- `phase4-explicitdeny-policy.json`

## 3. Intended Developer Workflow

The simulated developer workflow required only two actions on objects in the lab bucket:

- Upload objects (`s3:PutObject`)
- Delete objects (`s3:DeleteObject`)

The workflow did not require reading objects, listing the bucket, changing bucket configuration, or deleting the bucket. Phase 3 implements this as the target design; the other phases are compared against it.

## 4. Phase 1: Over-Broad Policy

### Phase 1 Configuration

The developer was granted `s3:*` on the lab bucket and its objects. The policy was limited to one bucket, but the wildcard action allowed every S3 operation on that bucket.

### Risk

| Excess permission | Risk | Severity |
| --- | --- | --- |
| `s3:DeleteBucket` | Developer could destroy the bucket and all of its data | High |
| `s3:PutBucketPolicy` | Developer could rewrite the bucket policy, including granting access to other principals | High |
| `s3:GetObject` | Developer could read data the workflow does not require | Medium |
| `s3:ListBucket` | Developer could list every object key in the bucket | Low |

### Phase 1 Results

| Action | Policy Simulator | AWS CLI | CloudTrail |
| --- | --- | --- | --- |
| `s3:PutObject` | Allowed | Succeeded | Recorded |
| `s3:GetObject` | Allowed | Succeeded | Recorded |
| `s3:ListBucket` | Allowed | Succeeded | Recorded as `ListObjects` |
| `s3:DeleteObject` | Allowed | Succeeded | Recorded |
| `s3:DeleteBucket` | Allowed | Not run (see note) | Not applicable |

**Note:** `s3:DeleteBucket` was validated only through the Policy Simulator. It was not run live because a successful request would have destroyed the lab bucket.

### Phase 1 Finding

The over-broad policy granted every S3 action on the bucket, including destructive and administrative actions unrelated to the workflow. Bucket-level actions (`ListBucket`, `DeleteBucket`) were only granted once the bare bucket ARN was added alongside the object ARN (`bucket-name/*`). A wildcard action grants only what the `Resource` field matches.

## 5. Phase 2: Conditional Policy

### Phase 2 Configuration

The developer policy allowed `s3:PutObject`, `s3:GetObject`, and `s3:DeleteObject` on the lab bucket, but only when a time-based condition was met:

```json
"Condition": {
  "DateLessThan": {
    "aws:CurrentTime": "2020-01-01T00:00:00Z"
  }
}
```

Because the cutoff date had already passed, the condition could never be true for a live request.

### Phase 2 Results

| Action | Simulator (current time) | Simulator (date before 2020-01-01) | AWS CLI | CloudTrail |
| --- | --- | --- | --- | --- |
| `s3:PutObject` | Denied | Allowed | `AccessDenied` | Recorded with `AccessDenied` |
| `s3:GetObject` | Denied | Allowed | `AccessDenied` | Recorded with `AccessDenied` |
| `s3:DeleteObject` | Denied | Allowed | `AccessDenied` | Recorded with `AccessDenied` |

### Phase 2 Finding

All three allowed actions were denied because the condition was not met. The Policy Simulator can test alternative condition values, but `aws:CurrentTime` is set by AWS at request time and cannot be changed from the CLI. Live requests therefore always evaluate against the real time.

In practice, time-based conditions are useful for access that should expire automatically, such as temporary access for a contractor or during a maintenance window.

## 6. Phase 3: Least-Privilege Policy (Target Design)

### Phase 3 Configuration

The `NiaomiDeveloperS3ObjectAccess` policy was attached to the `Niaomi-cloudDevelopers` group. It allowed only `s3:PutObject` and `s3:DeleteObject` on objects in the lab bucket (`arn:aws:s3:::niaomi-myiam-security-lab-[ACCOUNT-ID]-us-east-1-an/*`).

### Phase 3 Results

| Action | Expected | Policy Simulator | AWS CLI | CloudTrail |
| --- | --- | --- | --- | --- |
| `s3:PutObject` | Allow | Allowed | Succeeded | Recorded, success |
| `s3:DeleteObject` | Allow | Allowed | Succeeded | Recorded, success |
| `s3:GetObject` | Deny | Denied | `AccessDenied` | Recorded with `AccessDenied` |
| `s3:DeleteBucket` | Deny | Denied | `AccessDenied` | Recorded with `AccessDenied` (management event) |

### Phase 3 Finding

The developer could perform the two required actions and nothing else. All other actions were blocked by implicit deny: IAM denies any action that no policy explicitly allows.

`GetObject` is not in the policy, so it is implicitly denied whether or not the object exists. When `GetObject` was requested for an object that did not exist, the `AccessDenied` message referenced `s3:ListBucket`. S3 does this so that an identity without list permission cannot use "not found" responses to discover which objects exist.

## 7. Phase 4: Explicit Deny

### Phase 4 Configuration

The Phase 3 group policy remained in place. An additional policy containing an explicit `Deny` statement was attached directly to the `Niaomi-Developer` user, targeting `s3:DeleteObject` on the lab bucket. The group policy still allowed `s3:DeleteObject`, so the user had both an allow and an explicit deny for the same action.

### Phase 4 Results

| Action | Policy Simulator | AWS CLI | CloudTrail |
| --- | --- | --- | --- |
| `s3:PutObject` | Allowed (via group policy) | Succeeded | Recorded, success |
| `s3:DeleteObject` | Denied by the explicit deny | `AccessDenied`, naming the deny policy | Recorded with `AccessDenied`, naming the deny policy |

### Phase 4 Finding

An explicit deny overrides any allow, even when the allow comes from a group policy and the deny is attached directly to the user. AWS named the responsible policy in both the CLI error and the CloudTrail record, which makes the source of a denial easy to trace.

Key fields from the CloudTrail record of the denied request (full sanitized record: `evidence/phase4-explicitdeny/cloudtrail-phase4-sanitized.json`):

```json
{
  "eventName": "DeleteObject",
  "eventCategory": "Data",
  "userIdentity": {
    "userName": "Niaomi-Developer",
    "sessionContext": { "attributes": { "mfaAuthenticated": "true" } }
  },
  "errorCode": "AccessDenied",
  "errorMessage": "User: arn:aws:iam::[ACCOUNT-ID]:user/Niaomi-Developer is not authorized to perform: s3:DeleteObject on resource: \"arn:aws:s3:::niaomi-myiam-security-lab-[ACCOUNT-ID]-us-east-1-an/cli-tests/phase4-test.txt\" with an explicit deny in an identity-based policy: arn:aws:iam::[ACCOUNT-ID]:policy/phase4-explicit-deny-policy",
  "additionalEventData": { "httpStatusCode": 403 }
}
```

## 8. CloudTrail Evidence

CloudTrail S3 data events were enabled on the `MySecurity-cloudlab` trail to capture object-level activity. The recorded events included:

- IAM identity (`Niaomi-Developer`)
- Event name and event time
- AWS Region
- Bucket name and object key
- Request result, including `errorCode: AccessDenied` for denied requests
- AWS CLI user agent
- Whether the session was MFA-authenticated (`mfaAuthenticated: true` for the developer's CLI session)

Observations:

- **Data events vs. management events:** Object-level actions (`PutObject`, `GetObject`, `DeleteObject`) are data events. They are logged only when a trail is configured to capture them, and they do not appear in CloudTrail Event History. `DeleteBucket` is a management event and is logged separately.
- **Event naming:** The IAM action `s3:ListBucket` is recorded in CloudTrail under the event name `ListObjects`.
- **Denied requests are logged:** Denied requests produce a CloudTrail record. This gives audit evidence that a policy blocked an action, not only that permitted actions occurred.

Sanitized screenshots for each phase, plus a sanitized raw CloudTrail log for Phase 4, are stored in `evidence/phase1-broad`, `evidence/phase2-conditions`, `evidence/phase3-narrow`, and `evidence/phase4-explicitdeny`.

## 9. Recommendations

Based on these findings, an organization managing developer access to S3 should:

1. **Avoid wildcard actions in production policies.** Grant only the specific actions a role needs, as in Phase 3. Phase 1 showed that `s3:*` grants destructive permissions even when the resource is limited to one bucket.
2. **Use explicit deny as a guardrail for high-risk actions.** Actions such as `s3:DeleteBucket` and `s3:PutBucketPolicy` can be explicitly denied for developer identities so that a later, broader Allow cannot grant them by mistake.
3. **Use conditions for temporary access.** Time-based conditions let access expire automatically instead of depending on someone to remove it.
4. **Enable CloudTrail data events for sensitive buckets.** Without them, object-level reads, writes, and deletes are not logged, and denied attempts against data go unrecorded.
5. **Test policies before and after deployment.** Use the Policy Simulator before attaching a policy, then confirm with real requests and logs, as done in every phase of this lab.

## 10. Conclusion

- **Phase 1** showed that a wildcard action grants destructive and administrative permissions far beyond the workflow, even when the policy is scoped to a single bucket.
- **Phase 2** showed that a condition can deny an action that a policy otherwise allows.
- **Phase 3** met the workflow requirements with only `s3:PutObject` and `s3:DeleteObject`, relying on implicit deny for everything else.
- **Phase 4** showed that an explicit deny takes precedence over any allow, and that AWS identifies the denying policy in both CLI errors and CloudTrail logs.

The Policy Simulator, AWS CLI, and CloudTrail results were consistent in every phase. The lab demonstrates least-privilege access control and the three IAM policy evaluation outcomes: explicit allow, implicit deny, and explicit deny.
