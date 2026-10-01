# AWS IAM Least-Privilege Security Lab

**Summary:** I built an isolated AWS environment and tested one developer identity under four IAM policy configurations: over-broad access, a time-based condition, least privilege, and an explicit deny. Every result was confirmed three ways: IAM Policy Simulator, live AWS CLI requests, and CloudTrail audit logs. The lab shows how IAM actually evaluates access, not just how the documentation describes it.

**Skills demonstrated:** AWS IAM policy design · least privilege · IAM condition keys · explicit vs. implicit deny · Amazon S3 security configuration · AWS CLI · CloudTrail data events and log investigation · security documentation

**Full write-up:** [Security Assessment](findings/security-assessment.md)

## Why This Matters

Over-permissioned identities are one of the most common cloud security risks. In the 2019 Capital One breach, an IAM role with broader S3 access than it needed allowed an attacker to read data from many buckets once its credentials were obtained ([ACM case study](https://dl.acm.org/doi/full/10.1145/3546068)). This lab demonstrates the risks of over-broad policies and practices the controls that limit them: granting only required actions, layering explicit denies, and logging enough to prove what was allowed and what was blocked.

## The Four Phases

| Phase | Policy | What it demonstrates |
| --- | --- | --- |
| 1. Over-broad | `s3:*` on the lab bucket | What happens without least privilege |
| 2. Conditional | Object actions gated by an `aws:CurrentTime` condition that can never be met | How a condition stops an Allow statement from applying |
| 3. Least privilege (target design) | `s3:PutObject` and `s3:DeleteObject` only | Implicit deny for everything not explicitly allowed |
| 4. Explicit deny | User-level `Deny` on `s3:DeleteObject`, layered on the Phase 3 group policy | An explicit Deny overriding an Allow |

Phase 3 is the intended design and the account's standing configuration. Phases 1, 2, and 4 are controlled comparisons against it.

## Technical Environment

- **Cloud platform:** AWS (us-east-1)
- **Services:** IAM, S3, CloudTrail
- **Testing:** IAM Policy Simulator, AWS CLI
- **Authentication:** AWS CLI `aws login` with temporary, short-lived credentials (no long-lived access keys)
- **Development environment:** macOS, Zsh, VS Code

## Security Controls

The following controls were in place across all four phases:

- Group-based permission management, with Phase 4 testing a user-level override.
- Customer-managed IAM policies, each changing a single variable (breadth, condition, or explicit deny).
- S3 Block Public Access, with all four settings on.
- Bucket-owner-enforced object ownership (ACLs disabled).
- Server-side encryption with SSE-S3.
- MFA for IAM identities used for console access.
- CloudTrail data events for S3 object-level activity, scoped to the lab bucket.
- A separate CloudTrail log bucket, isolated from the bucket being monitored.

## Testing & Results

### Phase 1: Over-Broad Policy (`s3:*`)

| S3 Action | Policy Simulator | AWS CLI | CloudTrail |
| --- | --- | --- | --- |
| `s3:PutObject` | Allowed | Succeeded | Confirmed |
| `s3:GetObject` | Allowed | Succeeded | Confirmed |
| `s3:ListBucket` | Allowed | Succeeded | Confirmed (as `ListObjects`) |
| `s3:DeleteObject` | Allowed | Succeeded (no output returned) | Confirmed |
| `s3:DeleteBucket` | Allowed | Not run, to avoid destroying the lab bucket | Not applicable |

**Takeaway:** `s3:*` grants only what the `Resource` field matches. The policy first listed only the object ARN (`bucket-name/*`), so the bucket-level actions `ListBucket` and `DeleteBucket` were still denied. They were granted only after the bare bucket ARN (`bucket-name`) was added.

### Phase 2: Conditional Access (time-based condition)

The policy allowed `PutObject`, `GetObject`, and `DeleteObject`, but only if `aws:CurrentTime` was before 2020-01-01, a condition no live request can meet.

| S3 Action | Simulator (current time) | Simulator (date before 2020-01-01) | AWS CLI | CloudTrail |
| --- | --- | --- | --- | --- |
| `s3:PutObject` | Denied | Allowed | `AccessDenied` | Confirmed |
| `s3:GetObject` | Denied | Allowed | `AccessDenied` | Confirmed |
| `s3:DeleteObject` | Denied | Allowed | `AccessDenied` | Confirmed |

**Takeaway:** `aws:CurrentTime` is set by AWS when it receives the request and cannot be faked in a real, signed API call. Changing the client's clock would fail AWS's request-timestamp check before the IAM policy is evaluated. The "allowed" state could therefore only be shown in the Policy Simulator. In practice, this type of condition is useful for access that should expire automatically, such as temporary contractor access.

### Phase 3: Least-Privilege Policy (target design)

| S3 Action | Policy Simulator | AWS CLI | CloudTrail |
| --- | --- | --- | --- |
| `s3:PutObject` | Allowed | Succeeded | Confirmed |
| `s3:DeleteObject` | Allowed | Succeeded | Confirmed |
| `s3:GetObject` | Denied | `AccessDenied` | Confirmed |
| `s3:DeleteBucket` | Denied | `AccessDenied` | Confirmed (management event) |

**Takeaway:** `GetObject` is not in the developer's policy, so it is implicitly denied whether or not the object exists. When the test requested an object that didn't exist, the `AccessDenied` message referenced `s3:ListBucket` instead of returning "not found." S3 does this so an identity without list permission can't use "not found" responses to discover which objects exist.

### Phase 4: Explicit Deny

The Phase 3 group policy (Allow `PutObject` and `DeleteObject`) stayed attached. A second policy with an explicit `Deny` on `s3:DeleteObject` was attached directly to the user.

| S3 Action | Policy Simulator | AWS CLI | CloudTrail |
| --- | --- | --- | --- |
| `s3:PutObject` | Allowed (via group policy) | Succeeded | Confirmed |
| `s3:DeleteObject` | Denied (explicit deny) | `AccessDenied`, naming the deny policy | Confirmed, with the same policy named |

**Takeaway:** This is the only phase where an action was blocked by an explicit Deny rather than implicit deny. Both the CLI error and the CloudTrail entry named the responsible policy (`phase4-explicit-deny-policy`), so the audit log carries the same diagnostic detail as the live response.

Key fields from the sanitized CloudTrail record of the denied request ([full record](evidence/phase4-explicitdeny/cloudtrail-phase4-sanitized.json)):

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

The record also shows `mfaAuthenticated: true`, confirming the developer's CLI session was MFA-authenticated.

## IAM Evaluation Logic Summary

| Mechanism | Demonstrated in | What it means |
| --- | --- | --- |
| Explicit Allow | Phases 1 and 3, Phase 4 (`PutObject`) | A statement grants the action on the resource, and nothing overrides it. |
| Implicit Deny | Phase 3 (`GetObject`, `DeleteBucket`) | No statement allows the request, so IAM denies it by default. |
| Unmet condition | Phase 2 | A statement would allow the action, but its condition isn't satisfied, so it doesn't apply. The result is the same as implicit deny. |
| Explicit Deny | Phase 4 | A statement forbids the action. This always wins over any Allow, wherever each is attached. |

## Key Findings

- Simulator, CLI, and CloudTrail results agreed in every phase.
- A wildcard action grants only what the `Resource` field matches; bucket-level and object-level actions need different ARN formats.
- An unmet condition on an Allow statement produces the same result as having no matching statement.
- An explicit Deny overrides any Allow, regardless of whether each is attached to a user or a group.
- CloudTrail records the same diagnostic detail as the live API response, including which policy caused a denial.
- S3 doesn't confirm whether an object exists to an identity without list permission.

## Challenges & Troubleshooting

These were real problems I hit and worked through during the lab.

- **CloudTrail Event History shows only management events.** S3 object-level actions never appear there. Confirming them required downloading the trail's log files from the destination bucket and searching them directly.
- **The data-event selector was misconfigured.** After switching to "log all events," the selector was watching the CloudTrail log bucket instead of the lab bucket. I caught this by checking the selector's raw JSON and fixed it by scoping basic event selectors to the lab bucket.
- **Temporary credentials expire separately for each identity.** The developer and admin profiles each had to be re-authenticated with `aws login` when their sessions timed out. Logging in one did not extend the other.
- **A missing bucket-level ARN caused denials under an "allow everything" policy.** `s3:*` scoped only to `bucket-name/*` still denied `ListBucket` and `DeleteBucket`, because those actions need the bare bucket ARN.
- **A `ParamValidation` error was a local file-path problem, not a permissions problem.** The `--body` file didn't exist in the current folder, so the CLI failed before sending the request. Nothing reached AWS, so nothing appeared in CloudTrail.
- **IAM permission names and CloudTrail event names don't always match.** The `s3:ListBucket` permission is logged as `ListObjects`, not "ListBucket."
- **`aws:CurrentTime` can't be faked in a live request.** The allowed state for Phase 2 could only be shown in the Policy Simulator.
- **CloudTrail delivers data events in batches, usually 5–15 minutes late.** Several denied tests needed multiple rounds of syncing and searching before the log file arrived.

## Evidence

Sanitized screenshots are organized by phase in the `evidence/` folder. Expand a phase to view them.

<!-- markdownlint-disable MD033 -->

<details>
<summary><strong>Phase 1: Over-Broad Policy</strong></summary>

### Phase 1: IAM Policy

![Phase 1 Over-Broad Policy](evidence/phase1-broad/overbroadpolicy-phase1.png)

### Phase 1: IAM Policy Simulator

![Phase 1 Policy Simulator](evidence/phase1-broad/policy-simulator-phase1.png)

### Phase 1: AWS CLI Test Results

![Phase 1 CLI Tests](evidence/phase1-broad/cli-tests-broad-phase1.png)

### Phase 1: CloudTrail Confirmation

![Phase 1 CloudTrail PutObject](evidence/phase1-broad/cloudtrail-putobject-phase1.png)
![Phase 1 CloudTrail GetObject](evidence/phase1-broad/cloudtrail-getobject-phase1.png)
![Phase 1 CloudTrail ListObjects](evidence/phase1-broad/cloudtrail-listobjects-phase1.png)
![Phase 1 CloudTrail DeleteObject](evidence/phase1-broad/cloudtrail-deleteobject-phase1.png)

</details>

<details>
<summary><strong>Phase 2: Conditional Access</strong></summary>

### Phase 2: IAM Policy

![Phase 2 Conditional Policy](evidence/phase2-conditions/conditionalpolicy-phase2.png)

### Phase 2: IAM Policy Simulator: Denied at Current Time

![Phase 2 Policy Simulator Denied](evidence/phase2-conditions/policy-simulator-phase2-denied.png)

### Phase 2: IAM Policy Simulator: Allowed at Simulated Past Date

![Phase 2 Policy Simulator Allowed](evidence/phase2-conditions/policy-simulator-phase2-allowed.png)

### Phase 2: AWS CLI Test Results

![Phase 2 CLI Tests](evidence/phase2-conditions/cli-tests-phase2.png)

### Phase 2: CloudTrail Confirmation

![Phase 2 CloudTrail PutObject](evidence/phase2-conditions/cloudtrail-putobject-phase2.png)
![Phase 2 CloudTrail GetObject](evidence/phase2-conditions/cloudtrail-getobject-phase2.png)
![Phase 2 CloudTrail DeleteObject](evidence/phase2-conditions/cloudtrail-deleteobject-phase2.png)

</details>

<details>
<summary><strong>Phase 3: Least-Privilege Policy</strong></summary>

### Phase 3: IAM Policy

![Phase 3 Developer IAM Policy](evidence/phase3-narrow/developer-iam-policy-phase3.png)

### Phase 3: IAM Policy Simulator

![Phase 3 Policy Simulator](evidence/phase3-narrow/policy-simulator-phase3.png)

### Phase 3: AWS CLI Test Results

![Phase 3 CLI Tests](evidence/phase3-narrow/phase3-narrowCLITests.png)
![Phase 3 CLI Tests, continued](evidence/phase3-narrow/phase3-narrowCLITests2.png)

### Phase 3: CloudTrail Confirmation

![Phase 3 CloudTrail PutObject](evidence/phase3-narrow/cloudtrail-putobject-phase3.png)
![Phase 3 CloudTrail GetObject AccessDenied](evidence/phase3-narrow/cloudtrail-getobject-denied-phase3.png)
![Phase 3 CloudTrail DeleteObject](evidence/phase3-narrow/cloudtrail-deleteobject-phase3.png)
![Phase 3 CloudTrail DeleteBucket AccessDenied](evidence/phase3-narrow/cloudtrail-deletebucket-phase3.png)

</details>

<details>
<summary><strong>Phase 4: Explicit Deny</strong></summary>

### Phase 4: IAM Policy

![Phase 4 Explicit Deny Policy](evidence/phase4-explicitdeny/explicitdeny-policy-phase4.png)

### Phase 4: IAM Policy Simulator

![Phase 4 Policy Simulator](evidence/phase4-explicitdeny/policy-simulator-phase4.png)

### Phase 4: AWS CLI Test Results

![Phase 4 CLI Tests](evidence/phase4-explicitdeny/cli-tests-phase4.png)

### Phase 4: CloudTrail Confirmation

![Phase 4 CloudTrail PutObject](evidence/phase4-explicitdeny/cloudtrail-putobject-phase4.png)
![Phase 4 CloudTrail DeleteObject](evidence/phase4-explicitdeny/cloudtrail-deleteobject-phase4.png)

Raw log: [cloudtrail-phase4-sanitized.json](evidence/phase4-explicitdeny/cloudtrail-phase4-sanitized.json)

</details>

<!-- markdownlint-enable MD033 -->

## Repository Structure

```text
AWS-IAM-Security-Lab/
├── evidence/
│   ├── phase1-broad/          # Policy, simulator, CLI, and CloudTrail evidence
│   ├── phase2-conditions/
│   ├── phase3-narrow/
│   └── phase4-explicitdeny/   # Includes sanitized raw CloudTrail JSON
├── findings/
│   └── security-assessment.md
├── policies/
│   ├── phase1-overbroad-policy.json
│   ├── phase2-conditional-policy.json
│   ├── phase3-developer-policy.json
│   └── phase4-explicitdeny-policy.json
├── .gitignore
└── README.md
```

## Security & Privacy

- This lab was performed in a personal AWS account for learning and portfolio purposes. No production systems, company data, or real incidents were involved.
- The Phase 1 and Phase 4 policies were attached only during their tests and detached afterward. The account's standing configuration is the Phase 3 least-privilege policy.
- Screenshots and log files were sanitized to remove account IDs, principal IDs, access key IDs, source IP addresses, request IDs, and event IDs.
- No long-lived access keys or production credentials were used at any point.
