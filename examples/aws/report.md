# Threat Analysis Report

## Threat Summary

| ID | Threat | Severity | Score |
|----|---------|---------|-------|
| T001 | Potential Exposure of PII Over Unencrypted Database Connection | High | 8.0 |
| T002 | Unencrypted Traffic Between Load Balancer and ECS Service | High | 8.0 |
| T003 | Lack of Authentication on Application Load Balancer | High | 7.0 |
| T004 | Insufficient Access Controls on S3 Bucket (Assets) | Medium | 6.0 |
| T005 | Potential Lack of Input Validation on ECS Service | Medium | 6.0 |
| T006 | Denial of Service via Unrestricted Public Entry Points | Medium | 5.0 |
| T007 | Insufficient Logging and Auditing for Sensitive Operations | Medium | 5.0 |
| T008 | Lack of Encryption at Rest for Sensitive Data Stores | Medium | 5.0 |
| T009 | Over-Privileged Lambda Worker Access | Medium | 5.0 |
| T010 | Potential Information Disclosure via SNS/SQS Misconfiguration | Medium | 5.0 |

## Threat Details

### T001: Potential Exposure of PII Over Unencrypted Database Connection

**Severity:** High

**Score:** 8.0

**STRIDE:** Information Disclosure, Tampering

**Affected Components:** ECS Service (Fargate), Aurora (RDS)

**Why:** PII is transmitted over a generic TCP connection, which may not be encrypted, risking data exposure.

**References:** ASVS V9.1.1, ASVS V10.4.1, CWE-319

**Recommended Actions:**

Require TLS for all database connections and enforce encryption in transit for Aurora RDS.

---

### T002: Unencrypted Traffic Between Load Balancer and ECS Service

**Severity:** High

**Score:** 8.0

**STRIDE:** Information Disclosure, Tampering

**Affected Components:** Application Load Balancer, ECS Service (Fargate)

**Why:** Traffic between the load balancer and ECS service uses HTTP, exposing sensitive data to interception or modification.

**References:** ASVS V9.1.1, CWE-319

**Recommended Actions:**

Enforce HTTPS/TLS 1.2+ for all internal communications between the load balancer and ECS service.

---

### T003: Lack of Authentication on Application Load Balancer

**Severity:** High

**Score:** 7.0

**STRIDE:** Elevation of Privilege, Spoofing

**Affected Components:** Application Load Balancer

**Why:** The load balancer does not enforce authentication, allowing unauthenticated access to backend services.

**References:** ASVS V2.1.1, ASVS V2.1.2, CWE-287

**Recommended Actions:**

Implement authentication (e.g., JWT, OAuth2) at the load balancer or ECS service entry point.

---

### T004: Insufficient Access Controls on S3 Bucket (Assets)

**Severity:** Medium

**Score:** 6.0

**STRIDE:** Information Disclosure, Elevation of Privilege

**Affected Components:** S3 Bucket (assets)

**Why:** S3 bucket contains internal data and may be accessed by unauthorized entities if IAM policies are misconfigured.

**References:** ASVS V4.1.1, ASVS V1.4.3, CWE-284

**Recommended Actions:**

Restrict S3 bucket access using least privilege IAM roles and enable bucket policies to deny public access.

---

### T005: Potential Lack of Input Validation on ECS Service

**Severity:** Medium

**Score:** 6.0

**STRIDE:** Tampering, Elevation of Privilege

**Affected Components:** ECS Service (Fargate)

**Why:** User input flows from the internet to ECS service, risking injection attacks if not validated.

**References:** ASVS V5.3.2, ASVS V5.1.1, CWE-20

**Recommended Actions:**

Implement strict input validation and sanitization on all user-supplied data at the ECS service.

---

### T006: Denial of Service via Unrestricted Public Entry Points

**Severity:** Medium

**Score:** 5.0

**STRIDE:** Denial of Service

**Affected Components:** CloudFront, Application Load Balancer, ECS Service (Fargate)

**Why:** Public-facing endpoints may be targeted for DoS attacks due to lack of rate limiting or WAF.

**References:** ASVS V7.1.1, ASVS V7.5.1, CWE-400

**Recommended Actions:**

Enable AWS WAF and implement rate limiting on CloudFront and the load balancer.

---

### T007: Insufficient Logging and Auditing for Sensitive Operations

**Severity:** Medium

**Score:** 5.0

**STRIDE:** Repudiation

**Affected Components:** ECS Service (Fargate), Aurora (RDS), S3 Bucket (assets)

**Why:** Lack of comprehensive logging may hinder detection and investigation of security incidents involving PII or internal data.

**References:** ASVS V10.1.1, ASVS V10.2.1, CWE-778

**Recommended Actions:**

Enable detailed logging and auditing for ECS, RDS, and S3, and ensure logs are protected and monitored.

---

### T008: Lack of Encryption at Rest for Sensitive Data Stores

**Severity:** Medium

**Score:** 5.0

**STRIDE:** Information Disclosure

**Affected Components:** Aurora (RDS), S3 Bucket (assets)

**Why:** Sensitive data may be stored unencrypted at rest, risking exposure if storage is compromised.

**References:** ASVS V9.4.1, ASVS V9.4.2, CWE-311

**Recommended Actions:**

Enable encryption at rest for Aurora RDS and S3 buckets using AWS KMS.

---

### T009: Over-Privileged Lambda Worker Access

**Severity:** Medium

**Score:** 5.0

**STRIDE:** Elevation of Privilege

**Affected Components:** Lambda Worker, SQS Queue (jobs), SNS Topic (events)

**Why:** Lambda worker may have excessive permissions to queues, increasing risk if compromised.

**References:** ASVS V4.2.1, ASVS V1.4.3, CWE-250

**Recommended Actions:**

Apply least privilege IAM roles to Lambda, restricting access only to required queues and topics.

---

### T010: Potential Information Disclosure via SNS/SQS Misconfiguration

**Severity:** Medium

**Score:** 5.0

**STRIDE:** Information Disclosure

**Affected Components:** SQS Queue (jobs), SNS Topic (events)

**Why:** Internal data in queues/topics could be exposed if access policies are too permissive.

**References:** ASVS V4.1.1, ASVS V1.4.3, CWE-284

**Recommended Actions:**

Review and tighten SNS/SQS access policies to allow only trusted principals.

---

