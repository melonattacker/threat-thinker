# Threat Analysis Report

## Threat Summary

| ID | Threat | Severity | Score |
|----|---------|---------|-------|
| T001 | Potential Credential Theft at Ingress Point | High | 8.0 |
| T002 | Unencrypted Traffic Between Load Balancer and ECS Service Exposes Sensitive Data | High | 8.0 |
| T003 | Lack of End-to-End Encryption for PII to Database | High | 7.0 |
| T004 | Exposure of Internal Data via S3 Bucket Misconfiguration | Medium | 6.0 |
| T005 | Insufficient Authentication Between Internal Services | Medium | 6.0 |
| T006 | Denial of Service Risk at Public Ingress Points | Medium | 5.0 |
| T007 | Insufficient Access Controls on Internal AWS Resources | Medium | 5.0 |
| T008 | Lack of Audit Logging for Sensitive Operations | Medium | 5.0 |
| T009 | Potential for Message Tampering or Replay in SQS/SNS | Medium | 5.0 |
| T010 | Lack of Input Validation on User-Provided Data | Low | 3.0 |

## Threat Details

### T001: Potential Credential Theft at Ingress Point

**Severity:** High

**Score:** 8.0

**STRIDE:** Spoofing, Information Disclosure

**Affected Components:** User, CloudFront

**Why:** Credentials are transmitted from users to CloudFront; if HTTPS is misconfigured, credentials could be intercepted.

**References:** ASVS V2.1, ASVS V9.1, CWE-522

**Recommended Actions:**

Ensure HTTPS with strong TLS configuration is enforced at CloudFront and all credentials are transmitted securely.

---

### T002: Unencrypted Traffic Between Load Balancer and ECS Service Exposes Sensitive Data

**Severity:** High

**Score:** 8.0

**STRIDE:** Information Disclosure, Tampering

**Affected Components:** Application Load Balancer, ECS Service (Fargate)

**Why:** HTTP (unencrypted) is used between the load balancer and ECS, risking exposure or manipulation of PII/internal data in transit.

**References:** ASVS V9.1, CWE-319

**Recommended Actions:**

Enforce HTTPS/TLS 1.2+ for all internal traffic between the load balancer and ECS service.

---

### T003: Lack of End-to-End Encryption for PII to Database

**Severity:** High

**Score:** 7.0

**STRIDE:** Information Disclosure

**Affected Components:** ECS Service (Fargate), Aurora (RDS)

**Why:** PII is sent over TCP from ECS to Aurora RDS, which may not be encrypted if not explicitly configured.

**References:** ASVS V9.1, ASVS V10.4.1, CWE-319

**Recommended Actions:**

Enable TLS encryption for database connections and enforce encrypted client connections.

---

### T004: Exposure of Internal Data via S3 Bucket Misconfiguration

**Severity:** Medium

**Score:** 6.0

**STRIDE:** Information Disclosure

**Affected Components:** S3 Bucket (assets)

**Why:** Internal data stored in S3 could be exposed if bucket policies or ACLs are misconfigured.

**References:** ASVS V9.4, ASVS V10.5.1, CWE-200

**Recommended Actions:**

Restrict S3 bucket access using least privilege IAM policies and enable bucket encryption.

---

### T005: Insufficient Authentication Between Internal Services

**Severity:** Medium

**Score:** 6.0

**STRIDE:** Elevation of Privilege, Spoofing

**Affected Components:** Application Load Balancer, ECS Service (Fargate)

**Why:** No explicit authentication is described between the load balancer and ECS, risking unauthorized access if internal boundaries are breached.

**References:** ASVS V2.1, ASVS V2.2, CWE-287

**Recommended Actions:**

Implement mutual TLS or signed tokens for authentication between internal services.

---

### T006: Denial of Service Risk at Public Ingress Points

**Severity:** Medium

**Score:** 5.0

**STRIDE:** Denial of Service

**Affected Components:** CloudFront, Application Load Balancer

**Why:** Publicly exposed CloudFront and ALB endpoints could be targeted by volumetric or application-layer DoS attacks.

**References:** ASVS V1.7, ASVS V9.5, CWE-400

**Recommended Actions:**

Implement AWS WAF, rate limiting, and auto-scaling to mitigate DoS risks.

---

### T007: Insufficient Access Controls on Internal AWS Resources

**Severity:** Medium

**Score:** 5.0

**STRIDE:** Elevation of Privilege

**Affected Components:** S3 Bucket (assets), SQS Queue (jobs), SNS Topic (events), Aurora (RDS)

**Why:** If IAM roles/policies are overly permissive, attackers could escalate privileges or access sensitive resources.

**References:** ASVS V4.2, ASVS V4.3, CWE-269

**Recommended Actions:**

Review and enforce least privilege IAM roles and resource policies for all AWS resources.

---

### T008: Lack of Audit Logging for Sensitive Operations

**Severity:** Medium

**Score:** 5.0

**STRIDE:** Repudiation

**Affected Components:** ECS Service (Fargate), Aurora (RDS), S3 Bucket (assets)

**Why:** No evidence of audit logging for access to PII or internal data, risking undetected misuse or data breaches.

**References:** ASVS V10.1.1, ASVS V10.2.1, CWE-778

**Recommended Actions:**

Enable detailed audit logging for all sensitive data access and changes, and monitor logs for anomalies.

---

### T009: Potential for Message Tampering or Replay in SQS/SNS

**Severity:** Medium

**Score:** 5.0

**STRIDE:** Tampering, Repudiation

**Affected Components:** ECS Service (Fargate), SQS Queue (jobs), SNS Topic (events), Lambda Worker

**Why:** Internal data sent via SQS/SNS could be tampered with or replayed if message integrity and authentication are not enforced.

**References:** ASVS V10.5.2, ASVS V10.6.1, CWE-345

**Recommended Actions:**

Enable message signing, enforce authentication, and use idempotency tokens for message processing.

---

### T010: Lack of Input Validation on User-Provided Data

**Severity:** Low

**Score:** 3.0

**STRIDE:** Tampering, Elevation of Privilege

**Affected Components:** ECS Service (Fargate)

**Why:** No explicit input validation is described, risking injection or privilege escalation via crafted user input.

**References:** ASVS V5.3, ASVS V5.4, CWE-20

**Recommended Actions:**

Implement strict input validation and sanitization for all user-supplied data.

---

